#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use rusqlite::{params, Connection};
use serde::{Serialize, Deserialize};
use std::sync::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::{Argon2, password_hash::{rand_core::OsRng, SaltString}};
use rand::RngCore;
use tauri::State;
use uuid::Uuid;
use chrono::Utc;
use std::fs;
use flate2::write::GzEncoder;
use flate2::Compression;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jieba_rs::Jieba;

fn dir_is_writable(dir: &Path) -> bool {
    let probe = dir.join(".anchor_write_probe");
    match fs::File::create(&probe) {
        Ok(_) => { let _ = fs::remove_file(&probe); true }
        Err(_) => false,
    }
}

/// 解析数据目录，返回 (目录, 需要提示用户的说明)。
///
/// 以 exe 所在目录为准：工作目录会随启动方式变化（快捷方式、文件关联、以管理员身份
/// 运行），跟随它会在别处新建空 data 目录，表现为「笔记全部消失」。
///
/// 还必须确认可写——只读位置（例如只授予 Users 只读权限的磁盘）上 SQLite 无法以
/// 读写方式打开，早先这会直接 panic，release 版又没有控制台，表现为双击毫无反应。
fn resolve_data_root() -> (PathBuf, Option<String>) {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
        candidates.push(dir.join("data"));
    }
    // 兼容旧版本：数据目录曾经跟随工作目录，已经存在就继续用它
    if let Ok(cwd) = std::env::current_dir() {
        let legacy = cwd.join("data");
        if !candidates.contains(&legacy) { candidates.push(legacy); }
    }

    for c in &candidates {
        if c.is_dir() && dir_is_writable(c) { return (c.clone(), None); }
    }
    // 已存在但不可写的目录：多半装着用户的笔记，回退后必须告诉用户，否则会以为数据没了
    let blocked = candidates.iter().find(|c| c.is_dir()).cloned();
    for c in &candidates {
        if fs::create_dir_all(c).is_ok() && dir_is_writable(c) { return (c.clone(), None); }
    }

    let fallback = std::env::var_os("LOCALAPPDATA")
        .map(|v| PathBuf::from(v).join("锚点").join("data"))
        .unwrap_or_else(|| std::env::temp_dir().join("锚点").join("data"));
    let note = Some(match &blocked {
        Some(b) => format!(
            "数据目录不可写：\n{}\n\n已改用可写位置：\n{}\n\n原目录里的笔记不会显示。若要继续使用它，请以管理员身份运行本程序，或为该目录授予写入权限。",
            b.display(), fallback.display()
        ),
        None => format!("无法在程序目录创建数据目录，已改用：\n{}", fallback.display()),
    });
    (fallback, note)
}

fn data_root_choice() -> &'static (PathBuf, Option<String>) {
    static ROOT: std::sync::OnceLock<(PathBuf, Option<String>)> = std::sync::OnceLock::new();
    ROOT.get_or_init(resolve_data_root)
}

fn data_root() -> PathBuf {
    data_root_choice().0.clone()
}

fn note_dir(note_id: &str) -> PathBuf {
    data_root().join(note_id)
}

/// 笔记 ID 必须是单个普通目录名。前端传来的值可能被笔记正文里的注入内容污染，
/// 不校验就等于把 delete_note / export 之类的命令变成任意目录操作。
fn validate_note_id(note_id: &str) -> Result<(), String> {
    if note_id.is_empty()
        || note_id.len() > 128
        || note_id.contains('/')
        || note_id.contains('\\')
        || note_id.contains(':')
        || note_id.contains("..")
    {
        return Err("非法的笔记 ID".into());
    }
    Ok(())
}

fn safe_note_dir(note_id: &str) -> Result<PathBuf, String> {
    validate_note_id(note_id)?;
    Ok(data_root().join(note_id))
}

/// 把前端传来的相对路径解析到笔记目录内，拒绝一切越界写法。
/// 只接受普通路径段：`..`、绝对路径、盘符前缀一律拒绝；最终路径再核对一次仍在笔记目录下，
/// 以防符号链接绕过。
fn safe_note_path(note_id: &str, rel_path: &str) -> Result<PathBuf, String> {
    let base = safe_note_dir(note_id)?;
    let mut full = base.clone();
    for comp in Path::new(rel_path).components() {
        use std::path::Component;
        match comp {
            Component::Normal(p) => full.push(p),
            Component::CurDir => {}
            _ => return Err("非法的文件路径".into()),
        }
    }
    if full == base { return Err("非法的文件路径".into()); }
    if let (Ok(base_c), Ok(full_c)) = (base.canonicalize(), full.canonicalize()) {
        if !full_c.starts_with(&base_c) { return Err("非法的文件路径".into()); }
    }
    Ok(full)
}

/// 解析 Range 头，返回闭区间 [start, end]。越界或无法解析时返回 None（按整文件响应）。
fn parse_range(header: Option<&str>, total_len: usize) -> Option<(usize, usize)> {
    let spec = header?.strip_prefix("bytes=")?;
    let mut parts = spec.split('-');
    let start: usize = parts.next()?.trim().parse().ok()?;
    let end_str = parts.next().unwrap_or("").trim();
    let last = total_len.checked_sub(1)?;
    let end = if end_str.is_empty() { last } else { end_str.parse::<usize>().unwrap_or(last).min(last) };
    if start > end { return None; }
    Some((start, end))
}

fn read_file_range(path: &Path, start: usize, end: usize) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = fs::File::open(path)?;
    f.seek(SeekFrom::Start(start as u64))?;
    let mut buf = vec![0u8; end - start + 1];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// 定位 ffmpeg。绝不接受前端传入的可执行文件路径——那等于把任意程序启动权交给页面。
fn locate_ffmpeg() -> Result<String, String> {
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
        let local = dir.join("ffmpeg.exe");
        if local.exists() { return Ok(local.to_string_lossy().to_string()); }
    }
    let cwd_ffmpeg = std::env::current_dir().unwrap_or_default().join("ffmpeg.exe");
    if cwd_ffmpeg.exists() { return Ok(cwd_ffmpeg.to_string_lossy().to_string()); }
    if let Ok(output) = std::process::Command::new("where.exe").arg("ffmpeg").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().lines().next().unwrap_or("").to_string();
            if !path.is_empty() { return Ok(path); }
        }
    }
    Err("未找到 ffmpeg。请将 ffmpeg.exe 放到程序同目录，或添加到系统 PATH 中。".into())
}

#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 启动期失败必须可见：release 版是 windows 子系统，没有控制台，
/// 直接 panic 的话用户只会看到「双击了但什么都没发生」。
fn show_startup_error(message: &str) {
    eprintln!("[启动失败] {}", message);
    #[cfg(target_os = "windows")]
    unsafe {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
        use windows::core::PCWSTR;
        let text = to_wide(message);
        let title = to_wide("锚点 无法启动");
        MessageBoxW(HWND(0), PCWSTR(text.as_ptr()), PCWSTR(title.as_ptr()), MB_OK | MB_ICONERROR);
    }
}

/// 抢占单实例锁。返回 false 表示已有实例在运行。
///
/// WebView2 的用户数据目录是独占锁，第二个实例创建 WebView 必然失败；与其静默崩溃，
/// 不如直接把已有窗口唤到前台。互斥量句柄故意不关闭，随进程退出由系统释放。
#[cfg(target_os = "windows")]
fn acquire_single_instance() -> bool {
    unsafe {
        use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
        use windows::Win32::System::Threading::CreateMutexW;
        use windows::core::PCWSTR;
        let name = to_wide("Global\\anchor_notes_single_instance");
        let handle = CreateMutexW(std::ptr::null(), true, PCWSTR(name.as_ptr()));
        if handle.is_err() { return true; } // 拿不到锁就别挡着启动
        GetLastError() != ERROR_ALREADY_EXISTS
    }
}

/// 找到别的锚点实例的主窗口（不含自己）。
///
/// 只认标题是「锚点」且**所属进程确实是 anchor_ui.exe** 的顶层窗口：项目文件夹本身
/// 就叫「锚点」，资源管理器窗口的标题也是「锚点」，只看标题会误判，甚至把资源管理器唤到前台。
/// 同时它也能发现没有单实例互斥量的旧版实例。
#[cfg(target_os = "windows")]
fn find_other_anchor_window() -> Option<windows::Win32::Foundation::HWND> {
    use windows::Win32::Foundation::{CloseHandle, BOOL, HWND, LPARAM};
    use windows::core::PWSTR;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowTextW, GetWindowThreadProcessId};

    struct Search { found: Option<HWND>, me: u32 }

    unsafe extern "system" fn visit(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let search = &mut *(lparam.0 as *mut Search);
        let mut buf = [0u16; 64];
        let n = GetWindowTextW(hwnd, &mut buf);
        if n <= 0 || String::from_utf16_lossy(&buf[..n as usize]) != "锚点" { return BOOL(1); }

        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid == 0 || pid == search.me { return BOOL(1); }

        if let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            let mut path = [0u16; 520];
            let mut len = path.len() as u32;
            let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(path.as_mut_ptr()), &mut len).as_bool();
            CloseHandle(h);
            if ok {
                let full = String::from_utf16_lossy(&path[..len as usize]).to_lowercase();
                if full.ends_with("anchor_ui.exe") {
                    search.found = Some(hwnd);
                    return BOOL(0);   // 找到了，停止枚举
                }
            }
        }
        BOOL(1)
    }

    let mut search = Search { found: None, me: std::process::id() };
    unsafe { EnumWindows(Some(visit), LPARAM(&mut search as *mut Search as isize)); }
    search.found
}

/// 把已在运行的那个窗口还原并前置。先前出过这样的事故：窗口被最小化到屏幕外，
/// 用户以为程序没开。只在窗口确实被最小化时才还原，否则最大化的窗口会被缩回原尺寸。
#[cfg(target_os = "windows")]
fn focus_existing_window() {
    use windows::Win32::UI::WindowsAndMessaging::{IsIconic, SetForegroundWindow, ShowWindow, SW_RESTORE};
    if let Some(hwnd) = find_other_anchor_window() {
        unsafe {
            if IsIconic(hwnd).as_bool() { ShowWindow(hwnd, SW_RESTORE); }
            SetForegroundWindow(hwnd);
        }
    }
}

#[cfg(target_os = "windows")]
fn process_exists(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => { CloseHandle(h); true }
            Err(_) => false,
        }
    }
}

/// 给「再开一个」的实例分配独立的 WebView2 数据目录。
/// 默认目录是独占锁，两个实例共用会在创建 WebView 时失败（0x80010108）。
/// 返回目录路径，退出时用来清理。
#[cfg(target_os = "windows")]
fn setup_secondary_webview_dir() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(|v| PathBuf::from(v).join("com.anchor.dev").join("secondary"))
        .unwrap_or_else(|| std::env::temp_dir().join("anchor_secondary"));
    // 清掉已经不存在的实例遗留的目录：被强制结束的实例来不及自己清理，
    // 每个残留都是一份 WebView2 缓存，不处理会越积越多。只删进程已不在的，运行中的不碰。
    if let Ok(entries) = fs::read_dir(&base) {
        for e in entries.filter_map(Result::ok) {
            let pid = match e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) { Some(p) => p, None => continue };
            if pid != std::process::id() && !process_exists(pid) {
                let _ = fs::remove_dir_all(e.path());
            }
        }
    }
    let dir = base.join(std::process::id().to_string());
    if fs::create_dir_all(&dir).is_err() { return None; }
    std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", &dir);
    Some(dir)
}

static OTHER_INSTANCE_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[derive(Serialize)]
struct StartupContext {
    other_instance: bool,
}

/// 前端据此决定要不要弹「已经有一个在运行」的选择。
#[tauri::command(async)]
fn startup_context() -> StartupContext {
    StartupContext { other_instance: OTHER_INSTANCE_RUNNING.load(std::sync::atomic::Ordering::SeqCst) }
}

/// 把已经开启的那个实例唤到前台。
#[tauri::command(async)]
fn focus_other_instance() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    focus_existing_window();
    Ok(())
}

/// 退出当前（新开的）实例。
#[tauri::command(async)]
fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

/// 由密码和盐派生密钥。
///
/// 两处静默失败必须显式化：盐解析失败时原先会**随机生成一个新盐**（每次得到不同密钥，
/// 笔记从此再也打不开），派生出错时原先把全零数组当密钥用。两者都宁可报错。
fn derive_key(password: &str, salt: &str) -> Result<[u8; 32], String> {
    let parsed_salt = SaltString::from_b64(salt).map_err(|e| format!("加密盐已损坏，无法派生密钥：{}", e))?;
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), parsed_salt.as_str().as_bytes(), &mut key)
        .map_err(|e| format!("密钥派生失败：{}", e))?;
    Ok(key)
}

fn encrypt_text(key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).map_err(|e| e.to_string())?;
    
    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);
    Ok(STANDARD.encode(combined))
}

fn decrypt_text(key: &[u8; 32], encrypted_b64: &str) -> Result<String, String> {
    let combined = STANDARD.decode(encrypted_b64).map_err(|e| e.to_string())?;
    if combined.len() < 12 { return Err("Invalid ciphertext".into()); }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext_bytes = cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())?;
    String::from_utf8(plaintext_bytes).map_err(|e| e.to_string())
}

fn encrypt_binary(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| e.to_string())?;
    
    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);
    Ok(combined)
}

fn decrypt_binary(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted.len() < 12 { return Err("Invalid ciphertext".into()); }
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())
}

fn get_note_key(state: &State<AppState>, note_id: &str) -> Result<Option<[u8; 32]>, String> {
    let idx = lock_or_recover(&state.index_db);
    let is_enc: i32 = idx.query_row("SELECT COALESCE(is_encrypted, 0) FROM notes WHERE id = ?1", params![note_id], |row| row.get(0)).unwrap_or(0);
    if is_enc == 0 { return Ok(None); }
    let keys = lock_or_recover(&state.unlocked_keys);
    if let Some(key) = keys.get(note_id) {
        Ok(Some(*key))
    } else {
        Err("该笔记已被加密且尚未解锁，无法访问内容".into())
    }
}

/// 互斥量中毒恢复：任一命令 panic 过一次后，`.lock().unwrap()` 会让之后
/// 所有命令跟着 panic，整个程序变砖。数据本身没坏，继续用即可。
fn lock_or_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct AppState {
    index_db: Mutex<Connection>,
    jieba: Mutex<Jieba>,
    unlocked_keys: Mutex<HashMap<String, [u8; 32]>>,
}

#[derive(Serialize)]
struct Note {
    id: String,
    created_at: i64,
    updated_at: i64,
    title: String,
    preview: String,
    folder_id: Option<String>,
    background: String,
    is_encrypted: bool,
    is_unlocked: bool,
}

#[derive(serde::Serialize)]
struct Folder {
    id: String,
    name: String,
    created_at: i64,
}

#[derive(Serialize)]
struct NoteEvent {
    id: String,
    note_id: String,
    timestamp: i64,
    operation_type: String,
    delta_json: String,
}

/// 每次存取都新建连接，至少把并发行为调对：WAL 允许读写并行，
/// busy_timeout 避免瞬时锁冲突直接报错。
fn tune_connection(db: &Connection) {
    let _ = db.pragma_update(None, "journal_mode", "WAL");
    let _ = db.pragma_update(None, "busy_timeout", 5000);
    let _ = db.pragma_update(None, "synchronous", "NORMAL");
}

fn init_index_db() -> Result<Connection, String> {
    let root = data_root();
    fs::create_dir_all(&root).map_err(|e| format!("无法创建数据目录：\n{}\n\n{}", root.display(), e))?;
    let db_path = root.join("notes_index.db");
    let db = Connection::open(&db_path)
        .map_err(|e| format!("无法打开索引数据库：\n{}\n\n{}", db_path.display(), e))?;
    tune_connection(&db);
    db.execute(
        "CREATE TABLE IF NOT EXISTS notes (
            id TEXT PRIMARY KEY, created_at INTEGER, updated_at INTEGER, title TEXT, preview TEXT
        )", [],
    ).map_err(|e| format!("索引数据库不可写：\n{}\n\n{}", db_path.display(), e))?;
    db.execute("ALTER TABLE notes ADD COLUMN is_archived INTEGER DEFAULT 0", []).ok();
    db.execute("ALTER TABLE notes ADD COLUMN folder_id TEXT", []).ok();
    db.execute("ALTER TABLE notes ADD COLUMN background TEXT DEFAULT 'default'", []).ok();
    db.execute("ALTER TABLE notes ADD COLUMN is_encrypted INTEGER DEFAULT 0", []).ok();
    db.execute("ALTER TABLE notes ADD COLUMN encryption_salt TEXT", []).ok();
    db.execute("ALTER TABLE notes ADD COLUMN verify_token TEXT", []).ok();
    db.execute(
        "CREATE TABLE IF NOT EXISTS folders (
            id TEXT PRIMARY KEY, name TEXT, created_at INTEGER
        )", [],
    ).map_err(|e| format!("索引数据库初始化失败：{}", e))?;
    Ok(db)
}

/// 已建过表、设过 PRAGMA 的库。建表和 journal_mode=WAL 都是一次性的
/// （WAL 模式写在文件里，之后打开自动继承），每次保存重跑一遍要多花约 6.6ms，
/// 而这段时间正压在保存路径上。
fn initialized_dbs() -> &'static Mutex<std::collections::HashSet<PathBuf>> {
    static SET: std::sync::OnceLock<Mutex<std::collections::HashSet<PathBuf>>> = std::sync::OnceLock::new();
    SET.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

fn open_note_db(path: PathBuf, create_sql: &str, what: &str) -> Connection {
    let db = Connection::open(&path).unwrap_or_else(|e| panic!("无法打开 {}：{}", what, e));
    if lock_or_recover(initialized_dbs()).insert(path) {
        tune_connection(&db);
        db.execute(create_sql, []).ok();
    }
    db
}

fn init_note_content_db(note_id: &str) -> Connection {
    open_note_db(
        note_dir(note_id).join("content.db"),
        "CREATE TABLE IF NOT EXISTS content (
            id TEXT PRIMARY KEY DEFAULT 'current', delta_json TEXT, updated_at INTEGER
        )",
        "content.db",
    )
}

fn init_note_timeline_db(note_id: &str) -> Connection {
    open_note_db(
        note_dir(note_id).join("timeline.db"),
        "CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, timestamp INTEGER, operation_type TEXT, delta_json TEXT
        )",
        "timeline.db",
    )
}

fn ensure_note_dirs(note_id: &str) {
    let dir = note_dir(note_id);
    for sub in &["images", "videos", "files", "audio"] {
        fs::create_dir_all(dir.join(sub)).ok();
    }
}

fn migrate_old_db_if_needed(index_db: &Connection) {
    let old_db_path = std::env::current_dir().unwrap_or_default().join("anchor_data.db");
    if !old_db_path.exists() { return; }
    let old_db = match Connection::open(&old_db_path) { Ok(db) => db, Err(_) => return };
    let mut stmt = match old_db.prepare("SELECT id, created_at, updated_at, title, preview FROM notes") {
        Ok(s) => s, Err(_) => return,
    };
    let old_notes: Vec<(String, i64, i64, String, String)> = match stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => return,
    };

    for (id, created_at, updated_at, title, preview) in &old_notes {
        let exists: bool = index_db
            .query_row("SELECT COUNT(*) FROM notes WHERE id = ?1", params![id], |row| row.get::<_, i64>(0))
            .map(|c| c > 0).unwrap_or(false);
        if exists { continue; }
        ensure_note_dirs(id);
        index_db.execute(
            "INSERT INTO notes (id, created_at, updated_at, title, preview) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, created_at, updated_at, title, preview],
        ).ok();
        let timeline_db = init_note_timeline_db(id);
        // 旧库可能根本没有 note_events 表，这里不能 unwrap：启动期 panic 是看不见的
        let mut ev_stmt = match old_db.prepare(
            "SELECT id, timestamp, operation_type, delta_json FROM note_events WHERE note_id = ?1 ORDER BY timestamp ASC"
        ) { Ok(s) => s, Err(_) => continue };
        let events: Vec<(String, i64, String, String)> = match ev_stmt
            .query_map(params![id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => continue,
        };
        for (eid, ts, op, delta) in &events {
            timeline_db.execute(
                "INSERT OR IGNORE INTO events (id, timestamp, operation_type, delta_json) VALUES (?1, ?2, ?3, ?4)",
                params![eid, ts, op, delta],
            ).ok();
        }
        let content_db = init_note_content_db(id);
        if let Some(last) = events.last() {
            content_db.execute(
                "INSERT OR REPLACE INTO content (id, delta_json, updated_at) VALUES ('current', ?1, ?2)",
                params![last.3, updated_at],
            ).ok();
        }
    }
    fs::rename(&old_db_path, old_db_path.with_extension("db.migrated")).ok();
}

// ── Tauri 命令 ──

#[tauri::command(async)]
fn get_data_root() -> String {
    data_root().to_string_lossy().to_string()
}

#[tauri::command(async)]
fn create_note(state: State<AppState>) -> Result<String, String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp_millis();
    ensure_note_dirs(&id);
    init_note_content_db(&id);
    init_note_timeline_db(&id);
    let db = lock_or_recover(&state.index_db);
    db.execute(
        "INSERT INTO notes (id, created_at, updated_at, title, preview) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, now, now, "新笔记", "开始编写内容..."],
    ).map_err(|e| e.to_string())?;
    Ok(id)
}

#[tauri::command(async)]
fn save_event(state: State<AppState>, note_id: String, operation_type: String, mut delta_json: String, title: String, preview: String) -> Result<(), String> {
    validate_note_id(&note_id)?;
    let key_opt = get_note_key(&state, &note_id)?;
    if let Some(key) = key_opt {
        delta_json = encrypt_text(&key, &delta_json)?;
    }
    let event_id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp_millis();
    let timeline_db = init_note_timeline_db(&note_id);
    timeline_db.execute(
        "INSERT INTO events (id, timestamp, operation_type, delta_json) VALUES (?1, ?2, ?3, ?4)",
        params![event_id, now, operation_type, delta_json],
    ).map_err(|e| e.to_string())?;
    // 加密笔记的标题/摘要不能明文落库
    let stored_title = encrypt_meta(key_opt.as_ref(), &title);
    let stored_preview = encrypt_meta(key_opt.as_ref(), &preview);
    let idx = lock_or_recover(&state.index_db);
    idx.execute(
        "UPDATE notes SET updated_at = ?1, title = ?2, preview = ?3 WHERE id = ?4",
        params![now, stored_title, stored_preview, note_id],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command(async)]
fn save_content(state: State<AppState>, note_id: String, mut delta_json: String) -> Result<(), String> {
    validate_note_id(&note_id)?;
    let key_opt = get_note_key(&state, &note_id)?;
    if let Some(key) = key_opt {
        delta_json = encrypt_text(&key, &delta_json)?;
    }
    let now = Utc::now().timestamp_millis();
    let content_db = init_note_content_db(&note_id);
    content_db.execute(
        "INSERT OR REPLACE INTO content (id, delta_json, updated_at) VALUES ('current', ?1, ?2)",
        params![delta_json, now],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command(async)]
fn get_content(state: State<AppState>, note_id: String) -> Result<String, String> {
    validate_note_id(&note_id)?;
    let key_opt = get_note_key(&state, &note_id)?;
    let content_db = init_note_content_db(&note_id);
    let mut json = match content_db.query_row("SELECT delta_json FROM content WHERE id = 'current'", [], |row| row.get::<_, String>(0)) {
        Ok(json) => json,
        Err(_) => return Ok(String::new()),
    };
    if let Some(key) = key_opt {
        json = decrypt_text(&key, &json)?;
    }
    Ok(json)
}

#[tauri::command(async)]
fn get_notes(state: State<AppState>) -> Result<Vec<Note>, String> {
    let db = lock_or_recover(&state.index_db);
    let keys = lock_or_recover(&state.unlocked_keys);
    let mut stmt = db.prepare("SELECT id, created_at, updated_at, title, preview, folder_id, COALESCE(background, 'default'), COALESCE(is_encrypted, 0) FROM notes WHERE is_archived = 0 ORDER BY updated_at DESC").unwrap();
    let notes = stmt.query_map([], |row| {
        let id: String = row.get(0)?;
        let is_enc: i32 = row.get(7)?;
        let is_unlocked = if is_enc == 1 { keys.contains_key(&id) } else { true };
        let key = keys.get(&id);
        let title = decrypt_meta(key, &row.get::<_, String>(3)?, "🔒 已加密笔记");
        let preview = decrypt_meta(key, &row.get::<_, String>(4)?, "解锁后可见");
        Ok(Note { id, created_at: row.get(1)?, updated_at: row.get(2)?, title, preview, folder_id: row.get(5).ok(), background: row.get(6)?, is_encrypted: is_enc == 1, is_unlocked })
    }).map_err(|e| e.to_string())?.filter_map(Result::ok).collect();
    Ok(notes)
}

#[tauri::command(async)]
fn get_archived_notes(state: State<AppState>) -> Result<Vec<Note>, String> {
    let db = lock_or_recover(&state.index_db);
    let keys = lock_or_recover(&state.unlocked_keys);
    let mut stmt = db.prepare("SELECT id, created_at, updated_at, title, preview, folder_id, COALESCE(background, 'default'), COALESCE(is_encrypted, 0) FROM notes WHERE is_archived = 1 ORDER BY updated_at DESC").unwrap();
    let notes = stmt.query_map([], |row| {
        let id: String = row.get(0)?;
        let is_enc: i32 = row.get(7)?;
        let is_unlocked = if is_enc == 1 { keys.contains_key(&id) } else { true };
        let key = keys.get(&id);
        let title = decrypt_meta(key, &row.get::<_, String>(3)?, "🔒 已加密笔记");
        let preview = decrypt_meta(key, &row.get::<_, String>(4)?, "解锁后可见");
        Ok(Note { id, created_at: row.get(1)?, updated_at: row.get(2)?, title, preview, folder_id: row.get(5).ok(), background: row.get(6)?, is_encrypted: is_enc == 1, is_unlocked })
    }).map_err(|e| e.to_string())?.filter_map(Result::ok).collect();
    Ok(notes)
}

#[tauri::command(async)]
fn get_total_notes_count(state: State<AppState>) -> Result<i64, String> {
    let db = lock_or_recover(&state.index_db);
    let count: i64 = db.query_row("SELECT COUNT(*) FROM notes", [], |row| row.get(0)).unwrap_or(0);
    Ok(count)
}

#[tauri::command(async)]
fn archive_note(state: State<AppState>, note_id: String) -> Result<(), String> {
    validate_note_id(&note_id)?;
    let db = lock_or_recover(&state.index_db);
    db.execute("UPDATE notes SET is_archived = 1 WHERE id = ?1", params![note_id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command(async)]
fn unarchive_note(state: State<AppState>, note_id: String) -> Result<(), String> {
    validate_note_id(&note_id)?;
    let db = lock_or_recover(&state.index_db);
    db.execute("UPDATE notes SET is_archived = 0 WHERE id = ?1", params![note_id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command(async)]
fn set_note_background(state: State<AppState>, note_id: String, background: String) -> Result<(), String> {
    validate_note_id(&note_id)?;
    let db = lock_or_recover(&state.index_db);
    db.execute("UPDATE notes SET background = ?1 WHERE id = ?2", params![background, note_id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command(async)]
fn delete_note(state: State<AppState>, note_id: String) -> Result<(), String> {
    let db = lock_or_recover(&state.index_db);
    db.execute("DELETE FROM notes WHERE id = ?1", params![&note_id]).map_err(|e| e.to_string())?;
    let dir = safe_note_dir(&note_id)?;
    // 目录没了就必须把「已建表」的记录一并抹掉，否则同 ID 的笔记重新导入时会跳过建表
    {
        let mut inited = lock_or_recover(initialized_dbs());
        inited.remove(&dir.join("content.db"));
        inited.remove(&dir.join("timeline.db"));
    }
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|e| e.to_string())?;
    }
    lock_or_recover(&state.unlocked_keys).remove(&note_id);
    Ok(())
}

#[tauri::command(async)]
fn get_events(state: State<AppState>, note_id: String) -> Result<Vec<NoteEvent>, String> {
    validate_note_id(&note_id)?;
    let key_opt = get_note_key(&state, &note_id)?;
    let timeline_db = init_note_timeline_db(&note_id);
    let mut stmt = timeline_db.prepare("SELECT id, timestamp, operation_type, delta_json FROM events ORDER BY timestamp ASC")
        .map_err(|e| e.to_string())?;
    let nid = note_id.clone();
    let events = stmt.query_map([], |row| {
        let mut delta: String = row.get(3)?;
        if let Some(key) = key_opt {
            if let Ok(dec) = decrypt_text(&key, &delta) {
                delta = dec;
            } else {
                delta = "{}".to_string();
            }
        }
        Ok(NoteEvent { id: row.get(0)?, note_id: nid.clone(), timestamp: row.get(1)?, operation_type: row.get(2)?, delta_json: delta })
    }).map_err(|e| e.to_string())?.filter_map(Result::ok).collect();
    Ok(events)
}

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use serde_json::json;

/// 内容寻址的文件名。DefaultHasher 只有 64 位且非加密安全，单独用它做去重键，
/// 碰撞就意味着取到别的文件。这里加一轮带盐的第二次散列，把键扩到 128 位。
fn compute_file_hash(bytes: &[u8]) -> String {
    let mut h1 = DefaultHasher::new();
    bytes.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    0xa5a5_5a5a_u64.hash(&mut h2);
    bytes.hash(&mut h2);
    bytes.len().hash(&mut h2);
    format!("{:016x}{:016x}_{}", h1.finish(), h2.finish(), bytes.len())
}

/// 从本地文件路径复制媒体到笔记数据目录，返回相对路径
#[tauri::command(async)]
fn copy_media_to_note(state: State<AppState>, note_id: String, source_path: String, media_type: String) -> Result<serde_json::Value, String> {
    let src = Path::new(&source_path);
    let mut bytes = std::fs::read(src).map_err(|e| e.to_string())?;
    
    // Hash BEFORE encryption so that the filename is consistent with content
    let ext = src.extension().and_then(|e| e.to_str()).unwrap_or("bin");
    let hash_name = format!("{}.{}", compute_file_hash(&bytes), ext);
    
    if let Ok(Some(key)) = get_note_key(&state, &note_id) {
        bytes = encrypt_binary(&key, &bytes)?;
    }
    
    let sub = match media_type.as_str() { "image" => "images", "video" => "videos", "audio" => "audio", _ => "files" };
    let dir = safe_note_dir(&note_id)?.join(sub);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    
    let dest_path = dir.join(&hash_name);
    if !dest_path.exists() {
        std::fs::write(&dest_path, &bytes).map_err(|e| e.to_string())?;
    }
    
    Ok(json!({
        "path": format!("{}/{}", sub, hash_name),
        "size": bytes.len()
    }))
}

/// 查找系统中可用的 ffmpeg 路径
#[tauri::command(async)]
fn find_ffmpeg() -> Result<String, String> {
    locate_ffmpeg()
}

/// 检查视频文件是否需要转码（非 mp4/webm 格式需要转码）
#[tauri::command(async)]
fn check_video_needs_transcode(source_path: String) -> bool {
    let ext = Path::new(&source_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    !matches!(ext.as_str(), "mp4" | "webm")
}

/// 使用 ffmpeg 将视频转码为 MP4 (H.264 + AAC)，返回临时文件路径
#[tauri::command(async)]
fn transcode_video(source_path: String) -> Result<String, String> {
    let ffmpeg_path = locate_ffmpeg()?;
    let src = Path::new(&source_path);
    let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or("video");
    let tmp_dir = std::env::temp_dir().join("anchor_transcode");
    std::fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
    let out_path = tmp_dir.join(format!("{}_{}.mp4", stem, chrono::Utc::now().timestamp_millis()));
    
    let result = std::process::Command::new(&ffmpeg_path)
        .args([
            "-i", &source_path,
            "-c:v", "libx264",
            "-preset", "fast",
            "-crf", "23",
            "-c:a", "aac",
            "-b:a", "128k",
            "-movflags", "+faststart",
            "-y",
            &out_path.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("启动 ffmpeg 失败: {}", e))?;
    
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(format!("ffmpeg 转码失败: {}", stderr.chars().take(500).collect::<String>()));
    }
    
    Ok(out_path.to_string_lossy().to_string())
}

/// 提取音频文件的封面图片，返回 base64 data URL，如果没有封面则返回 null
#[tauri::command(async)]
fn extract_audio_cover(state: State<AppState>, note_id: String, rel_path: String) -> Result<Option<String>, String> {
    let file_path = safe_note_path(&note_id, &rel_path)?;
    if !file_path.exists() {
        eprintln!("[COVER] File not found: {}", file_path.display());
        return Ok(None);
    }
    
    // 先检查是否有自定义封面文件（同名.cover.jpg）
    let cover_path = file_path.with_extension("cover.jpg");
    if cover_path.exists() {
        let mut cover_bytes = std::fs::read(&cover_path).map_err(|e| e.to_string())?;
        if let Ok(Some(key)) = get_note_key(&state, &note_id) {
            if let Ok(dec) = decrypt_binary(&key, &cover_bytes) { cover_bytes = dec; }
        }
        let b64 = STANDARD.encode(&cover_bytes);
        return Ok(Some(format!("data:image/jpeg;base64,{}", b64)));
    }
    
    // 读取原始文件并可能解密
    let mut bytes = std::fs::read(&file_path).map_err(|e| e.to_string())?;
    if let Ok(Some(key)) = get_note_key(&state, &note_id) {
        if let Ok(dec) = decrypt_binary(&key, &bytes) { bytes = dec; }
    }
    
    eprintln!("[COVER] Read {} bytes from {}", bytes.len(), rel_path);
    
    use lofty::probe::Probe;
    use lofty::file::TaggedFileExt;
    
    let cursor = std::io::Cursor::new(&bytes);
    if let Ok(probe) = Probe::new(cursor).guess_file_type() {
        if let Ok(tagged_file) = probe.read() {
            let tag = tagged_file.primary_tag().or_else(|| tagged_file.first_tag());
            if let Some(tag) = tag {
                for pic in tag.pictures() {
                    let mime = match pic.mime_type() {
                        Some(m) => m.as_str(),
                        None => "image/jpeg",
                    };
                    let b64 = STANDARD.encode(pic.data());
                    eprintln!("[COVER] Found cover using lofty: {} ({} bytes)", mime, pic.data().len());
                    return Ok(Some(format!("data:{};base64,{}", mime, b64)));
                }
            }
        }
    }
    
    // 手动搜索后备方案：针对被截断的文件或者标签格式解析彻底失败的情况
    if let Some(pos) = bytes.windows(3).position(|w| w == [0xFF, 0xD8, 0xFF]) {
        if let Some(end_offset) = bytes[pos..].windows(2).rposition(|w| w == [0xFF, 0xD9]) {
            let jpeg_data = &bytes[pos..pos + end_offset + 2];
            if jpeg_data.len() > 1000 && jpeg_data.len() < 5_000_000 {
                eprintln!("[COVER] Found embedded JPEG via binary scan: {} bytes", jpeg_data.len());
                let b64 = STANDARD.encode(jpeg_data);
                return Ok(Some(format!("data:image/jpeg;base64,{}", b64)));
            }
        }
    }
    
    eprintln!("[COVER] No cover found for {}", rel_path);
    Ok(None)
}

/// 为音频设置自定义封面（保存为同名.cover.jpg）
#[tauri::command(async)]
fn set_audio_cover(state: State<AppState>, note_id: String, audio_rel_path: String, cover_source_path: String) -> Result<String, String> {
    let audio_path = safe_note_path(&note_id, &audio_rel_path)?;
    let cover_dest = audio_path.with_extension("cover.jpg");
    
    let mut bytes = std::fs::read(&cover_source_path).map_err(|e| e.to_string())?;
    
    if let Ok(Some(key)) = get_note_key(&state, &note_id) {
        bytes = encrypt_binary(&key, &bytes)?;
    }
    
    std::fs::write(&cover_dest, &bytes).map_err(|e| e.to_string())?;
    
    // 返回 base64 用于前端显示
    let mut display_bytes = std::fs::read(&cover_source_path).map_err(|e| e.to_string())?;
    let b64 = STANDARD.encode(&display_bytes);
    Ok(format!("data:image/jpeg;base64,{}", b64))
}

/// 从 base64 data URL 保存媒体到笔记数据目录，返回相对路径
#[tauri::command(async)]
fn save_media_base64(state: State<AppState>, note_id: String, media_type: String, file_name: String, base64_data: String) -> Result<serde_json::Value, String> {
    let raw = if let Some(pos) = base64_data.find(',') { &base64_data[pos + 1..] } else { &base64_data };
    let mut bytes = STANDARD.decode(raw).map_err(|e| e.to_string())?;
    
    let ext = Path::new(&file_name).extension().and_then(|e| e.to_str()).unwrap_or("bin");
    let hash_name = format!("{}.{}", compute_file_hash(&bytes), ext);
    
    if let Ok(Some(key)) = get_note_key(&state, &note_id) {
        bytes = encrypt_binary(&key, &bytes)?;
    }
    
    let sub = match media_type.as_str() { "image" => "images", "video" => "videos", "audio" => "audio", _ => "files" };
    let dir = safe_note_dir(&note_id)?.join(sub);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    
    let dest_path = dir.join(&hash_name);
    if !dest_path.exists() {
        std::fs::write(&dest_path, &bytes).map_err(|e| e.to_string())?;
    }
    
    Ok(json!({
        "path": format!("{}/{}", sub, hash_name),
        "size": bytes.len()
    }))
}

#[derive(serde::Serialize)]
struct OrphanedFile {
    note_id: String,
    note_title: String,
    path: String,
    rel_path: String,
    size: u64,
    preview_text: Option<String>,
}

#[tauri::command(async)]
fn get_note_orphaned_files(note_id: String) -> Result<Vec<OrphanedFile>, String> {
    let mut orphaned = Vec::new();
    let dir = safe_note_dir(&note_id)?;
    if !dir.exists() { return Ok(orphaned); }
    
    let mut referenced_paths = std::collections::HashSet::new();
    
    // Check current content
    let content_db = init_note_content_db(&note_id);
    if let Ok(json_str) = content_db.query_row::<String, _, _>("SELECT delta_json FROM content WHERE id = 'current'", [], |row| row.get(0)) {
        extract_media_paths(&json_str, &mut referenced_paths);
    }

    // 历史版本里引用的媒体同样不算闲置：只看当前快照的话，
    // 「清理无索引数据」会把时间线回溯所需的图片视频一并删掉。
    let timeline_db = init_note_timeline_db(&note_id);
    if let Ok(mut stmt) = timeline_db.prepare("SELECT delta_json FROM events") {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
            for json_str in rows.filter_map(Result::ok) {
                extract_media_paths(&json_str, &mut referenced_paths);
            }
        }
    }

    // 音频封面是 <同名>.cover.jpg，不会出现在正文里，但必须跟着音频一起留下
    let covers: Vec<String> = referenced_paths
        .iter()
        .filter_map(|p| {
            let path = Path::new(p);
            path.file_stem().and_then(|s| s.to_str()).map(|stem| {
                match path.parent().and_then(|d| d.to_str()).filter(|d| !d.is_empty()) {
                    Some(d) => format!("{}/{}.cover.jpg", d, stem),
                    None => format!("{}.cover.jpg", stem),
                }
            })
        })
        .collect();
    referenced_paths.extend(covers);


    // Scan subdirectories: images, videos, audio, files
    let subs = ["images", "videos", "audio", "files"];
    for sub in subs.iter() {
        let sub_dir = dir.join(sub);
        if sub_dir.exists() {
            if let Ok(entries) = fs::read_dir(sub_dir) {
                for entry in entries.filter_map(Result::ok) {
                    if let Ok(file_type) = entry.file_type() {
                        if file_type.is_file() {
                            let file_name = entry.file_name().to_string_lossy().into_owned();
                            let rel_str = format!("{}/{}", sub, file_name);
                            if !referenced_paths.contains(&rel_str) {
                                let mut preview_text = None;
                                if *sub == "files" {
                                    if let Some(ext) = entry.path().extension().and_then(|s| s.to_str()) {
                                        let ext_lower = ext.to_lowercase();
                                        if ["txt", "md", "json", "csv", "xml", "html", "css", "js", "rs", "py", "c", "cpp", "h"].contains(&ext_lower.as_str()) {
                                            if let Ok(mut f) = std::fs::File::open(entry.path()) {
                                                use std::io::Read;
                                                let mut buf = [0; 256];
                                                if let Ok(n) = f.read(&mut buf) {
                                                    let s = String::from_utf8_lossy(&buf[..n]).to_string();
                                                    preview_text = Some(s.chars().take(40).collect());
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                orphaned.push(OrphanedFile {
                                    note_id: note_id.clone(),
                                    note_title: String::new(),
                                    path: entry.path().to_string_lossy().into_owned(),
                                    rel_path: rel_str,
                                    size: entry.metadata().map(|m| m.len()).unwrap_or(0),
                                    preview_text,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(orphaned)
}

fn extract_media_paths(json_str: &str, paths: &mut std::collections::HashSet<String>) {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
        if let Some(ops) = json.get("ops").and_then(|o| o.as_array()) {
            for op in ops {
                if let Some(insert) = op.get("insert").and_then(|i| i.as_object()) {
                    if let Some(img) = insert.get("image").and_then(|i| i.as_str()) {
                        paths.insert(img.to_string());
                    }
                    if let Some(vid) = insert.get("customVideo").and_then(|v| v.as_str()) {
                        paths.insert(vid.to_string());
                    }
                    if let Some(file) = insert.get("customFile").and_then(|f| f.as_str()) {
                        if let Ok(file_json) = serde_json::from_str::<serde_json::Value>(file) {
                            if let Some(p) = file_json.get("path").and_then(|p| p.as_str()) {
                                paths.insert(p.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
}

#[tauri::command(async)]
fn export_note_backup(note_id: String, save_path: String) -> Result<String, String> {
    let dir = safe_note_dir(&note_id)?;
    if !dir.exists() { return Err("笔记数据目录不存在".to_string()); }
    let file = fs::File::create(&save_path).map_err(|e| e.to_string())?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar_builder = tar::Builder::new(enc);
    tar_builder.append_dir_all(&note_id, &dir).map_err(|e| e.to_string())?;
    tar_builder.finish().map_err(|e| e.to_string())?;
    Ok(save_path)
}

#[tauri::command(async)]
fn export_all_backup(save_path: String) -> Result<String, String> {
    let dir = data_root();
    if !dir.exists() { return Err("数据目录不存在".to_string()); }
    let file = fs::File::create(&save_path).map_err(|e| e.to_string())?;
    let mut tar_builder = tar::Builder::new(file);
    tar_builder.append_dir_all("anchor_notes_data", &dir).map_err(|e| e.to_string())?;
    tar_builder.finish().map_err(|e| e.to_string())?;
    Ok(save_path)
}

// ── 长图分片拼接 ──
//
// 浏览器画布有两条硬上限：单边 65535 像素、总面积 2^28（2.68 亿）像素，超过就直接
// 分配不出来。但 PNG 文件本身没有这个限制。所以超大长图改由前端按块边界渲染成若干
// 分片，这里把分片逐行写进同一个 PNG —— 输出尺寸不再受画布限制，且两端内存都只占单片。

struct StitchSession {
    writer: png::StreamWriter<'static, std::io::BufWriter<fs::File>>,
    path: PathBuf,
    width: u32,
    height: u32,
    rows_written: u32,
}

fn stitch_sessions() -> &'static Mutex<HashMap<String, StitchSession>> {
    static S: std::sync::OnceLock<Mutex<HashMap<String, StitchSession>>> = std::sync::OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

#[tauri::command(async)]
fn png_stitch_begin(width: u32, height: u32) -> Result<String, String> {
    if width == 0 || height == 0 { return Err("尺寸无效".into()); }
    let tmp_dir = std::env::temp_dir().join("anchor_stitch");
    fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
    let id = Uuid::new_v4().to_string();
    let path = tmp_dir.join(format!("{}.png", id));
    let file = fs::File::create(&path).map_err(|e| format!("无法创建临时文件：{}", e))?;

    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let writer = encoder.write_header().map_err(|e| format!("写 PNG 头失败：{}", e))?;
    let stream = writer.into_stream_writer().map_err(|e| format!("创建 PNG 流失败：{}", e))?;

    lock_or_recover(stitch_sessions()).insert(
        id.clone(),
        StitchSession { writer: stream, path, width, height, rows_written: 0 },
    );
    Ok(id)
}

/// 追加一个分片（前端 canvas.toBlob 出来的 PNG，base64）。分片宽度必须与总宽一致。
#[tauri::command(async)]
fn png_stitch_add(session_id: String, band_base64: String) -> Result<u32, String> {
    let raw = band_base64.find(',').map(|i| &band_base64[i + 1..]).unwrap_or(&band_base64);
    let bytes = STANDARD.decode(raw).map_err(|e| format!("分片数据解码失败：{}", e))?;

    let decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    let mut reader = decoder.read_info().map_err(|e| format!("分片不是合法 PNG：{}", e))?;
    let info = reader.info().clone();
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let frame = reader.next_frame(&mut buf).map_err(|e| format!("分片解码失败：{}", e))?;

    let mut sessions = lock_or_recover(stitch_sessions());
    let sess = sessions.get_mut(&session_id).ok_or_else(|| "拼接会话不存在".to_string())?;
    if info.width != sess.width {
        return Err(format!("分片宽度 {} 与总宽 {} 不一致", info.width, sess.width));
    }

    // 统一转成 RGBA8 再写入：canvas 导出的多是 RGBA，但别的通道数也要能接
    let src = &buf[..frame.buffer_size()];
    let channels = match info.color_type {
        png::ColorType::Rgba => 4,
        png::ColorType::Rgb => 3,
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Indexed => return Err("暂不支持索引色分片".into()),
    };
    let w = info.width as usize;
    let mut row_rgba = vec![0u8; w * 4];
    let mut written = 0u32;
    for y in 0..info.height as usize {
        if sess.rows_written >= sess.height { break; }
        let row = &src[y * w * channels..(y + 1) * w * channels];
        for x in 0..w {
            let p = &row[x * channels..(x + 1) * channels];
            let (r, g, b, a) = match channels {
                4 => (p[0], p[1], p[2], p[3]),
                3 => (p[0], p[1], p[2], 255),
                2 => (p[0], p[0], p[0], p[1]),
                _ => (p[0], p[0], p[0], 255),
            };
            row_rgba[x * 4] = r; row_rgba[x * 4 + 1] = g; row_rgba[x * 4 + 2] = b; row_rgba[x * 4 + 3] = a;
        }
        use std::io::Write;
        sess.writer.write_all(&row_rgba).map_err(|e| format!("写入分片失败：{}", e))?;
        sess.rows_written += 1;
        written += 1;
    }
    Ok(written)
}

/// 收尾：补齐可能缺的行，落盘到用户选定的位置。
#[tauri::command(async)]
fn png_stitch_finish(session_id: String, save_path: String) -> Result<String, String> {
    let mut sess = lock_or_recover(stitch_sessions())
        .remove(&session_id)
        .ok_or_else(|| "拼接会话不存在".to_string())?;

    // 分片总高若比声明的略少（块边界取整所致），用背景色补满，否则 PNG 行数不足会损坏
    if sess.rows_written < sess.height {
        use std::io::Write;
        let filler = vec![0u8; sess.width as usize * 4];
        while sess.rows_written < sess.height {
            sess.writer.write_all(&filler).map_err(|e| format!("补齐行失败：{}", e))?;
            sess.rows_written += 1;
        }
    }
    sess.writer.finish().map_err(|e| format!("PNG 收尾失败：{}", e))?;

    let dest = PathBuf::from(&save_path);
    if let Some(parent) = dest.parent() { fs::create_dir_all(parent).ok(); }
    if fs::rename(&sess.path, &dest).is_err() {
        fs::copy(&sess.path, &dest).map_err(|e| format!("保存失败：{}", e))?;
        fs::remove_file(&sess.path).ok();
    }
    Ok(save_path)
}

#[tauri::command(async)]
fn png_stitch_abort(session_id: String) -> Result<(), String> {
    if let Some(sess) = lock_or_recover(stitch_sessions()).remove(&session_id) {
        fs::remove_file(&sess.path).ok();
    }
    Ok(())
}

#[derive(Serialize)]
struct ImportSummary {
    imported: usize,
    renamed: usize,
    titles: Vec<String>,
}

/// 把归档条目路径安全地落到 base 之下。tar 条目可以带 `..` 或绝对路径
/// （zip-slip），不校验就能写到数据目录之外的任意位置。
fn sanitize_archive_path(base: &Path, entry_path: &Path) -> Result<PathBuf, String> {
    let mut safe = base.to_path_buf();
    for comp in entry_path.components() {
        match comp {
            std::path::Component::Normal(p) => safe.push(p),
            std::path::Component::CurDir => {}
            _ => return Err("备份文件包含非法路径，已中止导入".into()),
        }
    }
    if safe == base { return Err("备份文件包含非法路径，已中止导入".into()); }
    Ok(safe)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry.path(), &to)?;
        } else {
            fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

/// 在解包目录里找出所有笔记目录（含 content.db 或 timeline.db 的目录）。
fn find_note_dirs(root: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 3 { return; }
    let entries = match fs::read_dir(root) { Ok(e) => e, Err(_) => return };
    for entry in entries.filter_map(Result::ok) {
        let p = entry.path();
        if !p.is_dir() { continue; }
        if p.join("content.db").exists() || p.join("timeline.db").exists() {
            out.push(p);
        } else {
            find_note_dirs(&p, out, depth + 1);
        }
    }
}

/// 从笔记自身的 content.db 里推导标题和摘要（未加密时）。
fn derive_title_preview(note_dir: &Path) -> Option<(String, String)> {
    let db = Connection::open(note_dir.join("content.db")).ok()?;
    let json: String = db.query_row("SELECT delta_json FROM content WHERE id = 'current'", [], |r| r.get(0)).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&json).ok()?;
    let ops = parsed.get("ops").and_then(|o| o.as_array())?;
    let mut text = String::new();
    for op in ops {
        if let Some(s) = op.get("insert").and_then(|i| i.as_str()) {
            text.push_str(s);
            if text.len() > 400 { break; }
        }
    }
    let mut lines = text.splitn(2, '\n');
    let title = lines.next().unwrap_or("").trim().to_string();
    let preview: String = lines.next().unwrap_or("").chars().take(100).collect();
    Some((
        if title.is_empty() { "导入的笔记".into() } else { title },
        preview.replace('\n', " "),
    ))
}

/// 归一化标题用于相似度比较：去掉空白和常见标点，转小写。
fn normalize_title(t: &str) -> String {
    t.chars()
        .filter(|c| !c.is_whitespace() && !c.is_ascii_punctuation()
            && !matches!(*c, '，' | '。' | '、' | '；' | '：' | '？' | '！' | '（' | '）' | '《' | '》' | '“' | '”' | '‘' | '’' | '—' | '·'))
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn levenshtein(a: &[char], b: &[char]) -> usize {
    if a.is_empty() { return b.len(); }
    if b.is_empty() { return a.len(); }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// 0.0~1.0 的标题相似度。完全相同为 1.0。
fn title_similarity(a: &str, b: &str) -> f64 {
    let (na, nb) = (normalize_title(a), normalize_title(b));
    if na.is_empty() || nb.is_empty() { return 0.0; }
    if na == nb { return 1.0; }
    let ca: Vec<char> = na.chars().collect();
    let cb: Vec<char> = nb.chars().collect();
    let max = ca.len().max(cb.len()) as f64;
    1.0 - (levenshtein(&ca, &cb) as f64 / max)
}

// ── 笔记内容摘要与差异 ──
//
// 笔记正文是 Quill 的 delta（JSON）。要在导入冲突界面上比对「现有」和「备份里的」两个版本，
// 先把 delta 渲染成一行一行的类 Markdown 文本：格式（标题/列表/加粗…）和非文字内容
// （图片/视频/音频/文件）都以标记的形式留在行内，这样一个普通的逐行 diff 就能同时反映
// 文字、格式和媒体的变化。媒体文件名本身是内容哈希，路径相同就等于内容相同。

#[derive(Serialize, Clone, Default)]
struct DocStats {
    chars: usize,
    /// chars 里有多少是媒体折合出来的（文件字节数 ÷ 100，最少 16）
    media_chars: usize,
    images: usize,
    videos: usize,
    audio: usize,
    files: usize,
    lines: usize,
}

struct DocSummary {
    lines: Vec<String>,
    stats: DocStats,
}

fn embed_label(kind: &str, value: &serde_json::Value) -> (String, &'static str) {
    // 返回（行内标记, 统计类别）
    let short = |s: &str| -> String {
        if s.starts_with("data:") { "内嵌数据".to_string() } else { s.to_string() }
    };
    match kind {
        "image" => (format!("[图片: {}]", short(value.as_str().unwrap_or(""))), "image"),
        "customVideo" => (format!("[视频: {}]", short(value.as_str().unwrap_or(""))), "video"),
        "customAudio" | "customFile" => {
            let (label, cat) = if kind == "customAudio" { ("音频", "audio") } else { ("文件", "file") };
            // 这两种的值是一段 JSON 字符串：{"path":..,"name":..}
            let parsed = value.as_str().and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
            let (name, path) = match &parsed {
                Some(v) => (
                    v.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    v.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                ),
                None => (String::new(), value.as_str().unwrap_or("").to_string()),
            };
            (format!("[{}: {} {}]", label, name, path).replace("  ", " "), cat)
        }
        other => (format!("[嵌入: {}]", other), "other"),
    }
}

fn inline_format(text: &str, attrs: Option<&serde_json::Value>) -> String {
    let a = match attrs { Some(a) if a.is_object() => a, _ => return text.to_string() };
    let truthy = |k: &str| a.get(k).map(|v| v.as_bool().unwrap_or(!v.is_null())).unwrap_or(false);
    let mut t = text.to_string();
    if truthy("code") { t = format!("`{}`", t); }
    if truthy("strike") { t = format!("~~{}~~", t); }
    if truthy("underline") { t = format!("<u>{}</u>", t); }
    if truthy("italic") { t = format!("_{}_", t); }
    if truthy("bold") { t = format!("**{}**", t); }
    if let Some(l) = a.get("link").and_then(|v| v.as_str()) { t = format!("[{}]({})", t, l); }
    if let Some(c) = a.get("color").and_then(|v| v.as_str()) { t = format!("{{color={}}}{}{{/}}", c, t); }
    if let Some(c) = a.get("background").and_then(|v| v.as_str()) { t = format!("{{bg={}}}{}{{/}}", c, t); }
    if let Some(sz) = a.get("size").and_then(|v| v.as_str()) { t = format!("{{size={}}}{}{{/}}", sz, t); }
    t
}

fn block_prefix(attrs: Option<&serde_json::Value>) -> String {
    let a = match attrs { Some(a) if a.is_object() => a, _ => return String::new() };
    let mut p = String::new();
    if let Some(n) = a.get("indent").and_then(|v| v.as_u64()) { p.push_str(&"  ".repeat(n as usize)); }
    if let Some(al) = a.get("align").and_then(|v| v.as_str()) { p.push_str(&format!("{{align={}}} ", al)); }
    if let Some(h) = a.get("header").and_then(|v| v.as_u64()) { p.push_str(&"#".repeat(h as usize)); p.push(' '); }
    if let Some(l) = a.get("list").and_then(|v| v.as_str()) {
        p.push_str(match l { "ordered" => "1. ", "checked" => "[x] ", "unchecked" => "[ ] ", _ => "- " });
    }
    if a.get("blockquote").map(|v| !v.is_null() && v.as_bool() != Some(false)).unwrap_or(false) { p.push_str("> "); }
    if a.get("code-block").map(|v| !v.is_null() && v.as_bool() != Some(false)).unwrap_or(false) { p.push_str("│ "); }
    p
}

/// 媒体折合成多少「字」：文件字节数 ÷ 100，最少 16，取整。
/// 这样一张大图比一张小图在「内容量」上权重更大，对数条也能反映媒体的增减。
const MEDIA_BYTES_PER_CHAR: usize = 100;
const MEDIA_MIN_CHARS: usize = 16;

fn embed_rel_path(kind: &str, value: &serde_json::Value) -> String {
    match kind {
        "customAudio" | "customFile" => value
            .as_str()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .and_then(|v| v.get("path").and_then(|p| p.as_str()).map(|p| p.to_string()))
            .unwrap_or_default(),
        _ => value.as_str().unwrap_or("").to_string(),
    }
}

fn media_weight(note_dir: Option<&Path>, rel: &str) -> usize {
    let size = if rel.starts_with("data:") {
        // 内嵌的 base64：按解码后的大小算
        rel.split(',').nth(1).map(|b| b.len() * 3 / 4).unwrap_or(0)
    } else {
        note_dir
            .and_then(|dir| {
                // 路径来自笔记内容，不可信：只接受普通路径段，拒绝 .. 和绝对路径
                let mut full = dir.to_path_buf();
                for comp in Path::new(rel).components() {
                    match comp {
                        std::path::Component::Normal(p) => full.push(p),
                        std::path::Component::CurDir => {}
                        _ => return None,
                    }
                }
                fs::metadata(full).ok().map(|m| m.len() as usize)
            })
            .unwrap_or(0)
    };
    (size / MEDIA_BYTES_PER_CHAR).max(MEDIA_MIN_CHARS)
}

fn summarize_delta(json: &str, note_dir: Option<&Path>) -> DocSummary {
    let mut sum = DocSummary { lines: Vec::new(), stats: DocStats::default() };
    let v: serde_json::Value = match serde_json::from_str(json) { Ok(v) => v, Err(_) => return sum };
    let ops = match v.get("ops").and_then(|o| o.as_array()).or_else(|| v.as_array()) { Some(o) => o, None => return sum };

    let mut cur = String::new();
    for op in ops {
        let attrs = op.get("attributes");
        match op.get("insert") {
            Some(serde_json::Value::String(t)) => {
                let pieces: Vec<&str> = t.split('\n').collect();
                for (i, piece) in pieces.iter().enumerate() {
                    if !piece.is_empty() {
                        sum.stats.chars += piece.chars().count();
                        cur.push_str(&inline_format(piece, attrs));
                    }
                    if i + 1 < pieces.len() {
                        // 这个换行符上的属性才是整行的格式（标题、列表……）
                        sum.lines.push(format!("{}{}", block_prefix(attrs), cur));
                        cur.clear();
                    }
                }
            }
            Some(serde_json::Value::Object(o)) => {
                for (k, val) in o.iter() {
                    let (label, cat) = embed_label(k, val);
                    match cat {
                        "image" => sum.stats.images += 1,
                        "video" => sum.stats.videos += 1,
                        "audio" => sum.stats.audio += 1,
                        "file" => sum.stats.files += 1,
                        _ => {}
                    }
                    if matches!(cat, "image" | "video" | "audio" | "file") {
                        let w = media_weight(note_dir, &embed_rel_path(k, val));
                        sum.stats.chars += w;
                        sum.stats.media_chars += w;
                    }
                    cur.push_str(&label);
                }
            }
            _ => {}
        }
    }
    if !cur.is_empty() { sum.lines.push(cur); }
    sum.stats.lines = sum.lines.len();
    sum
}

/// 现有笔记的正文。加密且未解锁时返回 Err("locked")，调用方据此显示「无法比较」。
fn read_live_note_delta(state: &State<AppState>, note_id: &str) -> Result<Option<String>, String> {
    let key = get_note_key(state, note_id)?;           // 未解锁 -> Err
    let dir = safe_note_dir(note_id)?;
    if !dir.join("content.db").exists() { return Ok(None); }
    let db = Connection::open(dir.join("content.db")).map_err(|e| e.to_string())?;
    let raw: Option<String> = db
        .query_row("SELECT delta_json FROM content WHERE id = 'current'", [], |r| r.get(0))
        .ok();
    match (raw, key) {
        (Some(r), Some(k)) => decrypt_text(&k, &r).map(Some),
        (Some(r), None) => Ok(Some(r)),
        (None, _) => Ok(None),
    }
}

fn read_archived_note_delta(dir: &Path) -> Option<String> {
    let db = Connection::open(dir.join("content.db")).ok()?;
    db.query_row("SELECT delta_json FROM content WHERE id = 'current'", [], |r| r.get::<_, String>(0)).ok()
}

/// 每行都以换行结尾再拼接。用 join 的话最后一行没有结尾换行，
/// 会和另一边「内容相同但带换行」的最后一行被判为不同，凭空多出一对 -/+。
fn lines_to_text(lines: &[String]) -> String {
    let mut t = String::new();
    for l in lines { t.push_str(l); t.push('\n'); }
    t
}

struct LineDiffSummary {
    ratio: f64,
    added: usize,
    removed: usize,
}

fn compare_lines(old: &[String], new: &[String]) -> LineDiffSummary {
    use similar::{Algorithm, ChangeTag, TextDiff};
    let a = lines_to_text(old);
    let b = lines_to_text(new);
    let diff = TextDiff::configure()
        .algorithm(Algorithm::Myers)
        .timeout(std::time::Duration::from_secs(2))
        .diff_lines(&a, &b);
    let (mut added, mut removed) = (0usize, 0usize);
    for c in diff.iter_all_changes() {
        match c.tag() {
            ChangeTag::Insert => added += 1,
            ChangeTag::Delete => removed += 1,
            ChangeTag::Equal => {}
        }
    }
    // 两边都是空文档时相似度记 1.0；一边为空另一边不空为 0
    let ratio = if old.is_empty() && new.is_empty() { 1.0 } else { diff.ratio() as f64 };
    LineDiffSummary { ratio, added, removed }
}

#[derive(Serialize)]
struct DiffLine {
    tag: &'static str,           // "eq" | "del" | "ins"
    old_no: Option<usize>,
    new_no: Option<usize>,
    text: String,
}

#[derive(Serialize)]
struct MetaDiff {
    label: String,
    old: String,
    new: String,
}

#[derive(Serialize)]
struct DiffResult {
    meta: Vec<MetaDiff>,
    lines: Vec<DiffLine>,
    added: usize,
    removed: usize,
    truncated: bool,
}

fn fmt_ms(ms: i64) -> String {
    use chrono::TimeZone;
    chrono::Local.timestamp_millis_opt(ms).single()
        .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "-".into())
}

/// 按需生成两个版本的逐行差异。只在用户点「查看差异」时才算，扫描阶段不做。
#[tauri::command(async)]
fn import_diff(state: State<AppState>, session_id: String, src_id: String, existing_id: String) -> Result<DiffResult, String> {
    validate_note_id(&existing_id)?;
    let (dir, meta) = {
        let sessions = lock_or_recover(import_sessions());
        let sess = sessions.get(&session_id).ok_or_else(|| "导入会话已失效，请重新选择备份文件".to_string())?;
        let (d, m) = sess.entries.get(&src_id).ok_or_else(|| "找不到这篇笔记".to_string())?;
        (d.clone(), m.clone())
    };
    if meta.is_encrypted == 1 { return Err("备份里的这篇是加密笔记，无法比较内容".into()); }

    let new_json = read_archived_note_delta(&dir).unwrap_or_default();
    let old_json = match read_live_note_delta(&state, &existing_id) {
        Ok(j) => j.unwrap_or_default(),
        Err(_) => return Err("现有的这篇是加密笔记且尚未解锁，无法比较内容".into()),
    };
    let old_dir = safe_note_dir(&existing_id)?;
    let old = summarize_delta(&old_json, Some(&old_dir));
    let new = summarize_delta(&new_json, Some(&dir));

    // 元数据差异
    let mut metas = Vec::new();
    let existing_row: Option<(i64, i64, String)> = {
        let idx = lock_or_recover(&state.index_db);
        idx.query_row(
            "SELECT COALESCE(created_at,0), COALESCE(updated_at,0), COALESCE(background,'default') FROM notes WHERE id = ?1",
            params![existing_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).ok()
    };
    if let Some((c, u, bg)) = existing_row {
        if bg != meta.background { metas.push(MetaDiff { label: "背景".into(), old: bg, new: meta.background.clone() }); }
        metas.push(MetaDiff { label: "修改时间".into(), old: fmt_ms(u), new: fmt_ms(meta.updated_at) });
        metas.push(MetaDiff { label: "创建时间".into(), old: fmt_ms(c), new: fmt_ms(meta.created_at) });
    }

    use similar::{Algorithm, ChangeTag, TextDiff};
    let a = lines_to_text(&old.lines);
    let b = lines_to_text(&new.lines);
    let diff = TextDiff::configure()
        .algorithm(Algorithm::Myers)
        .timeout(std::time::Duration::from_secs(3))
        .diff_lines(&a, &b);

    const MAX_LINES: usize = 20000;
    let mut lines = Vec::new();
    let (mut added, mut removed) = (0usize, 0usize);
    let mut truncated = false;
    for c in diff.iter_all_changes() {
        if lines.len() >= MAX_LINES { truncated = true; break; }
        let text = c.value().trim_end_matches('\n').to_string();
        let tag = match c.tag() {
            ChangeTag::Equal => "eq",
            ChangeTag::Delete => { removed += 1; "del" }
            ChangeTag::Insert => { added += 1; "ins" }
        };
        lines.push(DiffLine { tag, old_no: c.old_index().map(|i| i + 1), new_no: c.new_index().map(|i| i + 1), text });
    }
    Ok(DiffResult { meta: metas, lines, added, removed, truncated })
}

#[derive(Serialize)]
struct SimilarNote {
    id: String,
    title: String,
    preview: String,
    /// 标题相似度 0~1
    similarity: f64,
    /// 正文相似度 0~1；加密未解锁时没有
    content_similarity: Option<f64>,
    /// 综合得分，候选按它排序
    score: f64,
    is_archived: bool,
    is_encrypted: bool,
    locked: bool,
    created_at: i64,
    updated_at: i64,
    background: String,
    stats: Option<DocStats>,
    /// 新版相对这个候选，新增/删除了多少行
    added_lines: usize,
    removed_lines: usize,
}

#[derive(Serialize)]
struct ScannedNote {
    src_id: String,
    title: String,
    preview: String,
    is_encrypted: bool,
    created_at: i64,
    updated_at: i64,
    background: String,
    stats: Option<DocStats>,
    similar: Vec<SimilarNote>,
}

#[derive(Serialize)]
struct ImportScan {
    session_id: String,
    notes: Vec<ScannedNote>,
}

struct ImportSession {
    tmp_dir: PathBuf,
    // src_id -> (笔记目录, 元数据)
    entries: HashMap<String, (PathBuf, NoteMeta)>,
}

#[derive(Clone)]
struct NoteMeta {
    title: String,
    preview: String,
    created_at: i64,
    updated_at: i64,
    is_encrypted: i32,
    salt: Option<String>,
    token: Option<String>,
    background: String,
}

fn import_sessions() -> &'static Mutex<HashMap<String, ImportSession>> {
    static S: std::sync::OnceLock<Mutex<HashMap<String, ImportSession>>> = std::sync::OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn unpack_archive(archive_path: &str, tmp_dir: &Path) -> Result<(), String> {
    let file = fs::File::open(archive_path).map_err(|e| format!("无法打开备份文件：{}", e))?;
    let mut magic = [0u8; 2];
    {
        use std::io::Read;
        let mut probe = fs::File::open(archive_path).map_err(|e| e.to_string())?;
        let _ = probe.read_exact(&mut magic);
    }
    let reader: Box<dyn std::io::Read> = if magic == [0x1f, 0x8b] {
        Box::new(flate2::read::GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path().map_err(|e| e.to_string())?.into_owned();
        let safe = sanitize_archive_path(tmp_dir, &path)?;
        if let Some(parent) = safe.parent() { fs::create_dir_all(parent).ok(); }
        entry.unpack(&safe).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn find_archive_index(root: &Path) -> Option<Connection> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for e in entries.filter_map(Result::ok) {
                let p = e.path();
                if p.is_dir() { stack.push(p); }
                else if p.file_name().and_then(|n| n.to_str()) == Some("notes_index.db") {
                    if let Ok(db) = Connection::open(&p) { return Some(db); }
                }
            }
        }
    }
    None
}

/// 第一步：解包并扫描，返回每篇笔记以及和现有笔记的标题相似情况。
/// 拆成扫描 / 应用两步，是为了让用户在冲突界面上逐篇决定怎么处理。
#[tauri::command(async)]
fn import_scan(state: State<AppState>, archive_path: String) -> Result<ImportScan, String> {
    let tmp_dir = std::env::temp_dir().join(format!("anchor_import_{}", Utc::now().timestamp_millis()));
    fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
    if let Err(e) = unpack_archive(&archive_path, &tmp_dir) {
        fs::remove_dir_all(&tmp_dir).ok();
        return Err(e);
    }

    let archive_index = find_archive_index(&tmp_dir);
    let mut note_dirs = Vec::new();
    find_note_dirs(&tmp_dir, &mut note_dirs, 0);
    if note_dirs.is_empty() {
        fs::remove_dir_all(&tmp_dir).ok();
        return Err("备份文件里没有找到任何笔记数据".into());
    }

    // 现有笔记（含归档区）用于比对：先把索引行收集完并释放锁，再去读各自的正文
    struct ExistingRow {
        id: String, title: String, preview: String, archived: bool, encrypted: bool,
        created_at: i64, updated_at: i64, background: String,
    }
    let existing: Vec<ExistingRow> = {
        let idx = lock_or_recover(&state.index_db);
        let keys = lock_or_recover(&state.unlocked_keys);
        let mut stmt = idx
            .prepare("SELECT id, COALESCE(title,''), COALESCE(preview,''), COALESCE(is_archived,0), COALESCE(is_encrypted,0), COALESCE(created_at,0), COALESCE(updated_at,0), COALESCE(background,'default') FROM notes")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| Ok((
                r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, i32>(3)?, r.get::<_, i32>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?, r.get::<_, String>(7)?,
            )))
            .map_err(|e| e.to_string())?;
        rows.filter_map(Result::ok)
            .map(|(id, t, pv, arch, enc, c, u, bg)| {
                let key = keys.get(&id);
                ExistingRow {
                    title: decrypt_meta(key, &t, ""),
                    preview: decrypt_meta(key, &pv, ""),
                    id, archived: arch == 1, encrypted: enc == 1, created_at: c, updated_at: u, background: bg,
                }
            })
            .collect()
    };
    // 现有笔记正文摘要的缓存：同一篇可能是多篇新笔记的候选
    let mut existing_docs: HashMap<String, Option<DocSummary>> = HashMap::new();

    let now = Utc::now().timestamp_millis();
    let mut entries = HashMap::new();
    let mut scanned = Vec::new();

    for dir in &note_dirs {
        let src_id = match dir.file_name().and_then(|n| n.to_str()) { Some(s) => s.to_string(), None => continue };
        let meta_row = archive_index.as_ref().and_then(|db| {
            db.query_row(
                "SELECT COALESCE(title,''), COALESCE(preview,''), COALESCE(created_at,0), COALESCE(updated_at,0), COALESCE(is_encrypted,0), encryption_salt, verify_token, COALESCE(background,'default') FROM notes WHERE id = ?1",
                params![src_id],
                |r| Ok(NoteMeta {
                    title: r.get(0)?, preview: r.get(1)?, created_at: r.get(2)?, updated_at: r.get(3)?,
                    is_encrypted: r.get(4)?, salt: r.get(5)?, token: r.get(6)?, background: r.get(7)?,
                }),
            ).ok()
        });
        let meta = match meta_row {
            Some(m) => m,
            None => {
                let (t, p) = derive_title_preview(dir).unwrap_or_else(|| ("导入的笔记".into(), String::new()));
                NoteMeta { title: t, preview: p, created_at: now, updated_at: now, is_encrypted: 0, salt: None, token: None, background: "default".into() }
            }
        };

        // 加密笔记的标题本身是密文，没法比对，只显示占位
        let shown_title = decrypt_meta(None, &meta.title, "🔒 已加密笔记");
        let shown_preview = decrypt_meta(None, &meta.preview, "解锁后可见");

        // 备份里这篇的正文摘要（加密的读不了）
        let new_doc: Option<DocSummary> = if meta.is_encrypted == 0 {
            read_archived_note_delta(dir).map(|j| summarize_delta(&j, Some(dir.as_path())))
        } else { None };

        let mut similar: Vec<SimilarNote> = Vec::new();
        if meta.is_encrypted == 0 && !shown_title.is_empty() {
            // 标题相同的笔记可能有一大堆（比如全是默认的「新笔记标题」），
            // 光看标题分不出该和哪篇比，所以先按标题筛一遍，再用正文相似度排序
            let mut cands: Vec<(&ExistingRow, f64)> = existing.iter()
                .filter(|e| !e.title.is_empty())
                .map(|e| (e, title_similarity(&shown_title, &e.title)))
                .filter(|(_, sim)| *sim >= 0.6)
                .collect();
            cands.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            cands.truncate(30);

            for (e, sim) in cands {
                let doc = existing_docs.entry(e.id.clone()).or_insert_with(|| {
                    match read_live_note_delta(&state, &e.id) {
                        Ok(Some(j)) => Some(summarize_delta(&j, safe_note_dir(&e.id).ok().as_deref())),
                        _ => None,
                    }
                });
                let locked = e.encrypted && doc.is_none();
                let (content_sim, added, removed, stats) = match (doc.as_ref(), new_doc.as_ref()) {
                    (Some(old), Some(new)) => {
                        let c = compare_lines(&old.lines, &new.lines);
                        (Some(c.ratio), c.added, c.removed, Some(old.stats.clone()))
                    }
                    (Some(old), None) => (None, 0, 0, Some(old.stats.clone())),
                    _ => (None, 0, 0, None),
                };
                let score = match content_sim { Some(c) => 0.35 * sim + 0.65 * c, None => sim };
                similar.push(SimilarNote {
                    id: e.id.clone(), title: e.title.clone(), preview: e.preview.chars().take(120).collect(),
                    similarity: (sim * 100.0).round() / 100.0,
                    content_similarity: content_sim.map(|c| (c * 100.0).round() / 100.0),
                    score: (score * 1000.0).round() / 1000.0,
                    is_archived: e.archived, is_encrypted: e.encrypted, locked,
                    created_at: e.created_at, updated_at: e.updated_at, background: e.background.clone(),
                    stats, added_lines: added, removed_lines: removed,
                });
            }
            similar.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
            similar.truncate(5);
        }

        scanned.push(ScannedNote {
            src_id: src_id.clone(),
            title: shown_title.chars().take(60).collect(),
            preview: shown_preview.chars().take(120).collect(),
            is_encrypted: meta.is_encrypted == 1,
            created_at: meta.created_at,
            updated_at: meta.updated_at,
            background: meta.background.clone(),
            stats: new_doc.as_ref().map(|d| d.stats.clone()),
            similar,
        });
        entries.insert(src_id, (dir.clone(), meta));
    }

    let session_id = Uuid::new_v4().to_string();
    lock_or_recover(import_sessions()).insert(session_id.clone(), ImportSession { tmp_dir, entries });
    scanned.sort_by(|a, b| b.similar.len().cmp(&a.similar.len()));
    Ok(ImportScan { session_id, notes: scanned })
}

#[derive(Deserialize)]
struct ImportDecision {
    src_id: String,
    /// "import" 正常导入 / "skip" 跳过 / "replace" 导入并把被替换的旧笔记移入归档区
    action: String,
    /// action 为 replace 时，要被归档的那篇现有笔记
    replace_id: Option<String>,
}

/// 第二步：按用户在冲突界面上的决定执行导入。
///
/// 「替换」不会删除任何东西——旧笔记只是被移进归档区，误操作可以从归档区找回。
#[tauri::command(async)]
fn import_apply(state: State<AppState>, session_id: String, decisions: Vec<ImportDecision>) -> Result<ImportSummary, String> {
    let session = lock_or_recover(import_sessions())
        .remove(&session_id)
        .ok_or_else(|| "导入会话已失效，请重新选择备份文件".to_string())?;

    let now = Utc::now().timestamp_millis();
    let mut summary = ImportSummary { imported: 0, renamed: 0, titles: Vec::new() };
    let mut archived_count = 0usize;

    {
        let idx = lock_or_recover(&state.index_db);
        for d in &decisions {
            if d.action == "skip" { continue; }
            let (dir, meta) = match session.entries.get(&d.src_id) { Some(v) => v, None => continue };

            let taken: bool = idx
                .query_row("SELECT COUNT(*) FROM notes WHERE id = ?1", params![d.src_id], |r| r.get::<_, i64>(0))
                .map(|c| c > 0).unwrap_or(false)
                || data_root().join(&d.src_id).exists()
                || validate_note_id(&d.src_id).is_err();
            let target_id = if taken { summary.renamed += 1; Uuid::new_v4().to_string() } else { d.src_id.clone() };

            let dest = data_root().join(&target_id);
            if copy_dir_recursive(dir, &dest).is_err() { continue; }
            for sub in &["images", "videos", "files", "audio"] { fs::create_dir_all(dest.join(sub)).ok(); }

            let ok = idx.execute(
                "INSERT INTO notes (id, created_at, updated_at, title, preview, is_archived, background, is_encrypted, encryption_salt, verify_token) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9)",
                params![target_id, if meta.created_at > 0 { meta.created_at } else { now },
                        if meta.updated_at > 0 { meta.updated_at } else { now },
                        meta.title, meta.preview, meta.background, meta.is_encrypted, meta.salt, meta.token],
            ).is_ok();
            if !ok { continue; }

            summary.imported += 1;
            summary.titles.push(decrypt_meta(None, &meta.title, "🔒 已加密笔记").chars().take(30).collect());

            // 替换：旧的那篇移进归档区而不是删除
            if d.action == "replace" {
                if let Some(rid) = &d.replace_id {
                    if validate_note_id(rid).is_ok()
                        && idx.execute("UPDATE notes SET is_archived = 1 WHERE id = ?1", params![rid]).is_ok() {
                        archived_count += 1;
                    }
                }
            }
        }
    }

    fs::remove_dir_all(&session.tmp_dir).ok();
    if summary.imported == 0 { return Err("没有导入任何笔记".into()); }
    summary.renamed = archived_count;   // 复用字段回传「被移入归档区的数量」
    Ok(summary)
}

#[tauri::command(async)]
fn import_cancel(session_id: String) -> Result<(), String> {
    if let Some(sess) = lock_or_recover(import_sessions()).remove(&session_id) {
        fs::remove_dir_all(&sess.tmp_dir).ok();
    }
    Ok(())
}

/// 选择性全局备份：只打包指定的笔记，并附带一份只含这些笔记的索引库，
/// 这样加密笔记的 salt / 校验令牌能跟着走，导入后原密码依然有效。
#[tauri::command(async)]
fn export_selected_backup(state: State<AppState>, save_path: String, note_ids: Vec<String>) -> Result<usize, String> {
    if note_ids.is_empty() { return Err("没有选择任何笔记".into()); }

    let staging = std::env::temp_dir().join(format!("anchor_export_{}", Utc::now().timestamp_millis()));
    fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    let result = (|| -> Result<usize, String> {
        // 过滤后的索引库
        let index_path = staging.join("notes_index.db");
        let out = Connection::open(&index_path).map_err(|e| e.to_string())?;
        out.execute(
            "CREATE TABLE notes (id TEXT PRIMARY KEY, created_at INTEGER, updated_at INTEGER, title TEXT, preview TEXT,
             is_archived INTEGER DEFAULT 0, folder_id TEXT, background TEXT DEFAULT 'default',
             is_encrypted INTEGER DEFAULT 0, encryption_salt TEXT, verify_token TEXT)", [],
        ).map_err(|e| e.to_string())?;
        out.execute("CREATE TABLE folders (id TEXT PRIMARY KEY, name TEXT, created_at INTEGER)", []).map_err(|e| e.to_string())?;

        let mut copied = 0usize;
        {
            let idx = lock_or_recover(&state.index_db);
            for id in &note_ids {
                if validate_note_id(id).is_err() { continue; }
                let row = idx.query_row(
                    "SELECT id, COALESCE(created_at,0), COALESCE(updated_at,0), COALESCE(title,''), COALESCE(preview,''),
                            COALESCE(is_archived,0), folder_id, COALESCE(background,'default'),
                            COALESCE(is_encrypted,0), encryption_salt, verify_token FROM notes WHERE id = ?1",
                    params![id],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?,
                            r.get::<_, String>(4)?, r.get::<_, i32>(5)?, r.get::<_, Option<String>>(6)?,
                            r.get::<_, String>(7)?, r.get::<_, i32>(8)?, r.get::<_, Option<String>>(9)?, r.get::<_, Option<String>>(10)?)),
                );
                let row = match row { Ok(r) => r, Err(_) => continue };
                out.execute(
                    "INSERT INTO notes VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7, row.8, row.9, row.10],
                ).ok();
                copied += 1;
            }
            let folders: Vec<(String, String, i64)> = {
                let mut fstmt = idx.prepare("SELECT id, name, created_at FROM folders").map_err(|e| e.to_string())?;
                let rows = fstmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)))
                    .map_err(|e| e.to_string())?;
                rows.filter_map(Result::ok).collect()
            };
            for f in folders {
                out.execute("INSERT INTO folders VALUES (?1,?2,?3)", params![f.0, f.1, f.2]).ok();
            }
        }
        drop(out);
        if copied == 0 { return Err("选中的笔记都不存在".into()); }

        let file = fs::File::create(&save_path).map_err(|e| format!("无法创建备份文件：{}", e))?;
        let mut builder = tar::Builder::new(file);
        builder.append_path_with_name(&index_path, "anchor_notes_data/notes_index.db").map_err(|e| e.to_string())?;
        for id in &note_ids {
            let dir = match safe_note_dir(id) { Ok(d) => d, Err(_) => continue };
            if !dir.exists() { continue; }
            builder.append_dir_all(format!("anchor_notes_data/{}", id), &dir).map_err(|e| e.to_string())?;
        }
        builder.finish().map_err(|e| e.to_string())?;
        Ok(copied)
    })();

    fs::remove_dir_all(&staging).ok();
    result
}

#[tauri::command(async)]
fn open_data_folder(note_id: String) -> Result<(), String> {
    let dir = safe_note_dir(&note_id)?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    { std::process::Command::new("explorer").arg(dir.to_str().unwrap_or(".")).spawn().map_err(|e| e.to_string())?; }
    Ok(())
}

#[tauri::command(async)]
fn open_file_external(state: State<AppState>, note_id: String, rel_path: String) -> Result<(), String> {
    let path = safe_note_path(&note_id, &rel_path)?;
    if !path.exists() { return Err("文件不存在".into()); }
    
    let mut bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    
    // 如果笔记已加密，解密到临时文件再打开
    if let Ok(Some(key)) = get_note_key(&state, &note_id) {
        if let Ok(dec) = decrypt_binary(&key, &bytes) {
            bytes = dec;
        }
    }
    
    // 获取文件名
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp_dir = std::env::temp_dir().join("anchor_open");
    std::fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
    let tmp_path = tmp_dir.join(file_name);
    std::fs::write(&tmp_path, &bytes).map_err(|e| e.to_string())?;
    
    // 用 explorer 直接带一个参数启动，不要走 `cmd /C start`：
    // cmd 会对参数做二次解析，文件名里的引号和 & 可以拼出命令注入。
    #[cfg(target_os = "windows")]
    { std::process::Command::new("explorer.exe").arg(&tmp_path).spawn().map_err(|e| e.to_string())?; }
    Ok(())
}

#[tauri::command(async)]
fn delete_orphaned_file(note_id: String, rel_path: String) -> Result<(), String> {
    // 原先直接收一个绝对路径，等于把任意文件删除权交给前端
    let p = safe_note_path(&note_id, &rel_path)?;
    if p.is_file() {
        fs::remove_file(p).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command(async)]
fn get_folders(state: State<AppState>) -> Result<Vec<Folder>, String> {
    let db = lock_or_recover(&state.index_db);
    let mut stmt = db.prepare("SELECT id, name, created_at FROM folders ORDER BY created_at ASC").unwrap();
    let folders = stmt.query_map([], |row| {
        Ok(Folder { id: row.get(0)?, name: row.get(1)?, created_at: row.get(2)? })
    }).map_err(|e| e.to_string())?.filter_map(Result::ok).collect();
    Ok(folders)
}

#[tauri::command(async)]
fn create_folder(state: State<AppState>, name: String) -> Result<String, String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp_millis();
    let db = lock_or_recover(&state.index_db);
    db.execute(
        "INSERT INTO folders (id, name, created_at) VALUES (?1, ?2, ?3)",
        params![id, name, now],
    ).map_err(|e| e.to_string())?;
    Ok(id)
}

#[tauri::command(async)]
fn set_note_folder(state: State<AppState>, note_id: String, folder_id: Option<String>) -> Result<(), String> {
    validate_note_id(&note_id)?;
    let db = lock_or_recover(&state.index_db);
    db.execute(
        "UPDATE notes SET folder_id = ?1 WHERE id = ?2",
        params![folder_id, note_id],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command(async)]
fn delete_folder(state: State<AppState>, folder_id: String) -> Result<(), String> {
    let db = lock_or_recover(&state.index_db);
    db.execute("UPDATE notes SET folder_id = NULL WHERE folder_id = ?1", params![folder_id]).map_err(|e| e.to_string())?;
    db.execute("DELETE FROM folders WHERE id = ?1", params![folder_id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command(async)]
fn rename_folder(state: State<AppState>, folder_id: String, new_name: String) -> Result<(), String> {
    let db = lock_or_recover(&state.index_db);
    db.execute("UPDATE folders SET name = ?1 WHERE id = ?2", params![new_name, folder_id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Serialize)]
struct TaggedWord {
    word: String,
    tag: String,
}

#[tauri::command(async)]
fn segment_text(state: State<AppState>, text: String) -> Vec<TaggedWord> {
    let jieba = lock_or_recover(&state.jieba);
    let tagged = jieba.tag(&text, true);
    tagged.into_iter().map(|t| TaggedWord {
        word: t.word.to_string(),
        tag: t.tag.to_string(),
    }).collect()
}

#[tauri::command(async)]
fn get_semantic_cache(state: State<AppState>, note_id: String) -> Result<Option<String>, String> {
    let key_opt = get_note_key(&state, &note_id)?;
    let dir = safe_note_dir(&note_id)?;
    if !dir.exists() { return Ok(None); }
    let db = Connection::open(dir.join("content.db")).map_err(|e| e.to_string())?;
    db.execute(
        "CREATE TABLE IF NOT EXISTS semantic_cache (id TEXT PRIMARY KEY DEFAULT 'current', tags_json TEXT, updated_at INTEGER)",
        [],
    ).map_err(|e| e.to_string())?;
    let result: Result<String, _> = db.query_row(
        "SELECT tags_json FROM semantic_cache WHERE id = 'current'",
        [],
        |row| row.get(0),
    );
    match result {
        Ok(mut json) => {
            if let Some(key) = key_opt {
                if let Ok(dec) = decrypt_text(&key, &json) {
                    json = dec;
                } else {
                    return Ok(None);
                }
            }
            Ok(Some(json))
        },
        Err(_) => Ok(None),
    }
}

#[tauri::command(async)]
fn save_semantic_cache(state: State<AppState>, note_id: String, mut tags_json: String) -> Result<(), String> {
    let key_opt = get_note_key(&state, &note_id)?;
    if let Some(key) = key_opt {
        tags_json = encrypt_text(&key, &tags_json)?;
    }
    let dir = safe_note_dir(&note_id)?;
    if !dir.exists() { return Err("Note dir not found".into()); }
    let db = Connection::open(dir.join("content.db")).map_err(|e| e.to_string())?;
    db.execute(
        "CREATE TABLE IF NOT EXISTS semantic_cache (id TEXT PRIMARY KEY DEFAULT 'current', tags_json TEXT, updated_at INTEGER)",
        [],
    ).map_err(|e| e.to_string())?;
    let now = Utc::now().timestamp();
    db.execute(
        "INSERT OR REPLACE INTO semantic_cache (id, tags_json, updated_at) VALUES ('current', ?1, ?2)",
        params![tags_json, now],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command(async)]
fn check_note_locked(state: State<AppState>, note_id: String) -> Result<bool, String> {
    validate_note_id(&note_id)?;
    let idx = lock_or_recover(&state.index_db);
    let is_enc: i32 = idx.query_row("SELECT COALESCE(is_encrypted, 0) FROM notes WHERE id = ?1", params![note_id], |row| row.get(0)).unwrap_or(0);
    if is_enc == 0 { return Ok(false); }
    let keys = lock_or_recover(&state.unlocked_keys);
    Ok(!keys.contains_key(&note_id))
}

/// 加密笔记里存放的校验明文：用笔记密钥加密后写入 notes.verify_token，
/// 解锁时据此判断密码是否正确。
const VERIFY_PLAINTEXT: &str = "anchor-verify-v1";

/// 索引库里密文字段的前缀。有它才能把「新写入的密文」和「旧版本留下的明文」区分开，
/// 老数据不加前缀，照旧当明文显示。
const META_ENC_PREFIX: &str = "enc:v1:";

fn encrypt_meta(key: Option<&[u8; 32]>, text: &str) -> String {
    match key {
        Some(k) => encrypt_text(k, text)
            .map(|c| format!("{}{}", META_ENC_PREFIX, c))
            .unwrap_or_else(|_| text.to_string()),
        None => text.to_string(),
    }
}

fn decrypt_meta(key: Option<&[u8; 32]>, stored: &str, placeholder: &str) -> String {
    match stored.strip_prefix(META_ENC_PREFIX) {
        None => stored.to_string(),
        Some(ct) => match key {
            Some(k) => decrypt_text(k, ct).unwrap_or_else(|_| placeholder.to_string()),
            None => placeholder.to_string(),
        },
    }
}

/// 旧数据没有 verify_token，退回到「拿现有密文试解」：正文快照 → 首条历史事件 → 任一媒体文件。
/// 返回 None 表示这条笔记没有任何密文可供验证。
fn verify_legacy_key(note_id: &str, key: &[u8; 32]) -> Option<bool> {
    let content_db = init_note_content_db(note_id);
    if let Ok(json) = content_db.query_row("SELECT delta_json FROM content WHERE id = 'current'", [], |row| row.get::<_, String>(0)) {
        return Some(decrypt_text(key, &json).is_ok());
    }
    let timeline_db = init_note_timeline_db(note_id);
    if let Ok(delta) = timeline_db.query_row("SELECT delta_json FROM events ORDER BY timestamp ASC LIMIT 1", [], |row| row.get::<_, String>(0)) {
        return Some(decrypt_text(key, &delta).is_ok());
    }
    let dir = note_dir(note_id);
    for sub in &["images", "videos", "audio", "files"] {
        if let Ok(entries) = fs::read_dir(dir.join(sub)) {
            for entry in entries.filter_map(Result::ok) {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    if let Ok(bytes) = fs::read(entry.path()) {
                        return Some(decrypt_binary(key, &bytes).is_ok());
                    }
                }
            }
        }
    }
    None
}

fn store_verify_token(state: &State<AppState>, note_id: &str, key: &[u8; 32]) {
    if let Ok(token) = encrypt_text(key, VERIFY_PLAINTEXT) {
        let idx = lock_or_recover(&state.index_db);
        idx.execute("UPDATE notes SET verify_token = ?1 WHERE id = ?2", params![token, note_id]).ok();
    }
}

#[tauri::command(async)]
fn unlock_note(state: State<AppState>, note_id: String, password: String) -> Result<bool, String> {
    validate_note_id(&note_id)?;
    let idx = lock_or_recover(&state.index_db);
    let (is_enc, salt, token): (i32, Option<String>, Option<String>) = idx.query_row(
        "SELECT COALESCE(is_encrypted, 0), encryption_salt, verify_token FROM notes WHERE id = ?1",
        params![note_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(|e| e.to_string())?;
    drop(idx); // Argon2 很慢，不要占着索引库锁阻塞其他命令

    if is_enc == 0 { return Ok(true); }
    let salt = salt.ok_or_else(|| "Salt not found".to_string())?;
    let key = derive_key(&password, &salt)?;

    if let Some(token) = token {
        let ok = decrypt_text(&key, &token).map(|p| p == VERIFY_PLAINTEXT).unwrap_or(false);
        if !ok { return Ok(false); }
    } else {
        match verify_legacy_key(&note_id, &key) {
            Some(false) => return Ok(false),
            // 既没有令牌也没有任何密文（加密后还未写入内容）：无从校验，
            // 只能接受并就此固定密码，避免这条笔记以后用任何密码都能打开。
            _ => {}
        }
        store_verify_token(&state, &note_id, &key);
    }

    lock_or_recover(&state.unlocked_keys).insert(note_id, key);
    Ok(true)
}

#[tauri::command(async)]
fn lock_note(state: State<AppState>, note_id: String) -> Result<(), String> {
    validate_note_id(&note_id)?;
    lock_or_recover(&state.unlocked_keys).remove(&note_id);
    Ok(())
}

/// 登记「关机阻止原因」。Windows 在用户关机/重启时会先询问各进程，
/// 登记过原因的程序会让系统弹出「以下应用阻止关机」并把原因显示出来，
/// 用户可以取消，也可以选择强制关机——这是系统允许的做法，不会真的锁死关机。
#[tauri::command]
fn set_shutdown_block(window: tauri::Window, enable: bool, reason: Option<String>) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::System::Shutdown::{ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy};
        use windows::core::PCWSTR;
        let hwnd = HWND(window.hwnd().map_err(|e| e.to_string())?.0);
        unsafe {
            if enable {
                let text = to_wide(reason.as_deref().unwrap_or("锚点正在运行，关机可能丢失尚未保存的笔记内容"));
                if !ShutdownBlockReasonCreate(hwnd, PCWSTR(text.as_ptr())).as_bool() {
                    return Err("登记关机阻止原因失败".into());
                }
            } else {
                ShutdownBlockReasonDestroy(hwnd);
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    { let _ = (window, enable, reason); }
    Ok(())
}


#[tauri::command]
fn toggle_vibrancy(window: tauri::Window, enable: bool) {
    if enable {
        #[cfg(target_os = "windows")]
        {
            if window_vibrancy::apply_acrylic(&window, Some((0, 0, 0, 0))).is_err() {
                let _ = window_vibrancy::apply_blur(&window, Some((0, 0, 0, 0)));
            }
        }
    } else {
        #[cfg(target_os = "windows")]
        {
            let _ = window_vibrancy::clear_blur(&window);
            let _ = window_vibrancy::clear_acrylic(&window);
        }
    }
}

/// 用旧密钥解、新密钥重加密一篇笔记的全部密文。任一处失败即整体报错，由调用方回滚。
///
/// 解密失败一律当硬错误：把解不开的内容拿新密钥再加密一遍，等于永久损坏该文件。
fn rekey_note_contents(note_id: &str, old_key: &[u8; 32], new_key: &[u8; 32]) -> Result<(), String> {
    {
        let content_db = init_note_content_db(note_id);
        if let Ok(enc) = content_db.query_row("SELECT delta_json FROM content WHERE id = 'current'", [], |r| r.get::<_, String>(0)) {
            let plain = decrypt_text(old_key, &enc).map_err(|e| format!("正文解密失败：{}", e))?;
            let re = encrypt_text(new_key, &plain)?;
            content_db.execute("UPDATE content SET delta_json = ?1 WHERE id = 'current'", params![re])
                .map_err(|e| format!("正文写回失败：{}", e))?;
        }
        // 语义缓存是可再生数据，解不开就丢弃，不要因此挡住改密码
        if let Ok(enc) = content_db.query_row("SELECT tags_json FROM semantic_cache WHERE id = 'current'", [], |r| r.get::<_, String>(0)) {
            match decrypt_text(old_key, &enc).and_then(|p| encrypt_text(new_key, &p)) {
                Ok(re) => { content_db.execute("UPDATE semantic_cache SET tags_json = ?1 WHERE id = 'current'", params![re]).ok(); }
                Err(_) => { content_db.execute("DELETE FROM semantic_cache WHERE id = 'current'", []).ok(); }
            }
        }
    }
    {
        let timeline_db = init_note_timeline_db(note_id);
        let events: Vec<(String, String)> = {
            let mut stmt = timeline_db.prepare("SELECT id, delta_json FROM events").map_err(|e| e.to_string())?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map_err(|e| e.to_string())?;
            rows.filter_map(Result::ok).collect()
        };
        for (eid, enc) in events {
            let plain = decrypt_text(old_key, &enc).map_err(|e| format!("历史记录解密失败：{}", e))?;
            let re = encrypt_text(new_key, &plain)?;
            timeline_db.execute("UPDATE events SET delta_json = ?1 WHERE id = ?2", params![re, eid])
                .map_err(|e| format!("历史记录写回失败：{}", e))?;
        }
    }

    let dir = safe_note_dir(note_id)?;
    for sub in &["images", "videos", "audio", "files"] {
        let entries = match fs::read_dir(dir.join(sub)) { Ok(e) => e, Err(_) => continue };
        for entry in entries.filter_map(Result::ok) {
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) { continue; }
            let path = entry.path();
            let enc = fs::read(&path).map_err(|e| format!("读取 {} 失败：{}", path.display(), e))?;
            let plain = decrypt_binary(old_key, &enc)
                .map_err(|_| format!("媒体文件解密失败：{}", path.display()))?;
            let re = encrypt_binary(new_key, &plain)?;
            fs::write(&path, re).map_err(|e| format!("写回 {} 失败：{}", path.display(), e))?;
        }
    }
    Ok(())
}

/// 修改加密笔记的密码。
///
/// 需要原地重写该笔记的全部密文，中途失败会留下「一半新密钥一半旧密钥」的混合状态，
/// 两个密码都打不开全部内容。所以先把整个笔记目录复制一份，失败即整目录回滚。
#[tauri::command(async)]
fn change_note_password(state: State<AppState>, note_id: String, old_password: String, new_password: String) -> Result<bool, String> {
    validate_note_id(&note_id)?;
    if new_password.is_empty() { return Err("新密码不能为空".into()); }

    // 旧密码校验走既有解锁逻辑（含旧数据的兼容路径）
    if !unlock_note(state.clone(), note_id.clone(), old_password)? {
        return Ok(false);
    }
    let old_key = match lock_or_recover(&state.unlocked_keys).get(&note_id) {
        Some(k) => *k,
        None => return Err("笔记尚未解锁".into()),
    };

    let dir = safe_note_dir(&note_id)?;
    if !dir.exists() { return Err("笔记数据目录不存在".into()); }
    // 放在数据目录同级，保证与笔记目录同卷，回滚时的 rename 才是原子的
    let backup = data_root().join(format!(".rekey_bak_{}", note_id));
    if backup.exists() { fs::remove_dir_all(&backup).ok(); }
    copy_dir_recursive(&dir, &backup).map_err(|e| format!("创建安全备份失败，已中止：{}", e))?;

    let new_salt = SaltString::generate(&mut OsRng).to_string();
    let new_key = derive_key(&new_password, &new_salt)?;
    let new_token = encrypt_text(&new_key, VERIFY_PLAINTEXT)?;

    let rekeyed = rekey_note_contents(&note_id, &old_key, &new_key);
    if let Err(e) = rekeyed {
        // 回滚：整个目录换回备份，笔记保持旧密码可用
        fs::remove_dir_all(&dir).ok();
        if fs::rename(&backup, &dir).is_err() {
            let _ = copy_dir_recursive(&backup, &dir);
            fs::remove_dir_all(&backup).ok();
        }
        return Err(format!("{}\n\n已回滚到修改前的状态，原密码仍然有效。", e));
    }

    {
        let idx = lock_or_recover(&state.index_db);
        let (t, p): (String, String) = idx
            .query_row("SELECT COALESCE(title,''), COALESCE(preview,'') FROM notes WHERE id = ?1", params![note_id], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap_or_default();
        let title = encrypt_meta(Some(&new_key), &decrypt_meta(Some(&old_key), &t, "🔒 已加密笔记"));
        let preview = encrypt_meta(Some(&new_key), &decrypt_meta(Some(&old_key), &p, ""));
        idx.execute(
            "UPDATE notes SET encryption_salt = ?1, verify_token = ?2, title = ?3, preview = ?4 WHERE id = ?5",
            params![new_salt, new_token, title, preview, note_id],
        ).map_err(|e| e.to_string())?;
    }

    lock_or_recover(&state.unlocked_keys).insert(note_id.clone(), new_key);
    fs::remove_dir_all(&backup).ok();
    Ok(true)
}

/// 解除加密：把正文、历史、媒体、索引元数据全部还原成明文。
/// 此前只有 encrypt_note，加密一旦施加就无法撤销，密码也无从更换。
#[tauri::command(async)]
fn decrypt_note(state: State<AppState>, note_id: String, password: String) -> Result<bool, String> {
    validate_note_id(&note_id)?;
    if !unlock_note(state.clone(), note_id.clone(), password)? {
        return Ok(false);
    }
    let key = match lock_or_recover(&state.unlocked_keys).get(&note_id) {
        Some(k) => *k,
        None => return Err("笔记尚未解锁".into()),
    };

    let content_db = init_note_content_db(&note_id);
    if let Ok(enc) = content_db.query_row("SELECT delta_json FROM content WHERE id = 'current'", [], |row| row.get::<_, String>(0)) {
        if let Ok(plain) = decrypt_text(&key, &enc) {
            content_db.execute("UPDATE content SET delta_json = ?1 WHERE id = 'current'", params![plain]).ok();
        }
    }

    let timeline_db = init_note_timeline_db(&note_id);
    if let Ok(mut stmt) = timeline_db.prepare("SELECT id, delta_json FROM events") {
        let events: Vec<(String, String)> = match stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?))) {
            Ok(rows) => rows.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        };
        for (eid, enc) in events {
            if let Ok(plain) = decrypt_text(&key, &enc) {
                timeline_db.execute("UPDATE events SET delta_json = ?1 WHERE id = ?2", params![plain, eid]).ok();
            }
        }
    }

    let dir = safe_note_dir(&note_id)?;
    for sub in &["images", "videos", "audio", "files"] {
        if let Ok(entries) = std::fs::read_dir(dir.join(sub)) {
            for entry in entries.filter_map(Result::ok) {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    let path = entry.path();
                    if let Ok(enc) = std::fs::read(&path) {
                        if let Ok(plain) = decrypt_binary(&key, &enc) {
                            std::fs::write(&path, plain).ok();
                        }
                    }
                }
            }
        }
    }

    {
        let idx = lock_or_recover(&state.index_db);
        let (t, p): (String, String) = idx
            .query_row("SELECT COALESCE(title,''), COALESCE(preview,'') FROM notes WHERE id = ?1", params![note_id], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap_or_default();
        let plain_title = decrypt_meta(Some(&key), &t, "无标题");
        let plain_preview = decrypt_meta(Some(&key), &p, "");
        idx.execute(
            "UPDATE notes SET is_encrypted = 0, encryption_salt = NULL, verify_token = NULL, title = ?1, preview = ?2 WHERE id = ?3",
            params![plain_title, plain_preview, note_id],
        ).map_err(|e| e.to_string())?;
    }
    lock_or_recover(&state.unlocked_keys).remove(&note_id);
    Ok(true)
}

#[tauri::command(async)]
fn encrypt_note(state: State<AppState>, note_id: String, password: String) -> Result<(), String> {
    let idx = lock_or_recover(&state.index_db);
    let is_enc: i32 = idx.query_row("SELECT COALESCE(is_encrypted, 0) FROM notes WHERE id = ?1", params![note_id], |row| row.get(0)).unwrap_or(0);
    if is_enc == 1 { return Err("笔记已经被加密".into()); }
    
    let salt = SaltString::generate(&mut OsRng).to_string();
    let key = derive_key(&password, &salt)?;
    let verify_token = encrypt_text(&key, VERIFY_PLAINTEXT)?;

    // 标题和摘要（正文开头 100 字）一并加密：留在索引库里是明文的话，
    // 谁打开 notes_index.db 都能读到加密笔记写了什么，加密就形同虚设。
    let (title, preview): (String, String) = idx
        .query_row("SELECT COALESCE(title,''), COALESCE(preview,'') FROM notes WHERE id = ?1", params![note_id], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap_or_default();
    let enc_title = encrypt_meta(Some(&key), &title);
    let enc_preview = encrypt_meta(Some(&key), &preview);

    idx.execute(
        "UPDATE notes SET is_encrypted = 1, encryption_salt = ?1, verify_token = ?2, title = ?3, preview = ?4 WHERE id = ?5",
        params![salt, verify_token, enc_title, enc_preview, note_id.clone()],
    ).map_err(|e| e.to_string())?;
    drop(idx);
    
    lock_or_recover(&state.unlocked_keys).insert(note_id.clone(), key.clone());
    
    let content_db = init_note_content_db(&note_id);
    if let Ok(delta) = content_db.query_row("SELECT delta_json FROM content WHERE id = 'current'", [], |row| row.get::<_, String>(0)) {
        if let Ok(enc_delta) = encrypt_text(&key, &delta) {
            content_db.execute("UPDATE content SET delta_json = ?1 WHERE id = 'current'", params![enc_delta]).ok();
        }
    }
    
    let timeline_db = init_note_timeline_db(&note_id);
    let mut stmt = timeline_db.prepare("SELECT id, delta_json FROM events").unwrap();
    let events: Vec<(String, String)> = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap().filter_map(Result::ok).collect();
    for (eid, delta) in events {
        if let Ok(enc_delta) = encrypt_text(&key, &delta) {
            timeline_db.execute("UPDATE events SET delta_json = ?1 WHERE id = ?2", params![enc_delta, eid]).ok();
        }
    }
    
    // Encrypt all existing media files
    let dir = safe_note_dir(&note_id)?;
    for sub in &["images", "videos", "audio", "files"] {
        let sub_dir = dir.join(sub);
        if let Ok(entries) = std::fs::read_dir(sub_dir) {
            for entry in entries.filter_map(Result::ok) {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_file() {
                        let path = entry.path();
                        if let Ok(bytes) = std::fs::read(&path) {
                            if let Ok(enc_bytes) = encrypt_binary(&key, &bytes) {
                                std::fs::write(&path, enc_bytes).ok();
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(())
}


use tauri::Manager;
fn main() {
    // 已有实例在跑：不在这里弹原生对话框（风格对不上），而是照常启动，
    // 但先分配独立的 WebView2 数据目录——默认目录是独占锁，共用会在建窗口时失败。
    // 窗口起来后由前端用标准的圆角卡片弹窗询问：显示已开启的 / 开启新的 / 取消。
    // 外部显式设置了 WEBVIEW2_USER_DATA_FOLDER 说明是有意隔离（比如开发测试），不拦也不问。
    #[cfg(target_os = "windows")]
    let mut secondary_dir: Option<PathBuf> = None;
    #[cfg(target_os = "windows")]
    if std::env::var_os("WEBVIEW2_USER_DATA_FOLDER").is_none() {
        let first = acquire_single_instance();
        // 互斥量只能发现带它的新版；旧版实例要靠窗口标题 + 进程名兜底
        if !first || find_other_anchor_window().is_some() {
            OTHER_INSTANCE_RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);
            secondary_dir = setup_secondary_webview_dir();
        }
    }

    if let Some(note) = &data_root_choice().1 {
        show_startup_error(note);
    }

    let index_db = match init_index_db() {
        Ok(db) => db,
        Err(e) => { show_startup_error(&e); return; }
    };
    migrate_old_db_if_needed(&index_db);
    let jieba = Jieba::new();
    let run_result = tauri::Builder::default()
        .register_uri_scheme_protocol("anchor", move |app_handle, request| {
            let uri = request.uri();
            let path_str = uri
                .replace("anchor://localhost/", "")
                .replace("http://anchor.localhost/", "")
                .replace("https://anchor.localhost/", "");
            let decoded = percent_encoding::percent_decode_str(&path_str).decode_utf8_lossy().to_string();
            
            // 查询串不属于路径，必须剥掉，否则会被当成文件名的一部分
            let decoded = decoded.split(['?', '#']).next().unwrap_or("").to_string();
            let mut parts = decoded.splitn(2, '/');
            let note_id = parts.next().unwrap_or("");
            let rel_path = parts.next().unwrap_or("");

            let file_path = match safe_note_path(note_id, rel_path) {
                Ok(p) => p,
                Err(_) => {
                    return tauri::http::ResponseBuilder::new()
                        .status(403)
                        .mimetype("text/plain")
                        .body(Vec::new());
                }
            };
            if !file_path.is_file() {
                return tauri::http::ResponseBuilder::new()
                    .status(404)
                    .mimetype("text/plain")
                    .body(Vec::new());
            }
            let state = app_handle.state::<AppState>();
            let key_opt = get_note_key(&state, note_id).ok().flatten();

            let ext = file_path.extension().and_then(|s| s.to_str()).unwrap_or("");
            let mime_type = match ext.to_lowercase().as_str() {
                "png" => "image/png",
                "jpg" | "jpeg" => "image/jpeg",
                "gif" => "image/gif",
                "mp4" => "video/mp4",
                "mp3" => "audio/mpeg",
                "wav" => "audio/wav",
                "svg" => "image/svg+xml",
                "pdf" => "application/pdf",
                _ => "application/octet-stream",
            };

            let range_header = request.headers().get("range").and_then(|v| v.to_str().ok()).map(|s| s.to_string());

            let mut status = 200;
            let mut content_range = String::new();
            let body_bytes;

            if let Some(key) = key_opt {
                // AES-GCM 无法只解密一段，只能整体读入再切片
                let raw = std::fs::read(&file_path).unwrap_or_default();
                let bytes = decrypt_binary(&key, &raw).unwrap_or(raw);
                let total_len = bytes.len();
                match parse_range(range_header.as_deref(), total_len) {
                    Some((start, end)) => {
                        body_bytes = bytes[start..=end].to_vec();
                        status = 206;
                        content_range = format!("bytes {}-{}/{}", start, end, total_len);
                    }
                    None => body_bytes = bytes,
                }
            } else {
                // 未加密：只把请求的那一段读出来。以前每次拖动进度条都要重读整个文件，
                // 几百 MB 的视频会卡死。
                let total_len = std::fs::metadata(&file_path).map(|m| m.len() as usize).unwrap_or(0);
                match parse_range(range_header.as_deref(), total_len) {
                    Some((start, end)) => {
                        body_bytes = read_file_range(&file_path, start, end).unwrap_or_default();
                        status = 206;
                        content_range = format!("bytes {}-{}/{}", start, end, total_len);
                    }
                    None => body_bytes = std::fs::read(&file_path).unwrap_or_default(),
                }
            }

            let mut builder = tauri::http::ResponseBuilder::new()
                .mimetype(mime_type)
                .status(status)
                .header("Access-Control-Allow-Origin", "*")
                .header("Accept-Ranges", "bytes")
                .header("Content-Length", body_bytes.len().to_string());
                
            if status == 206 {
                builder = builder.header("Content-Range", content_range);
            }
            
            builder.body(body_bytes)
        })
        .manage(AppState { index_db: Mutex::new(index_db), jieba: Mutex::new(jieba), unlocked_keys: Mutex::new(HashMap::new()) })
        .invoke_handler(tauri::generate_handler![
            get_data_root, create_note, save_event, save_content, get_content,
            get_notes, get_archived_notes, archive_note, unarchive_note, delete_note,
            get_events, copy_media_to_note, save_media_base64,
            find_ffmpeg, check_video_needs_transcode, transcode_video,
            extract_audio_cover, set_audio_cover,
            export_note_backup, export_all_backup, export_selected_backup,
            import_scan, import_diff, import_apply, import_cancel, open_data_folder,
            png_stitch_begin, png_stitch_add, png_stitch_finish, png_stitch_abort, open_file_external, get_note_orphaned_files,
            delete_orphaned_file,
            get_folders, create_folder, set_note_folder, delete_folder, rename_folder,
            set_note_background, segment_text, get_semantic_cache, save_semantic_cache, get_total_notes_count,
            check_note_locked, unlock_note, lock_note, encrypt_note, decrypt_note, change_note_password,
            set_shutdown_block, startup_context, focus_other_instance, quit_app, toggle_vibrancy
        ])
        .setup(|app| {
            let window = app.get_window("main").unwrap();

            // 默认登记关机阻止原因，避免误触关机丢掉未保存内容；
            // 前端可以随时用 set_shutdown_block 关掉。
            #[cfg(target_os = "windows")]
            {
                use windows::Win32::Foundation::HWND;
                use windows::Win32::System::Shutdown::ShutdownBlockReasonCreate;
                use windows::core::PCWSTR;
                if let Ok(h) = window.hwnd() {
                    let text = to_wide("锚点正在运行，关机可能丢失尚未保存的笔记内容");
                    unsafe { ShutdownBlockReasonCreate(HWND(h.0), PCWSTR(text.as_ptr())); }
                }
            }

            // Windows WebView2: 自动授予麦克风权限，防止用户误拒后永久无法使用
            #[cfg(target_os = "windows")]
            window.with_webview(|webview| {
                unsafe {
                    use webview2_com::Microsoft::Web::WebView2::Win32::*;
                    use windows::Win32::System::WinRT::EventRegistrationToken;
                    let core = webview.controller().CoreWebView2().unwrap();
                    let mut token = EventRegistrationToken::default();
                    core.add_PermissionRequested(
                        &webview2_com::PermissionRequestedEventHandler::create(
                            Box::new(|_sender, args| {
                                if let Some(args) = args {
                                    let mut kind = COREWEBVIEW2_PERMISSION_KIND_UNKNOWN_PERMISSION;
                                    args.PermissionKind(&mut kind)?;
                                    if kind == COREWEBVIEW2_PERMISSION_KIND_MICROPHONE {
                                        args.SetState(COREWEBVIEW2_PERMISSION_STATE_ALLOW)?;
                                    }
                                }
                                Ok(())
                            }),
                        ),
                        &mut token,
                    ).ok();
                }
            }).ok();
            Ok(())
        })
        .run(tauri::generate_context!());

    #[cfg(target_os = "windows")]
    if let Some(dir) = &secondary_dir {
        // WebView2 子进程可能还在收尾，清不掉就留着，不影响下次
        let _ = fs::remove_dir_all(dir);
    }

    if let Err(e) = run_result {
        show_startup_error(&format!(
            "窗口创建失败：\n{}\n\n常见原因：已有一个锚点实例在运行（可能被最小化），或 WebView2 运行时异常。",
            e
        ));
    }
}
