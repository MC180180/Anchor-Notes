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

fn data_root() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("data")
}

fn note_dir(note_id: &str) -> PathBuf {
    data_root().join(note_id)
}

fn derive_key(password: &str, salt: &str) -> [u8; 32] {
    let parsed_salt = SaltString::from_b64(salt).unwrap_or_else(|_| SaltString::generate(&mut OsRng));
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    let _ = argon2.hash_password_into(password.as_bytes(), parsed_salt.as_str().as_bytes(), &mut key);
    key
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
    let idx = state.index_db.lock().unwrap();
    let is_enc: i32 = idx.query_row("SELECT COALESCE(is_encrypted, 0) FROM notes WHERE id = ?1", params![note_id], |row| row.get(0)).unwrap_or(0);
    if is_enc == 0 { return Ok(None); }
    let keys = state.unlocked_keys.lock().unwrap();
    if let Some(key) = keys.get(note_id) {
        Ok(Some(*key))
    } else {
        Err("该笔记已被加密且尚未解锁，无法访问内容".into())
    }
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

fn init_index_db() -> Connection {
    let root = data_root();
    fs::create_dir_all(&root).expect("无法创建 data 目录");
    let db = Connection::open(root.join("notes_index.db")).expect("无法打开索引数据库");
    db.execute(
        "CREATE TABLE IF NOT EXISTS notes (
            id TEXT PRIMARY KEY, created_at INTEGER, updated_at INTEGER, title TEXT, preview TEXT
        )", [],
    ).unwrap();
    db.execute("ALTER TABLE notes ADD COLUMN is_archived INTEGER DEFAULT 0", []).ok();
    db.execute("ALTER TABLE notes ADD COLUMN folder_id TEXT", []).ok();
    db.execute("ALTER TABLE notes ADD COLUMN background TEXT DEFAULT 'default'", []).ok();
    db.execute("ALTER TABLE notes ADD COLUMN is_encrypted INTEGER DEFAULT 0", []).ok();
    db.execute("ALTER TABLE notes ADD COLUMN encryption_salt TEXT", []).ok();
    db.execute(
        "CREATE TABLE IF NOT EXISTS folders (
            id TEXT PRIMARY KEY, name TEXT, created_at INTEGER
        )", [],
    ).unwrap();
    db
}

fn init_note_content_db(note_id: &str) -> Connection {
    let db = Connection::open(note_dir(note_id).join("content.db")).expect("无法打开 content.db");
    db.execute(
        "CREATE TABLE IF NOT EXISTS content (
            id TEXT PRIMARY KEY DEFAULT 'current', delta_json TEXT, updated_at INTEGER
        )", [],
    ).unwrap();
    db
}

fn init_note_timeline_db(note_id: &str) -> Connection {
    let db = Connection::open(note_dir(note_id).join("timeline.db")).expect("无法打开 timeline.db");
    db.execute(
        "CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, timestamp INTEGER, operation_type TEXT, delta_json TEXT
        )", [],
    ).unwrap();
    db
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
    let old_notes: Vec<(String, i64, i64, String, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
        .unwrap().filter_map(|r| r.ok()).collect();

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
        let mut ev_stmt = old_db.prepare(
            "SELECT id, timestamp, operation_type, delta_json FROM note_events WHERE note_id = ?1 ORDER BY timestamp ASC"
        ).unwrap();
        let events: Vec<(String, i64, String, String)> = ev_stmt
            .query_map(params![id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .unwrap().filter_map(|r| r.ok()).collect();
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

#[tauri::command]
fn get_data_root() -> String {
    data_root().to_string_lossy().to_string()
}

#[tauri::command]
fn create_note(state: State<AppState>) -> Result<String, String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp_millis();
    ensure_note_dirs(&id);
    init_note_content_db(&id);
    init_note_timeline_db(&id);
    let db = state.index_db.lock().unwrap();
    db.execute(
        "INSERT INTO notes (id, created_at, updated_at, title, preview) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, now, now, "新笔记", "开始编写内容..."],
    ).map_err(|e| e.to_string())?;
    Ok(id)
}

#[tauri::command]
fn save_event(state: State<AppState>, note_id: String, operation_type: String, mut delta_json: String, title: String, preview: String) -> Result<(), String> {
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
    let idx = state.index_db.lock().unwrap();
    idx.execute(
        "UPDATE notes SET updated_at = ?1, title = ?2, preview = ?3 WHERE id = ?4",
        params![now, title, preview, note_id],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn save_content(state: State<AppState>, note_id: String, mut delta_json: String) -> Result<(), String> {
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

#[tauri::command]
fn get_content(state: State<AppState>, note_id: String) -> Result<String, String> {
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

#[tauri::command]
fn get_notes(state: State<AppState>) -> Result<Vec<Note>, String> {
    let db = state.index_db.lock().unwrap();
    let keys = state.unlocked_keys.lock().unwrap();
    let mut stmt = db.prepare("SELECT id, created_at, updated_at, title, preview, folder_id, COALESCE(background, 'default'), COALESCE(is_encrypted, 0) FROM notes WHERE is_archived = 0 ORDER BY updated_at DESC").unwrap();
    let notes = stmt.query_map([], |row| {
        let id: String = row.get(0)?;
        let is_enc: i32 = row.get(7)?;
        let is_unlocked = if is_enc == 1 { keys.contains_key(&id) } else { true };
        Ok(Note { id, created_at: row.get(1)?, updated_at: row.get(2)?, title: row.get(3)?, preview: row.get(4)?, folder_id: row.get(5).ok(), background: row.get(6)?, is_encrypted: is_enc == 1, is_unlocked })
    }).map_err(|e| e.to_string())?.filter_map(Result::ok).collect();
    Ok(notes)
}

#[tauri::command]
fn get_archived_notes(state: State<AppState>) -> Result<Vec<Note>, String> {
    let db = state.index_db.lock().unwrap();
    let keys = state.unlocked_keys.lock().unwrap();
    let mut stmt = db.prepare("SELECT id, created_at, updated_at, title, preview, folder_id, COALESCE(background, 'default'), COALESCE(is_encrypted, 0) FROM notes WHERE is_archived = 1 ORDER BY updated_at DESC").unwrap();
    let notes = stmt.query_map([], |row| {
        let id: String = row.get(0)?;
        let is_enc: i32 = row.get(7)?;
        let is_unlocked = if is_enc == 1 { keys.contains_key(&id) } else { true };
        Ok(Note { id, created_at: row.get(1)?, updated_at: row.get(2)?, title: row.get(3)?, preview: row.get(4)?, folder_id: row.get(5).ok(), background: row.get(6)?, is_encrypted: is_enc == 1, is_unlocked })
    }).map_err(|e| e.to_string())?.filter_map(Result::ok).collect();
    Ok(notes)
}

#[tauri::command]
fn get_total_notes_count(state: State<AppState>) -> Result<i64, String> {
    let db = state.index_db.lock().unwrap();
    let count: i64 = db.query_row("SELECT COUNT(*) FROM notes", [], |row| row.get(0)).unwrap_or(0);
    Ok(count)
}

#[tauri::command]
fn archive_note(state: State<AppState>, note_id: String) -> Result<(), String> {
    let db = state.index_db.lock().unwrap();
    db.execute("UPDATE notes SET is_archived = 1 WHERE id = ?1", params![note_id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn unarchive_note(state: State<AppState>, note_id: String) -> Result<(), String> {
    let db = state.index_db.lock().unwrap();
    db.execute("UPDATE notes SET is_archived = 0 WHERE id = ?1", params![note_id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn set_note_background(state: State<AppState>, note_id: String, background: String) -> Result<(), String> {
    let db = state.index_db.lock().unwrap();
    db.execute("UPDATE notes SET background = ?1 WHERE id = ?2", params![background, note_id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn delete_note(state: State<AppState>, note_id: String) -> Result<(), String> {
    let db = state.index_db.lock().unwrap();
    db.execute("DELETE FROM notes WHERE id = ?1", params![&note_id]).map_err(|e| e.to_string())?;
    let dir = note_dir(&note_id);
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn get_events(state: State<AppState>, note_id: String) -> Result<Vec<NoteEvent>, String> {
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

fn compute_file_hash(bytes: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("{:016x}_{}", hasher.finish(), bytes.len())
}

/// 从本地文件路径复制媒体到笔记数据目录，返回相对路径
#[tauri::command]
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
    let dir = note_dir(&note_id).join(sub);
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
#[tauri::command]
fn find_ffmpeg() -> Result<String, String> {
    // 1. 检查程序同目录
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()));
    if let Some(dir) = &exe_dir {
        let local = dir.join("ffmpeg.exe");
        if local.exists() { return Ok(local.to_string_lossy().to_string()); }
    }
    // 2. 检查工作目录
    let cwd_ffmpeg = std::env::current_dir().unwrap_or_default().join("ffmpeg.exe");
    if cwd_ffmpeg.exists() { return Ok(cwd_ffmpeg.to_string_lossy().to_string()); }
    // 3. 检查 PATH
    if let Ok(output) = std::process::Command::new("where.exe").arg("ffmpeg").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().lines().next().unwrap_or("").to_string();
            if !path.is_empty() { return Ok(path); }
        }
    }
    Err("未找到 ffmpeg。请将 ffmpeg.exe 放到程序同目录，或添加到系统 PATH 中。".into())
}

/// 检查视频文件是否需要转码（非 mp4/webm 格式需要转码）
#[tauri::command]
fn check_video_needs_transcode(source_path: String) -> bool {
    let ext = Path::new(&source_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    !matches!(ext.as_str(), "mp4" | "webm")
}

/// 使用 ffmpeg 将视频转码为 MP4 (H.264 + AAC)，返回临时文件路径
#[tauri::command]
fn transcode_video(ffmpeg_path: String, source_path: String) -> Result<String, String> {
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
#[tauri::command]
fn extract_audio_cover(state: State<AppState>, note_id: String, rel_path: String) -> Result<Option<String>, String> {
    let file_path = note_dir(&note_id).join(&rel_path);
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
#[tauri::command]
fn set_audio_cover(state: State<AppState>, note_id: String, audio_rel_path: String, cover_source_path: String) -> Result<String, String> {
    let audio_path = note_dir(&note_id).join(&audio_rel_path);
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
#[tauri::command]
fn save_media_base64(state: State<AppState>, note_id: String, media_type: String, file_name: String, base64_data: String) -> Result<serde_json::Value, String> {
    let raw = if let Some(pos) = base64_data.find(',') { &base64_data[pos + 1..] } else { &base64_data };
    let mut bytes = STANDARD.decode(raw).map_err(|e| e.to_string())?;
    
    let ext = Path::new(&file_name).extension().and_then(|e| e.to_str()).unwrap_or("bin");
    let hash_name = format!("{}.{}", compute_file_hash(&bytes), ext);
    
    if let Ok(Some(key)) = get_note_key(&state, &note_id) {
        bytes = encrypt_binary(&key, &bytes)?;
    }
    
    let sub = match media_type.as_str() { "image" => "images", "video" => "videos", "audio" => "audio", _ => "files" };
    let dir = note_dir(&note_id).join(sub);
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

#[tauri::command]
fn get_note_orphaned_files(note_id: String) -> Result<Vec<OrphanedFile>, String> {
    let mut orphaned = Vec::new();
    let dir = note_dir(&note_id);
    if !dir.exists() { return Ok(orphaned); }
    
    let mut referenced_paths = std::collections::HashSet::new();
    
    // Check current content
    let content_db = init_note_content_db(&note_id);
    if let Ok(json_str) = content_db.query_row::<String, _, _>("SELECT delta_json FROM content WHERE id = 'current'", [], |row| row.get(0)) {
        extract_media_paths(&json_str, &mut referenced_paths);
    }
    
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

#[tauri::command]
fn export_note_backup(note_id: String, save_path: String) -> Result<String, String> {
    let dir = note_dir(&note_id);
    if !dir.exists() { return Err("笔记数据目录不存在".to_string()); }
    let file = fs::File::create(&save_path).map_err(|e| e.to_string())?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar_builder = tar::Builder::new(enc);
    tar_builder.append_dir_all(&note_id, &dir).map_err(|e| e.to_string())?;
    tar_builder.finish().map_err(|e| e.to_string())?;
    Ok(save_path)
}

#[tauri::command]
fn export_all_backup(save_path: String) -> Result<String, String> {
    let dir = data_root();
    if !dir.exists() { return Err("数据目录不存在".to_string()); }
    let file = fs::File::create(&save_path).map_err(|e| e.to_string())?;
    let mut tar_builder = tar::Builder::new(file);
    tar_builder.append_dir_all("anchor_notes_data", &dir).map_err(|e| e.to_string())?;
    tar_builder.finish().map_err(|e| e.to_string())?;
    Ok(save_path)
}

#[tauri::command]
fn open_data_folder(note_id: String) -> Result<(), String> {
    let dir = note_dir(&note_id);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    { std::process::Command::new("explorer").arg(dir.to_str().unwrap_or(".")).spawn().map_err(|e| e.to_string())?; }
    Ok(())
}

#[tauri::command]
fn open_file_external(state: State<AppState>, note_id: String, rel_path: String) -> Result<(), String> {
    let dir = note_dir(&note_id);
    let path = dir.join(&rel_path);
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
    
    #[cfg(target_os = "windows")]
    { std::process::Command::new("cmd").args(["/C", "start", "", tmp_path.to_str().unwrap_or(".")]).spawn().map_err(|e| e.to_string())?; }
    Ok(())
}

#[tauri::command]
fn delete_orphaned_file(path: String) -> Result<(), String> {
    let p = Path::new(&path);
    if p.exists() {
        fs::remove_file(p).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn get_folders(state: State<AppState>) -> Result<Vec<Folder>, String> {
    let db = state.index_db.lock().unwrap();
    let mut stmt = db.prepare("SELECT id, name, created_at FROM folders ORDER BY created_at ASC").unwrap();
    let folders = stmt.query_map([], |row| {
        Ok(Folder { id: row.get(0)?, name: row.get(1)?, created_at: row.get(2)? })
    }).map_err(|e| e.to_string())?.filter_map(Result::ok).collect();
    Ok(folders)
}

#[tauri::command]
fn create_folder(state: State<AppState>, name: String) -> Result<String, String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp_millis();
    let db = state.index_db.lock().unwrap();
    db.execute(
        "INSERT INTO folders (id, name, created_at) VALUES (?1, ?2, ?3)",
        params![id, name, now],
    ).map_err(|e| e.to_string())?;
    Ok(id)
}

#[tauri::command]
fn set_note_folder(state: State<AppState>, note_id: String, folder_id: Option<String>) -> Result<(), String> {
    let db = state.index_db.lock().unwrap();
    db.execute(
        "UPDATE notes SET folder_id = ?1 WHERE id = ?2",
        params![folder_id, note_id],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn delete_folder(state: State<AppState>, folder_id: String) -> Result<(), String> {
    let db = state.index_db.lock().unwrap();
    db.execute("UPDATE notes SET folder_id = NULL WHERE folder_id = ?1", params![folder_id]).map_err(|e| e.to_string())?;
    db.execute("DELETE FROM folders WHERE id = ?1", params![folder_id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn rename_folder(state: State<AppState>, folder_id: String, new_name: String) -> Result<(), String> {
    let db = state.index_db.lock().unwrap();
    db.execute("UPDATE folders SET name = ?1 WHERE id = ?2", params![new_name, folder_id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Serialize)]
struct TaggedWord {
    word: String,
    tag: String,
}

#[tauri::command]
fn segment_text(state: State<AppState>, text: String) -> Vec<TaggedWord> {
    let jieba = state.jieba.lock().unwrap();
    let tagged = jieba.tag(&text, true);
    tagged.into_iter().map(|t| TaggedWord {
        word: t.word.to_string(),
        tag: t.tag.to_string(),
    }).collect()
}

#[tauri::command]
fn get_semantic_cache(state: State<AppState>, note_id: String) -> Result<Option<String>, String> {
    let key_opt = get_note_key(&state, &note_id)?;
    let dir = note_dir(&note_id);
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

#[tauri::command]
fn save_semantic_cache(state: State<AppState>, note_id: String, mut tags_json: String) -> Result<(), String> {
    let key_opt = get_note_key(&state, &note_id)?;
    if let Some(key) = key_opt {
        tags_json = encrypt_text(&key, &tags_json)?;
    }
    let dir = note_dir(&note_id);
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

#[tauri::command]
fn check_note_locked(state: State<AppState>, note_id: String) -> Result<bool, String> {
    let idx = state.index_db.lock().unwrap();
    let is_enc: i32 = idx.query_row("SELECT COALESCE(is_encrypted, 0) FROM notes WHERE id = ?1", params![note_id], |row| row.get(0)).unwrap_or(0);
    if is_enc == 0 { return Ok(false); }
    let keys = state.unlocked_keys.lock().unwrap();
    Ok(!keys.contains_key(&note_id))
}

#[tauri::command]
fn unlock_note(state: State<AppState>, note_id: String, password: String) -> Result<bool, String> {
    let idx = state.index_db.lock().unwrap();
    let (is_enc, salt): (i32, Option<String>) = idx.query_row("SELECT COALESCE(is_encrypted, 0), encryption_salt FROM notes WHERE id = ?1", params![note_id], |row| Ok((row.get(0)?, row.get(1)?))).map_err(|e| e.to_string())?;
    
    if is_enc == 0 { return Ok(true); }
    let salt = salt.ok_or_else(|| "Salt not found".to_string())?;
    let key = derive_key(&password, &salt);
    
    let content_db = init_note_content_db(&note_id);
    let mut is_correct = false;
    if let Ok(json) = content_db.query_row("SELECT delta_json FROM content WHERE id = 'current'", [], |row| row.get::<_, String>(0)) {
        if decrypt_text(&key, &json).is_ok() { is_correct = true; }
    } else {
        is_correct = true;
    }
    
    if is_correct {
        state.unlocked_keys.lock().unwrap().insert(note_id, key);
        Ok(true)
    } else {
        Ok(false)
    }
}

#[tauri::command]
fn lock_note(state: State<AppState>, note_id: String) -> Result<(), String> {
    state.unlocked_keys.lock().unwrap().remove(&note_id);
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

#[tauri::command]
fn encrypt_note(state: State<AppState>, note_id: String, password: String) -> Result<(), String> {
    let idx = state.index_db.lock().unwrap();
    let is_enc: i32 = idx.query_row("SELECT COALESCE(is_encrypted, 0) FROM notes WHERE id = ?1", params![note_id], |row| row.get(0)).unwrap_or(0);
    if is_enc == 1 { return Err("笔记已经被加密".into()); }
    
    let salt = SaltString::generate(&mut OsRng).to_string();
    let key = derive_key(&password, &salt);
    
    idx.execute("UPDATE notes SET is_encrypted = 1, encryption_salt = ?1 WHERE id = ?2", params![salt, note_id.clone()]).map_err(|e| e.to_string())?;
    drop(idx);
    
    state.unlocked_keys.lock().unwrap().insert(note_id.clone(), key.clone());
    
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
    let dir = note_dir(&note_id);
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

    let index_db = init_index_db();
    migrate_old_db_if_needed(&index_db);
    let jieba = Jieba::new();
    tauri::Builder::default()
        .register_uri_scheme_protocol("anchor", move |app_handle, request| {
            let uri = request.uri();
            let path_str = uri
                .replace("anchor://localhost/", "")
                .replace("http://anchor.localhost/", "")
                .replace("https://anchor.localhost/", "");
            let decoded = percent_encoding::percent_decode_str(&path_str).decode_utf8_lossy().to_string();
            
            let mut parts = decoded.splitn(2, '/');
            let note_id = parts.next().unwrap_or("");
            let rel_path = parts.next().unwrap_or("");
            
            let file_path = note_dir(note_id).join(rel_path);
            let mut bytes = std::fs::read(&file_path).unwrap_or_default();
            
            let state = app_handle.state::<AppState>();
            if let Ok(Some(key)) = get_note_key(&state, note_id) {
                if let Ok(dec) = decrypt_binary(&key, &bytes) {
                    bytes = dec;
                }
            }
            
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

            let total_len = bytes.len();
            let mut status = 200;
            let mut body_bytes = bytes;
            let mut content_range = String::new();
            
            if let Some(range_val) = request.headers().get("range").and_then(|v| v.to_str().ok()) {
                if range_val.starts_with("bytes=") {
                    let range = &range_val[6..];
                    let mut parts = range.split('-');
                    let start_str = parts.next().unwrap_or("");
                    let end_str = parts.next().unwrap_or("");
                    
                    if let Ok(start) = start_str.parse::<usize>() {
                        let end = if end_str.is_empty() {
                            total_len.saturating_sub(1)
                        } else {
                            end_str.parse::<usize>().unwrap_or(total_len.saturating_sub(1))
                        };
                        
                        let end = std::cmp::min(end, total_len.saturating_sub(1));
                        if start <= end && start < total_len {
                            body_bytes = body_bytes[start..=end].to_vec();
                            status = 206;
                            content_range = format!("bytes {}-{}/{}", start, end, total_len);
                        }
                    }
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
            export_note_backup, export_all_backup, open_data_folder, open_file_external, get_note_orphaned_files,
            delete_orphaned_file,
            get_folders, create_folder, set_note_folder, delete_folder, rename_folder,
            set_note_background, segment_text, get_semantic_cache, save_semantic_cache, get_total_notes_count,
            check_note_locked, unlock_note, lock_note, encrypt_note, toggle_vibrancy
        ])
        .setup(|app| {
            let window = app.get_window("main").unwrap();
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
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
