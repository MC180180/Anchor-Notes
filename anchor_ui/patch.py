import re
import sys

with open('src/main.rs.bak', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Imports
imports = '''
use std::collections::HashMap;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::{Argon2, PasswordHasher, password_hash::{rand_core::OsRng, SaltString}};
use rand::RngCore;
'''
text = re.sub(r'use std::sync::Mutex;', 'use std::sync::Mutex;\n' + imports.strip(), text)

# 2. Crypto utils
crypto_utils = '''
fn derive_key(password: &str, salt: &str) -> [u8; 32] {
    let parsed_salt = SaltString::new(salt).unwrap_or_else(|_| SaltString::generate(&mut OsRng));
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), parsed_salt.as_bytes(), &mut key).unwrap();
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

fn get_note_key(state: &State<AppState>, note_id: &str) -> Result<Option<[u8; 32]>, String> {
    let idx = state.index_db.lock().unwrap();
    let is_enc: i32 = idx.query_row("SELECT COALESCE(is_encrypted, 0) FROM notes WHERE id = ?1", params![note_id], |row| row.get(0)).unwrap_or(0);
    if is_enc == 0 {
        return Ok(None);
    }
    let keys = state.unlocked_keys.lock().unwrap();
    if let Some(key) = keys.get(note_id) {
        Ok(Some(*key))
    } else {
        Err("该笔记已被加密且尚未解锁，无法访问内容".into())
    }
}
'''
text = re.sub(r'(fn get_data_root)', crypto_utils.strip() + r'\n\n\1', text)

# 3. AppState
text = re.sub(
    r'struct AppState \{\s*index_db: Mutex<Connection>,\s*jieba: Mutex<Jieba>,\s*\}',
    'struct AppState {\\n    index_db: Mutex<Connection>,\\n    jieba: Mutex<Jieba>,\\n    unlocked_keys: Mutex<HashMap<String, [u8; 32]>>,\\n}',
    text
)

# 4. init_index_db
text = re.sub(
    r'(db\.execute\(\"ALTER TABLE notes ADD COLUMN background TEXT DEFAULT \'default\'\", \[\]\)\.ok\(\);)',
    r'\1\n    db.execute("ALTER TABLE notes ADD COLUMN is_encrypted INTEGER DEFAULT 0", []).ok();\n    db.execute("ALTER TABLE notes ADD COLUMN encryption_salt TEXT", []).ok();',
    text
)

# 5. Note Struct
text = re.sub(
    r'background: String,\s*\}',
    'background: String,\n    is_encrypted: bool,\n}',
    text
)

# 6. get_notes & get_archived_notes
text = re.sub(
    r"SELECT id, created_at, updated_at, title, preview, folder_id, COALESCE\(background, 'default'\) FROM notes",
    "SELECT id, created_at, updated_at, title, preview, folder_id, COALESCE(background, 'default'), COALESCE(is_encrypted, 0) FROM notes",
    text
)
text = re.sub(
    r'background: row\.get\(6\)\? \}\)',
    'background: row.get(6)?, is_encrypted: row.get::<_, i32>(7)? == 1 })',
    text
)

# 7. Tauri AppState init
text = re.sub(
    r'AppState \{ index_db: Mutex::new\(index_db\), jieba: Mutex::new\(jieba\) \}',
    'AppState { index_db: Mutex::new(index_db), jieba: Mutex::new(jieba), unlocked_keys: Mutex::new(HashMap::new()) }',
    text
)

# 8. save_content
text = re.sub(
    r'fn save_content\(note_id: String, delta_json: String\) -> Result<\(\), String> \{',
    '''fn save_content(state: State<AppState>, note_id: String, mut delta_json: String) -> Result<(), String> {
    let key_opt = get_note_key(&state, &note_id)?;
    if let Some(key) = key_opt {
        delta_json = encrypt_text(&key, &delta_json)?;
    }''',
    text
)

# 9. get_content
text = re.sub(
    r'fn get_content\(note_id: String\) -> Result<String, String> \{[\s\S]*?Ok\(json\) => Ok\(json\),[\s\S]*?Err\(_\) => Ok\(String::new\(\)\),[\s\S]*?\}[\s\S]*?\}',
    '''fn get_content(state: State<AppState>, note_id: String) -> Result<String, String> {
    let key_opt = get_note_key(&state, &note_id)?;
    let content_db = init_note_content_db(&note_id);
    let mut json = match content_db.query_row("SELECT delta_json FROM content WHERE id = 'current'", [], |row| row.get::<_, String>(0)) {
        Ok(j) => j,
        Err(_) => return Ok(String::new()),
    };
    if let Some(key) = key_opt {
        json = decrypt_text(&key, &json)?;
    }
    Ok(json)
}''',
    text
)

# 10. save_event
text = re.sub(
    r'fn save_event\(state: State<AppState>, note_id: String, operation_type: String, delta_json: String',
    'fn save_event(state: State<AppState>, note_id: String, operation_type: String, mut delta_json: String',
    text
)
text = re.sub(
    r'(let event_id = Uuid::new_v4\(\)\.to_string\(\);)',
    r'let key_opt = get_note_key(&state, &note_id)?;\n    if let Some(key) = key_opt {\n        delta_json = encrypt_text(&key, &delta_json)?;\n    }\n    \1',
    text
)

# 11. get_events
text = re.sub(
    r'fn get_events\(note_id: String\)',
    'fn get_events(state: State<AppState>, note_id: String)',
    text
)
text = re.sub(
    r'let timeline_db = init_note_timeline_db\(&note_id\);',
    'let key_opt = get_note_key(&state, &note_id)?;\n    let timeline_db = init_note_timeline_db(&note_id);',
    text
)
text = re.sub(
    r'Ok\(NoteEvent \{ id: row\.get\(0\)\?, note_id: nid\.clone\(\), timestamp: row\.get\(1\)\?, operation_type: row\.get\(2\)\?, delta_json: row\.get\(3\)\? \}\)',
    '''let mut delta: String = row.get(3)?;
        if let Some(key) = key_opt {
            if let Ok(dec) = decrypt_text(&key, &delta) { delta = dec; } else { delta = "{}".to_string(); }
        }
        Ok(NoteEvent { id: row.get(0)?, note_id: nid.clone(), timestamp: row.get(1)?, operation_type: row.get(2)?, delta_json: delta })''',
    text
)

# 12. new crypto commands
crypto_commands = '''
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
fn encrypt_note(state: State<AppState>, note_id: String, password: String) -> Result<(), String> {
    let idx = state.index_db.lock().unwrap();
    let is_enc: i32 = idx.query_row("SELECT COALESCE(is_encrypted, 0) FROM notes WHERE id = ?1", params![note_id], |row| row.get(0)).unwrap_or(0);
    if is_enc == 1 { return Err("笔记已经被加密".into()); }
    
    let salt = SaltString::generate(&mut OsRng).to_string();
    let key = derive_key(&password, &salt);
    
    idx.execute("UPDATE notes SET is_encrypted = 1, encryption_salt = ?1 WHERE id = ?2", params![salt, note_id]).map_err(|e| e.to_string())?;
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
    Ok(())
}
'''
text = re.sub(r'(fn segment_text)', crypto_commands.strip() + r'\n\n\1', text)

# 13. Update generate_handler!
text = re.sub(
    r'get_total_notes_count',
    'get_total_notes_count, check_note_locked, unlock_note, lock_note, encrypt_note',
    text
)

# 14. Fix semantic cache
text = re.sub(
    r'fn get_semantic_cache\(note_id: String\)',
    'fn get_semantic_cache(state: State<AppState>, note_id: String)',
    text
)
text = re.sub(
    r'(let db = Connection::open\(dir\.join\(\"content\.db\"\)\)\.map_err\(\|e\| e\.to_string\(\)\)\?;)',
    r'let key_opt = get_note_key(&state, &note_id)?;\n    \1',
    text
)
text = re.sub(
    r'Ok\(json\) => Ok\(Some\(json\)\)',
    '''Ok(mut json) => {
            if let Some(key) = key_opt {
                if let Ok(dec) = decrypt_text(&key, &json) { json = dec; } else { return Ok(None); }
            }
            Ok(Some(json))
        }''',
    text
)

text = re.sub(
    r'fn save_semantic_cache\(note_id: String, tags_json: String\)',
    'fn save_semantic_cache(state: State<AppState>, note_id: String, mut tags_json: String)',
    text
)
text = re.sub(
    r'(let dir = note_dir\(&note_id\);)',
    r'let key_opt = get_note_key(&state, &note_id)?;\n    if let Some(key) = key_opt {\n        tags_json = encrypt_text(&key, &tags_json)?;\n    }\n    \1',
    text
)

with open('src/main.rs', 'w', encoding='utf-8') as f:
    f.write(text)

print('Updated src/main.rs')
