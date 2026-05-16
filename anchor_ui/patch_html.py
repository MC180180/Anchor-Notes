import re
import sys

with open('frontend/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

# Add encrypt buttons to right-controls
text = re.sub(
    r'(<div class="tl-btn" id="archive-note-btn")',
    r'<div class="tl-btn" id="encrypt-note-btn" title="为当前笔记加密">加密</div>\n      <div class="tl-btn" id="lock-status-btn" style="display:none; color:#4caf50;" title="已解锁，退出时自动重新上锁">🔓 已解锁</div>\n      \1',
    text
)

# Rename openNote to doOpenNote and inject wrapper
wrapper = '''
function openNote(id, background) {
    invoke('check_note_locked', { noteId: id }).then(function(locked) {
        if (locked) {
            customDialog({
                title: '解锁笔记',
                message: '此笔记已被加密，请输入密码解锁：',
                isInput: true,
                isPassword: true
            }).then(function(pwd) {
                if (!pwd) return;
                invoke('unlock_note', { noteId: id, password: pwd }).then(function(success) {
                    if (success) {
                        doOpenNote(id, background, true);
                    } else {
                        customDialog({ title: '错误', message: '密码错误，无法解锁！' });
                    }
                }).catch(function(e) {
                    customDialog({ title: '错误', message: '解锁失败: ' + e });
                });
            });
        } else {
            // Check if it's actually encrypted but already unlocked
            var isEncrypted = false;
            var note = allNotesCache.find(function(n) { return n.id === id; });
            if (note && note.is_encrypted) isEncrypted = true;
            doOpenNote(id, background, isEncrypted);
        }
    }).catch(function(e) {
        doOpenNote(id, background, false);
    });
}

function doOpenNote(id, background, isEncrypted) {
    var encBtn = document.getElementById('encrypt-note-btn');
    var lockBtn = document.getElementById('lock-status-btn');
    if (encBtn && lockBtn) {
        if (isEncrypted) {
            encBtn.style.display = 'none';
            lockBtn.style.display = 'block';
        } else {
            encBtn.style.display = 'block';
            lockBtn.style.display = 'none';
        }
    }
'''

text = re.sub(
    r'function openNote\(id, background\) \{',
    wrapper.strip(),
    text
)

# Also we need to close the note gracefully and lock it
# Search for back-btn event listener
close_wrapper = '''
document.getElementById('back-btn').addEventListener('click', function() {
    if (currentNoteId) {
        var nid = currentNoteId;
        // Check if note is encrypted
        var note = allNotesCache.find(function(n) { return n.id === nid; });
        if (note && note.is_encrypted) {
            invoke('lock_note', { noteId: nid });
        }
    }
'''
text = re.sub(
    r'document\.getElementById\(\'back-btn\'\)\.addEventListener\(\'click\', function\(\) \{',
    close_wrapper.strip(),
    text
)

# And add the event listener for encrypt button!
# Can be placed at the end of DOMContentLoaded or somewhere
encrypt_event = '''
document.getElementById('encrypt-note-btn').addEventListener('click', function() {
    customDialog({
        title: '加密笔记',
        message: '请输入您要设置的密码。注意：密码丢失将无法恢复数据！',
        isInput: true,
        isPassword: true
    }).then(function(pwd) {
        if (!pwd) return;
        customDialog({
            title: '确认密码',
            message: '请再次输入密码以确认：',
            isInput: true,
            isPassword: true
        }).then(function(pwd2) {
            if (!pwd2) return;
            if (pwd !== pwd2) {
                customDialog({ title: '错误', message: '两次密码不一致！' });
                return;
            }
            invoke('encrypt_note', { noteId: currentNoteId, password: pwd }).then(function() {
                customDialog({ title: '成功', message: '笔记已加密！' });
                var encBtn = document.getElementById('encrypt-note-btn');
                var lockBtn = document.getElementById('lock-status-btn');
                if (encBtn && lockBtn) {
                    encBtn.style.display = 'none';
                    lockBtn.style.display = 'block';
                }
                var note = allNotesCache.find(function(n) { return n.id === currentNoteId; });
                if (note) note.is_encrypted = true;
                loadNotes();
            }).catch(function(e) {
                customDialog({ title: '加密失败', message: '错误: ' + e });
            });
        });
    });
});
'''

# Find a good place to inject the event listener, e.g., after the document.getElementById('archive-note-btn')...
text = re.sub(
    r'(document\.getElementById\(\'archive-note-btn\'\)\.addEventListener\(\'dblclick\', function\(\) \{)',
    encrypt_event.strip() + r'\n\n\1',
    text
)


with open('frontend/index.html', 'w', encoding='utf-8') as f:
    f.write(text)

print('Updated frontend/index.html')
