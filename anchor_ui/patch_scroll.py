import re

with open(r'c:\Users\Administrator\Desktop\锚点\anchor_ui\frontend\index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the scroll listener
old_listener = """document.querySelector('#editor-container').addEventListener('scroll', function(e) {
    if (streamIsActive) {
        var el = e.target;
        if (el.scrollHeight - el.scrollTop - el.clientHeight < 1200) {
            loadNextStreamChunk();
        }
    }
});"""

new_listener = """var streamIsLoading = false;
document.querySelector('#editor-container').addEventListener('scroll', function(e) {
    if (streamIsActive && !streamIsLoading) {
        var el = e.target;
        if (el.scrollHeight - el.scrollTop - el.clientHeight < 2000) {
            streamIsLoading = true;
            document.getElementById('streaming-text').innerText = '缓冲中...';
            // 异步执行，释放主线程，防止滑动瞬间卡死
            setTimeout(function() {
                try {
                    loadNextStreamChunk();
                } catch(err) {
                    console.error("Stream loading error:", err);
                }
                streamIsLoading = false;
            }, 50);
        }
    }
});"""

if old_listener in content:
    content = content.replace(old_listener, new_listener)
else:
    print("Could not find old listener")

with open(r'c:\Users\Administrator\Desktop\锚点\anchor_ui\frontend\index.html', 'w', encoding='utf-8') as f:
    f.write(content)
