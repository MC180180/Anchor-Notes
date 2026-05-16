import re

with open(r'c:\Users\Administrator\Desktop\锚点\anchor_ui\frontend\index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add HTML for streaming-status
status_html = """    <div id="save-status" style="margin-right: auto; color: var(--txt); pointer-events: none;">已自动保存</div>
    <div id="streaming-status" style="display:none; align-items:center; margin-right: 15px; color: #ff9800; font-size: 13px;">
        <span id="streaming-text" style="font-family: monospace;">缓冲 0%</span>
        <div style="width: 80px; height: 4px; background: rgba(255,255,255,0.2); border-radius: 2px; margin-left: 8px; overflow: hidden;">
            <div id="streaming-bar" style="width: 0%; height: 100%; background: #ff9800;"></div>
        </div>
    </div>"""
content = re.sub(r'<div id="save-status" style="margin-right: auto; color: var\(--txt\); pointer-events: none;">已自动保存</div>', status_html, content)

# 2. Add streaming functions
stream_funcs = """
// --- 流式加载全局状态 ---
var streamOps = [];
var streamTotalLen = 0;
var streamLoadedLen = 0;
var streamIsActive = false;

function applyContentStream(ops) {
    var CHUNK_SIZE_CHARS = 100000; // 首次加载10万字，兼顾首屏速度与阅读体验
    streamOps = [];
    streamTotalLen = ops.length; // 以 op 块数量估算进度
    
    var currentChunk = [];
    var charCount = 0;
    
    for (var i = 0; i < ops.length; i++) {
        var op = ops[i];
        if (charCount < CHUNK_SIZE_CHARS) {
            if (typeof op.insert === 'string') {
                var len = op.insert.length;
                if (charCount + len <= CHUNK_SIZE_CHARS) {
                    currentChunk.push(op);
                    charCount += len;
                } else {
                    var take = CHUNK_SIZE_CHARS - charCount;
                    currentChunk.push({ insert: op.insert.substring(0, take), attributes: op.attributes });
                    streamOps.push({ insert: op.insert.substring(take), attributes: op.attributes });
                    streamOps = streamOps.concat(ops.slice(i + 1));
                    charCount += take;
                    break;
                }
            } else {
                currentChunk.push(op);
                charCount += 1;
            }
        } else {
            streamOps = ops.slice(i);
            break;
        }
    }
    
    streamLoadedLen = streamTotalLen - streamOps.length;
    quill.setContents(currentChunk);
    
    if (streamOps.length > 0) {
        streamIsActive = true;
        document.getElementById('streaming-status').style.display = 'flex';
        updateStreamUI();
    } else {
        streamIsActive = false;
        document.getElementById('streaming-status').style.display = 'none';
    }
}

function loadNextStreamChunk() {
    if (!streamIsActive || streamOps.length === 0) return;
    var CHUNK_SIZE_CHARS = 50000; // 每次增量加载5万字
    var currentChunk = [];
    var charCount = 0;
    var DeltaCls = Quill.import('delta');
    
    for (var i = 0; i < streamOps.length; i++) {
        var op = streamOps[i];
        if (typeof op.insert === 'string') {
            var len = op.insert.length;
            if (charCount + len <= CHUNK_SIZE_CHARS) {
                currentChunk.push(op);
                charCount += len;
            } else {
                var take = CHUNK_SIZE_CHARS - charCount;
                currentChunk.push({ insert: op.insert.substring(0, take), attributes: op.attributes });
                streamOps[i] = { insert: op.insert.substring(take), attributes: op.attributes };
                streamOps = streamOps.slice(i);
                charCount += take;
                break;
            }
        } else {
            currentChunk.push(op);
            charCount += 1;
        }
        if (i === streamOps.length - 1) {
            streamOps = []; 
        }
    }
    
    streamLoadedLen = streamTotalLen - streamOps.length;
    var appendDelta = new DeltaCls().retain(quill.getLength() - 1).concat(new DeltaCls(currentChunk));
    
    isProgrammaticChange = true;
    quill.updateContents(appendDelta, 'silent');
    isProgrammaticChange = false;
    
    updateStreamUI();
    if (streamOps.length === 0) {
        streamIsActive = false;
        setTimeout(function() { document.getElementById('streaming-status').style.display = 'none'; }, 1000);
    }
}

function updateStreamUI() {
    var pct = Math.floor((streamLoadedLen / streamTotalLen) * 100);
    if (pct > 100) pct = 100;
    document.getElementById('streaming-text').innerText = '缓冲 ' + pct + '%';
    document.getElementById('streaming-bar').style.width = pct + '%';
}

function loadAllStreamChunks() {
    if (!streamIsActive || streamOps.length === 0) return;
    document.getElementById('streaming-text').innerText = '全量合并...';
    // 强制一帧后执行，以便渲染文本
    setTimeout(function() {
        var DeltaCls = Quill.import('delta');
        var appendDelta = new DeltaCls().retain(quill.getLength() - 1).concat(new DeltaCls(streamOps));
        isProgrammaticChange = true;
        quill.updateContents(appendDelta, 'silent');
        isProgrammaticChange = false;
        streamOps = [];
        streamIsActive = false;
        updateStreamUI();
        document.getElementById('streaming-status').style.display = 'none';
    }, 10);
}

function extractDeletedText(delta, oldDelta) {"""
content = content.replace('function extractDeletedText(delta, oldDelta) {', stream_funcs)

# 3. Replace quill.setContents(parsed) with applyContentStream
content = content.replace('quill.setContents(parsed);', 'applyContentStream(parsed.ops || parsed);')

# 4. Add Event Listeners for scroll and keydown
listeners = """
document.querySelector('#editor-container').addEventListener('scroll', function(e) {
    if (streamIsActive) {
        var el = e.target;
        if (el.scrollHeight - el.scrollTop - el.clientHeight < 1200) {
            loadNextStreamChunk();
        }
    }
});
document.addEventListener('keydown', function(e) {
    if (e.ctrlKey && (e.key === 'a' || e.key === 'A' || e.key === 'End' || e.key === 'Home')) {
        if (streamIsActive) {
            loadAllStreamChunks();
        }
    }
});
"""
content = content.replace("var DeltaCls = Quill.import('delta');", listeners + "\nvar DeltaCls = Quill.import('delta');", 1) # Insert just before the first var DeltaCls definition or something early.
# Wait, let's just append listeners at the end of the script block.
content = content.replace("</script>\n</body>", listeners + "\n</script>\n</body>")

with open(r'c:\Users\Administrator\Desktop\锚点\anchor_ui\frontend\index.html', 'w', encoding='utf-8') as f:
    f.write(content)
