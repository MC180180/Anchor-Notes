# 锚点笔记 - 数据存储结构规范

## 核心原则

> **完全自包含**: 笔记数据目录是笔记的**唯一真实来源**。所有文字、图片、视频、音频、附件
> 在添加时都会被**物理复制**到笔记的数据目录中。即使原始文件被删除或移动，
> 只要数据目录完整，笔记的所有内容就能正常显示和使用。

## 顶层目录结构

```
data/                           ★ 所有笔记的数据根目录
├── notes_index.db              全局索引数据库
├── {note-uuid-1}/              笔记1 的独立数据目录
│   ├── content.db              当前文档快照
│   ├── timeline.db             操作历史时间线
│   ├── images/                 图片资源
│   │   ├── a1b2c3d4.png
│   │   └── e5f6g7h8.jpg
│   ├── videos/                 视频资源
│   │   └── f9g0h1i2.mp4
│   ├── files/                  附件文件
│   └── audio/                  语音/音乐
├── {note-uuid-2}/
│   └── ...
└── ...
```

## 全局索引 (`notes_index.db`)

主页卡片列表的数据来源，无需打开每个笔记的独立数据库即可快速展示。

| 字段         | 类型    | 说明               |
| ------------ | ------- | ------------------ |
| id           | TEXT PK | 笔记 UUID          |
| created_at   | INTEGER | 创建时间 (ms 时间戳) |
| updated_at   | INTEGER | 最后修改时间        |
| title        | TEXT    | 标题 (首行文字)     |
| preview      | TEXT    | 预览文本            |

## 笔记独立数据库

### `content.db` — 当前文档快照

存放笔记的**最新完整 Quill Delta**，打开笔记时直接加载，无需重放历史。

| 字段       | 类型    | 说明                        |
| ---------- | ------- | --------------------------- |
| id         | TEXT PK | 固定值 `"current"`          |
| delta_json | TEXT    | Quill Delta JSON (完整文档) |
| updated_at | INTEGER | 最后更新时间                 |

### `timeline.db` — 操作时间线

每一次编辑的增量变更记录，用于时间线面板回溯。

| 字段            | 类型    | 说明                          |
| --------------- | ------- | ----------------------------- |
| id              | TEXT PK | 事件 UUID                     |
| timestamp       | INTEGER | 操作时间 (ms 时间戳)          |
| operation_type  | TEXT    | 操作类型 (键入/粘贴/拖拽等)   |
| delta_json      | TEXT    | 增量 Delta JSON               |

## 媒体资源管理

### 存储规则

| 文件夹    | 用途       | 命名规则              | 触发方式                   |
| --------- | ---------- | --------------------- | -------------------------- |
| `images/` | 图片       | `{uuid}.{原始扩展名}` | 工具栏/拖拽/粘贴           |
| `videos/` | 视频       | `{uuid}.{原始扩展名}` | 工具栏/拖拽                |
| `files/`  | 附件       | `{uuid}.{原始扩展名}` | 工具栏/拖拽                |
| `audio/`  | 语音/音乐  | `{uuid}.{原始扩展名}` | 工具栏/拖拽                |

### 引用机制

1. **Delta 中存储相对路径**: 如 `images/a1b2c3d4.png`、`videos/f9g0h1i2.mp4`
2. **渲染时动态解析**: `resolveMediaPath()` 函数将相对路径转换为 Tauri `asset://` 协议 URL
3. **不使用 Base64 内嵌**: 媒体文件独立存储，Delta JSON 体积极小

### 插入流程

```
用户插入媒体
    ├── 工具栏按钮 → Tauri 原生文件对话框 → copy_media_to_note (文件复制)
    ├── 拖拽文件   → FileReader → save_media_base64 (base64 解码写入)
    └── 粘贴图片   → FileReader → save_media_base64 (base64 解码写入)
         ↓
    后端返回相对路径 (如 "images/abc.png")
         ↓
    Blot.create(相对路径) → resolveMediaPath() → asset URL 渲染显示
         ↓
    Blot.value() → 返回原始相对路径 → 存入 Delta JSON
```

## 导出备份

点击「导出」按钮将**整个笔记目录**打包为 `.tar.gz`：

```
笔记标题.tar.gz
└── {note-uuid}/
    ├── content.db
    ├── timeline.db
    ├── images/  (含所有图片文件)
    ├── videos/  (含所有视频文件)
    ├── files/
    └── audio/
```

备份文件包含笔记的一切数据，可独立恢复。
