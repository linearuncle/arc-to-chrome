# arc-to-chrome

把 **Arc 浏览器**的密码、历史记录、cookies 以及 **Spaces（工作区/固定标签页/收藏夹）** 迁移到 **Google Chrome** 的小工具（仅支持 macOS）。

全程离线，没有任何网络请求；解密后的明文只存在于内存中，不写入任何文件。

## 特色功能

- **Spaces & 标签页迁移**：解析 Arc 的 Spaces（包含 Pinned 标签、多层文件夹、Split Views 分屏标签，以及可选的今日未固定标签和置顶 Favorites），支持**直接合并入 Chrome 书签栏**或**导出为通用 HTML 书签文件**。
- **多 Profile 自动配对**：支持多配置文件映射。自动识别 Arc Profile 与 Chrome Profile（按配置名智能匹配），可单 Profile 迁移或 `--all-profiles` 一键批量合并。
- **密码与 Cookie 无损解密重加密**：两款浏览器均为 Chromium 内核但使用不同钥匙串密钥（`Arc Safe Storage` vs `Chrome Safe Storage`），工具完成跨钥匙串安全重加密，带严格 PKCS#7 校验与闭环校验（Round-trip verify）。
- **历史记录安全合并**：去重保留访问时间戳，自动处理自增 ID 偏移与引用字段清理。
- **安全防灾**：正式合并前自动备份 Chrome 原始文件至 `~/arc-to-chrome-backups/`，Chrome 运行保护防写入冲突。

---

## 快速使用

> 需要 Python 3.7+ 和 `pycryptodome`（`pip3 install -r requirements.txt`）。

### 1. 查看 Profile 映射与 Space 状态

```bash
# 查看所有 Arc 和 Chrome 的 Profile 及自动配对建议
python3 arc_to_chrome.py profiles

# 查看所有 Arc Spaces、关联的 Profile、标签数及 Chrome 配对
python3 arc_to_chrome.py spaces list
```

### 2. 迁移 Spaces（工作区 / 收藏标签）

你可以选择 **直接写入 Chrome 书签栏** 或 **导出为 HTML 书签导入**：

#### 方式 A：直接合并进 Chrome 书签（推荐）
```bash
# 演练预览：查看各 Profile 将合并的书签文件夹结构（不写磁盘）
python3 arc_to_chrome.py spaces merge --dry-run --all-profiles

# 完全退出 Chrome（⌘Q），正式合并所有 Spaces 到对应的 Chrome Profiles
python3 arc_to_chrome.py spaces merge --all-profiles

# 也可以只合并指定 Space 或指定 Profile
python3 arc_to_chrome.py spaces merge --space "xxd2025"
```
合并后打开 Chrome，书签栏中会出现对应的 `[Arc] <Space名称>` 及 `[Arc Favorites]` 文件夹，完整保留多层目录结构！

#### 方式 B：导出为通用 HTML 书签文件
```bash
# 导出全部 Spaces 到 HTML 文件（默认输出至 ~/Downloads/arc_spaces.html）
python3 arc_to_chrome.py spaces export

# 导出特定 Space
python3 arc_to_chrome.py spaces export --space "xxd2025" -o ~/Downloads/xxd2025.html
```
然后在 Chrome 中通过菜单「书签」→「导入书签和设置」选择 HTML 文件导入。

---

### 3. 迁移密码、历史记录与 Cookies

```bash
# 1. 预览：查看会有多少条密码、历史、Cookie 被合并（只读）
python3 arc_to_chrome.py diff --all-profiles
# 或指定单个 Profile（支持指定 Profile 目录名、显示名或 Space 名）
python3 arc_to_chrome.py diff --arc-profile "xxd2025"

# 2. 演练：对着临时副本完整走一遍加解密与写入校验，不修改真实文件
python3 arc_to_chrome.py merge --dry-run --all-profiles

# 3. 完全退出 Chrome（⌘Q），正式合并（会自动备份 Chrome 原始数据库）
python3 arc_to_chrome.py merge --all-profiles

# 🌟 强力推荐：一步全量迁移（包含密码、历史、Cookies 和所有 Spaces/书签！）
python3 arc_to_chrome.py merge --all-profiles --with-spaces

# 也可以只迁移指定 Profile 或指定数据项
python3 arc_to_chrome.py merge --arc-profile "xxd2025" --what logins,cookies
```

---

## 回滚与恢复

正式合并前会自动备份对应 Profile 的原始文件至 `~/arc-to-chrome-backups/<时间戳>_<Profile>/`。

如需回滚：
1. 完全退出 Chrome；
2. 将对应备份目录中的数据库或书签文件复制回对应的 Chrome Profile 目录（如 `~/Library/Application Support/Google/Chrome/<Profile>/`）即可。

## 安全性

- **全程离线**：系统调用仅限读取系统钥匙串（macOS Keychain）与读写本地数据库文件，零网络请求。
- **明文不出内存**：解密出的密码和 Cookie 敏感数据严格仅驻留内存，不落盘。
- **闭环验证（Round-trip verify）**：写入 Chrome 的每一条密码和 Cookie 都会立即读取并用 Chrome 密钥解密验证，任何不匹配立刻整组事务回滚。
- 更多说明见 [SECURITY.md](SECURITY.md)。

## License

[MIT](LICENSE)
