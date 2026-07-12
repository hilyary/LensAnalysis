# 析镜 LensAnalysis

基于 [Volatility 3](https://github.com/volatilityfoundation/volatility3) 的图形化内存取证工具，面向安全研究、CTF 竞赛、教学和应急响应场景。析镜支持 Windows、Linux、macOS 内存镜像分析，并提供传统插件操作与「小析」AI 辅助分析两套工作流。

[![Release](https://img.shields.io/badge/release-v1.0.7-3b82f6)](https://github.com/hilyary/LensAnalysis/releases/latest)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078d4)
![macOS](https://img.shields.io/badge/macOS-12%2B-111827)
![Memory Images](https://img.shields.io/badge/images-Windows%20%7C%20Linux%20%7C%20macOS-10b981)
![License](https://img.shields.io/badge/license-Proprietary-ef4444)

## 下载

请从 [Releases](https://github.com/hilyary/LensAnalysis/releases/latest) 下载最新版：

- Windows：`LensAnalysis-Windows-1.0.7.exe`
- macOS：`LensAnalysis-macOS-1.0.7.dmg`

> Windows 版本暂未进行代码签名，Microsoft SmartScreen 或部分安全软件可能提示“未知发布者”或“可能不安全”。请只从本仓库 Releases 下载，并在运行前核对 SHA-256。

### v1.0.7 SHA-256

| 文件 | SHA-256 |
| --- | --- |
| `LensAnalysis-Windows-1.0.7.exe` | `e81caa2346390540fb79a3c15a774b74fdeef2348b047a51e4839d44e996129e` |
| `LensAnalysis-macOS-1.0.7.dmg` | `ffd894b033ec6df003c142cf8e1a918e48aab5ca58b9127445232d22301f9c0b` |

## 核心能力

### 图形化取证

- 镜像加载、系统识别、符号表状态检查和插件分类导航
- 插件结果表格、分页搜索、高级多条件筛选和数据导出
- 文件扫描分层可视化，按目录逐级浏览文件和子目录
- 插件结果按镜像自动缓存，相同镜像可直接复用
- Markdown、HTML、Word 取证报告
- HTTP、HTTPS、SOCKS5 代理配置

### 小析 AI 助手

- 使用自然语言查询镜像、插件缓存和取证结果
- 支持常用大模型供应商、第三方 API 服务及 OpenAI-compatible 接口
- 支持保存多份模型配置、连接测试、模型列表获取和当前配置切换
- 可加载镜像、运行插件、安装符号表、Dump 进程、导出或提取文件、解密数据，以及打开文件和定位目录
- 支持分析计划、线索索引、案件时间线和 AI 取证报告
- 支持手动确认与用户主动授权后的自动确认，并可查看进度、取消当前插件
- AI 对话按镜像保存；重新加载相同镜像后，可继续查看和使用历史记录
- 支持搜索、进入和删除其他镜像的历史对话

> 小析不会绕过用户配置擅自切换模型供应商。需要切换供应商时，应由用户确认。

### Windows 内存镜像

- 进程：`pslist`、`pstree`、`psscan`、`dlllist`、`handles`、`cmdline`
- 网络：`netscan`、`netstat`
- 注册表：`hivelist`、`printkey`、`certificates`、`userassist`
- 文件：`filescan`、文件提取、事件日志提取
- 恶意代码：`malfind`、`ldrmodules`、`hollowprocesses` 等
- 凭据：`hashdump`、`lsadump`、`cachedump`
- 服务与系统：`svcscan`、`getsids`、`envars` 等

### Linux 内存镜像

- 进程：`pslist`、`pstree`、`psscan`、`psaux`、`envars`
- 网络：`sockstat`、`ip_addr`、`ip_link`
- 文件：`lsof`、`elfs`、`mountinfo`、`pagecache`
- 内核与安全检查：`lsmod`、`check_modules`、`check_syscall`、`check_idt`
- Bash 历史、内存映射和恶意代码检测
- Linux 符号表下载或自动制作

### macOS 内存镜像

- 进程：`pslist`、`pstree`、`psaux`、`envars`
- 网络：`netstat`、`ifconfig`、`socket_filters`
- 文件：`lsof`、`list_files`、`mount`
- 系统与内核：`lsmod`、`dmesg`、`kevents`、`timers`、`vfsevents`
- 系统调用、Sysctl、陷阱表和恶意代码检查

### CTF 与线索搜索

- 常见 Flag 格式搜索
- 自定义正则表达式搜索
- 可打印字符串提取
- 搜索结果缓存和历史记录

## 快速上手

### 传统插件流程

1. 启动析镜并完成首次使用配置；首次运行时，请根据界面提示完成免费激活。
2. 点击「加载镜像」，选择 `.raw`、`.mem`、`.vmem`、`.dmp` 或 `.lime` 等文件。
3. 等待系统类型和符号表状态识别完成。
4. 从左侧导航选择插件，查看、筛选或导出分析结果。
5. 导出或提取完成后，可直接打开输出目录。

### 小析 AI 流程

1. 打开右侧「小析」入口，在设置中新增模型配置。
2. 选择供应商，填写 API Key、端点和模型，并执行连接测试。
3. 加载内存镜像后，直接描述取证目标或粘贴题目内容。
4. 小析会优先读取已有插件缓存；需要运行插件或安装符号表时，会请求确认。
5. 可按需开启自动确认、生成时间线或导出取证报告。

## Python、Volatility 与符号表

- 支持指定 Python 可执行文件或 Python 安装目录。
- 设置自定义 Python 后，依赖检测、依赖安装和 Volatility 命令均使用同一环境。
- 支持自定义 Volatility 3 命令路径。
- 支持自定义统一符号表目录，或分别配置 Windows、Linux、macOS 符号表目录。
- 支持共享 Volatility 3 缓存目录，减少重复扫描符号表的等待时间。
- Windows 支持通过当前解析到的 `vol` 命令下载匹配符号表。
- 支持导入 `.zip`、`.json`、`.json.xz` 本地符号表，并在安装前校验是否匹配当前镜像。
- 切换 Python 环境后会重新检测相关依赖。

## AI 数据与隐私说明

- 模型端点和 API Key 由用户自行配置。
- 小析调用在线模型时，会将当前问题以及完成回答所需的镜像信息、插件缓存摘要或工具结果发送给用户选择的模型供应商。
- 取证数据默认保留原始字段，不进行自动脱敏；请根据案件要求选择可信的模型服务。
- 对话历史按镜像保存在本地应用数据目录，可由用户手动查看或删除。
- 网络请求、模型计费、数据留存和服务可用性受所选供应商条款约束。

## 版本演进

README 仅展示近期重要变化，完整修复记录请查看 [Releases](https://github.com/hilyary/LensAnalysis/releases)。

| 版本 | 主要变化 |
| --- | --- |
| [v1.0.7](https://github.com/hilyary/LensAnalysis/releases/tag/1.0.7) | 新增小析 AI 助手、多模型配置、镜像对话历史、工具调用、自动确认、时间线、线索索引、AI 报告和 AI 符号表管理；改进文件可视化、任务取消、Windows 拖放、netscan 与符号表兼容性。 |
| [v1.0.6](https://github.com/hilyary/LensAnalysis/releases/tag/1.0.6) | 新增自定义 Python、符号表目录、Volatility 缓存目录、依赖检测、多条件筛选、镜像信息和一键打开目录；优化导出性能与日志管理。 |
| [v1.0.5](https://github.com/hilyary/LensAnalysis/releases/tag/1.0.5) | 大结果改为分页加载，搜索改为手动触发；新增更新日志展示，并修复 UserAssist、计划任务和注册表导航问题。 |

## 界面预览

> 下列截图展示基础工作流。小析 AI 助手及新版界面截图将在后续补充。

### 镜像主界面

![析镜主界面](screenshots/screenshot-main.png)

### 加载镜像

![加载内存镜像](screenshots/screenshot-load.png)

### 符号表管理

![符号表管理](screenshots/fhb.png)

### 插件执行结果

![插件执行结果](screenshots/chajian.png)

### Flag 搜索

![Flag 搜索](screenshots/flagsearch.png)

## 系统要求

| 运行平台 | 最低要求 | 安装包 |
| --- | --- | --- |
| Windows | Windows 10/11，64 位 | EXE |
| macOS | macOS 12 Monterey 或更高 | DMG |

目前未提供 Linux 桌面安装包，但可以在 Windows 或 macOS 版析镜中分析 Linux 内存镜像。

## 安装提示

### Windows

1. 从 [Releases](https://github.com/hilyary/LensAnalysis/releases/latest) 下载 Windows EXE。
2. 核对 Release 页面提供的 SHA-256。
3. 双击运行；如 SmartScreen 提示未知发布者，请先确认下载来源和哈希。
4. 根据界面提示完成首次激活。
5. 根据启动检查结果安装缺少的 Python/Volatility 依赖。

### macOS

1. 从 [Releases](https://github.com/hilyary/LensAnalysis/releases/latest) 下载 macOS DMG。
2. 打开 DMG，将 `LensAnalysis.app` 拖入 Applications。
3. 首次启动若被 Gatekeeper 拦截，可在 Finder 中右键应用并选择「打开」。
4. 根据界面提示完成首次激活。
5. 根据启动检查结果安装缺少的 Python/Volatility 依赖。

## 许可协议

**本项目为专有软件，源码将在未来开源。**

### 允许的用途

- 个人学习、研究和安全测试
- CTF 等安全竞赛活动
- 获得授权的渗透测试和应急响应
- 教育机构和学术研究

### 禁止的行为

- 未经授权的商业使用
- 移除或修改软件版权信息
- 反向工程或破解软件
- 利用软件进行违法违规活动

如需商业使用授权，请联系作者。

## 免责声明

本工具仅供安全研究和授权测试使用。用户应遵守所在地法律法规，并确保对被分析数据和系统拥有合法授权。对于因滥用本工具造成的后果，作者不承担责任。

## 致谢

- [Volatility 3](https://github.com/volatilityfoundation/volatility3) - 内存取证框架

## 联系与支持

- GitHub：[hilyary/LensAnalysis](https://github.com/hilyary/LensAnalysis)
- 问题反馈：[GitHub Issues](https://github.com/hilyary/LensAnalysis/issues)

析镜完全免费。如果它对你有帮助，欢迎 Star 本项目或推荐给更多人。

---

**析镜 LensAnalysis - 让内存取证更简单**

最后更新：2026 年 7 月 12 日
