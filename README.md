# 析镜 LensAnalysis

专业的内存取证分析工具，基于 Volatility 3 框架开发，为安全研究人员、CTF 爱好者和应急响应人员提供强大的内存镜像分析能力。

![Windows](https://img.shields.io/badge/Windows-10%2F11-blue)
![macOS](https://img.shields.io/badge/macOS-12%2B-blue)
![License](https://img.shields.io/badge/License-Proprietary-red)

## ✨ 功能特性

### 🖥️ 跨平台支持

- **Windows** - 原生支持，提供 `.exe` 可执行文件（由于是py打包，没签名会误报有毒）
- **macOS** - 提供 `.dmg` 安装包
- **Linux** - 无用户，暂不提供

### 🔍 强大的分析能力

#### Windows 内存镜像

- **进程分析** - pslist, pstree, psscan, dlllist, handles, cmdline
- **网络分析** - netscan, netstat（含完整时间戳）
- **注册表** - hivelist, printkey, certificates, userassist
- **恶意代码** - malfind, ldrmodules, hollowprocesses
- **密码提取** - hashdump, lsadump, cachedump
- **服务扫描** - svcscan, svclist
- **更多插件** - 60+ Windows 分析插件

#### Linux 内存镜像

- **进程分析** - pslist, pstree, psaux, envars
- **网络分析** - netstat, sockstat, ip_addr, ip_link
- **内核模块** - lsmod, check_modules, check_syscall
- **Bash 历史** - bash 命令历史提取
- **文件系统** - lsof, list_files, mount_info
- **恶意代码** - malfind, check_idt, check_afinfo

#### macOS 内存镜像

- **进程分析** - pslist, pstree, psaux, envars
- **网络分析** - netstat, ifconfig
- **内核扩展** - lsmod
- **文件系统** - lsof, list_files, mount
- **系统信息** - timers, kauth_listeners, vfsevents

### 🎯 CTF 专用功能

- **Flag 搜索** - 自动搜索常见 Flag 格式（flag{xxx}）
- **正则搜索** - 自定义正则表达式搜索内存
- **字符串提取** - 提取所有可打印字符串

### 🚀 性能优化

- **智能缓存** - 分析结果自动缓存，重复操作秒级响应
- **符号表管理** - 自动下载和管理系统符号表
- **代理支持** - 支持 HTTP/HTTPS/SOCKS5 代理

### 📊 报告导出

- **Markdown** - 生成 Markdown 格式报告
- **HTML** - 生成网页格式报告
- **Word** - 生成 Word 文档报告

## 🖼️ 界面预览

### 镜像主界面

![主界面](screenshots/screenshot-main.png)

### 激活页面

![主界面](screenshots/jihuo.png)

### 符号表管理

![加载镜像](screenshots/fhb.png)

### 加载镜像

![加载镜像](screenshots/screenshot-load.png)

### 插件执行结果

![加载镜像](screenshots/chajian.png)

## 📦 下载安装

### Windows

1. 下载 `LensAnalysis1.0.0.exe`
2. `核对md5值：434e132480e84c9f9e70322f9c1e65f5`
3. 双击运行即可
4. 首次运行需要激活（激活码免费）

### macOS

1. 下载 `LensAnalysis.dmg`
2. `核对md5值：4c623e94ad916228e437211e7472db22`
3. 打开 DMG 文件
4. 将 `LensAnalysis.app` 拖到 Applications 文件夹
5. 打开应用（首次运行需要右键→打开）

## 🎮 快速上手

1. **启动应用**
   - Windows: 双击 `LensAnalysis.exe`
   - macOS: 启动台打开 `LensAnalysis`

2. **加载镜像**
   - 点击 "加载镜像" 按钮
   - 选择内存镜像文件（`.raw`、`.mem`、`.vmem` 等）
   - 选择操作系统类型（可选，系统会自动检测）

3. **执行分析**
   - 左侧面板选择分析插件
   - 点击即可执行分析
   - 结果实时显示在右侧面板

4. **导出报告**
   - 点击 "导出报告" 按钮
   - 选择报告格式（Markdown/HTML/Word）
   - 报告自动生成并保存

## 🔧 系统要求

| 平台    | 最低要求                    |
| ------- | --------------------------- |
| Windows | Windows 10/11 (64位)        |
| macOS   | macOS 12+ (Monterey 或更高) |

## ⚖️ 许可协议

**本项目为专有软件，源码将在未来开源。**

### ✅ 允许的用途

- 个人学习、研究和安全测试
- CTF 竞赛等安全竞赛活动
- 授权的渗透测试和应急响应
- 教育机构和学术研究

### ❌ 禁止的行为

- 未经授权的商业使用
- 移除或修改软件版权信息
- 反向工程或破解软件
- 利用软件进行任何违法违规活动

### 📧 商业授权

如需商业使用授权，请联系作者。

## 🛡️ 免责声明

本工具仅供安全研究和授权测试使用。用户在使用本工具时应遵守当地法律法规。对于因滥用本工具造成的任何后果，作者不承担责任。

## 🙏 致谢

- [Volatility 3](https://github.com/volatilityfoundation/volatility3) - 强大的内存分析框架

## 📮 联系方式

- **GitHub**: https://github.com/hilyary/LensAnalysis
- **Issues**: https://github.com/hilyary/LensAnalysis/issues

---

**析镜 LensAnalysis** - 让内存取证更简单

*最后更新：2026年2月*9日
