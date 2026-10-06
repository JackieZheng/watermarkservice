# ExplorerWatermarkService

Monitor `explorer.exe` restarts and automatically clear the Windows 11 desktop watermark.

监控 `explorer.exe` 重启，自动去掉 Windows 11 桌面右下角的 Insider 水印。

Windows 预览版（Insider）会在桌面右下角绘制一行水印。绘制者是 `explorer.exe` 里 `shell32.dll` 的
`CDesktopWatermark::s_DesktopBuildPaint`。本项目把它入口的第一个字节改成 `0xC3`（`RET`），
让这个函数直接返回、什么都不画 —— **不修改任何系统文件，只改 explorer 的内存页**。

---

## 特性

- **不碰系统文件**：只写入 explorer 进程内存，重启 explorer 即完全还原（可逆、无残留）。
- **不修改 exe**：清除动作由原版 `ClearWinWatermark.exe` 完成，一个字节都没改。
- **离线可用**：把 RVA 缓存提前准备好，exe 启动即命中缓存，**不联网、不依赖微软符号服务器**。
- **抗"符号未发布"**：预览版 / 刚打完累积更新的机器，微软往往还没发布对应的 `shell32.pdb`（下载必然 404）。
  本项目会在本机自行定位正确地址，而不是撞上去 panic。
- **发现失败就跳过**：拿不到可信地址时**宁可不动**，不会把错误的地址 patch 进 explorer。
- **安装即成服务**：注册为 Windows 服务，开机自动运行。

## 快速开始

需要管理员权限（安装 / 卸载服务）。

| 操作 | 入口 |
|---|---|
| 安装服务 | 双击 `install.bat`（会自动提权） |
| 卸载服务 | 双击 `uninstall.bat` |
| 查看状态 | 双击 `status.bat` |
| 手动执行一次 | 双击 `RunManual.bat` |

命令行等价写法：

```
tools\nssm.exe install ExplorerWatermarkService
tools\nssm.exe start   ExplorerWatermarkService
tools\nssm.exe status  ExplorerWatermarkService
tools\nssm.exe restart ExplorerWatermarkService
tools\nssm.exe stop    ExplorerWatermarkService
tools\nssm.exe remove  ExplorerWatermarkService confirm
```

## 工作原理

```
explorer.exe 重启
      │ 触发
      ▼
monitor.ps1（常驻，轮询 explorer 的 StartTime，默认 3s）
      │ 调用
      ▼
clear-watermark.cmd  →  run-watermark-guarded.ps1（守卫）
      │  步骤 0：体检 RVA 缓存（prewarm-rva.py --verify）
      │          0=就绪 / 4=缺失 / 2=校验未通过
      │          缺失或校验未通过 → 按三条来源预热，全部要过硬校验才写缓存：
      │            ⓪ 同机其它账户档案里已有的缓存（离线播种，最快）
      │            ① 本 build 的 shell32.pdb（用本机 GUID+Age 索引）
      │            ② 相邻 build 迁移（本 build 符号未发布时的兜底）
      │  步骤 1：启动 tools\ClearWinWatermark.exe
      │  步骤 2：exe 非 0 退出 → verify-inject.py 复核 explorer 内存，
      │          区分「真失败」与「服务账户没有交互桌面导致的假失败」
      ▼
exe 把 shell32 里 CDesktopWatermark::s_DesktopBuildPaint 的首字节写成 0xC3 (RET)
      ▼
explorer 不再绘制水印
```

### 三层各自负责什么

| 层 | 文件 | 职责 |
|---|---|---|
| 触发 | `bin\monitor.ps1` | 常驻，发现 explorer 重启就调下一层；记录**真实退出码与耗时** |
| 守卫 | `bin\clear-watermark.cmd` → `bin\run-watermark-guarded.ps1` | 体检缓存 → 必要时预热 → 调 exe → 复核内存 |
| 执行 | `tools\ClearWinWatermark.exe` | 唯一真正往 explorer 里写字节的程序（原版未改） |

## 关键概念：RVA 缓存

exe 需要知道 `s_DesktopBuildPaint` 在 `shell32.dll` 里的偏移（RVA）。它从本机 `shell32.dll` 的
CodeView（RSDS）记录里拼出符号索引 `<GUID><Age>`，然后：

1. 先看 `%APPDATA%\reticivis\UWD2\data\<索引>.rva` —— **有就直接用，全程离线**；
2. 没有才去微软符号服务器下载 `shell32.pdb` 查符号 —— 而预览版 / 刚更新的版本必然 404。

所以**把缓存提前准备好，问题就从根上消失了**。本项目负责产出这个缓存，并且**保证写进去的值是对的**。

**为什么要校验**：缓存文件名用的是本机 GUID，内容却可能是别的 build 算出来的 RVA（历史上 exe 曾硬编码
GUID，造成"串号"）。这种错位极隐蔽 —— exe 看起来运行正常，实际把无关函数的首字节改掉、破坏栈平衡。
因此本项目在采纳任何值之前，必须通过两条硬校验：

- 落点必须是本机 `shell32.dll` 的 `.pdata` 函数入口；
- 若参考 PDB 给出了该函数的 size，本机对应函数的 size 必须**完全一致**。

**相邻 build 迁移**（本 build 符号未发布时的兜底）：从 WinbIndex 的 Insider 索引里挑出比当前 build 更早、
`SizeOfImage` 最接近的 build，下载它的 `shell32.dll` + `shell32.pdb`，取出参考函数体，用多个 24 字节锚点
在本机 `shell32.dll` 里投票定位，采纳条件为「票数 ≥ 8 且 > 次高票 × 2」并通过上述两条硬校验。

参考实测（Windows 11 Insider Dev，build 29680）：

| 项 | 值 |
|---|---|
| PDB 索引 | `9AEBCD7CEA66988F436F79A9FD18F6C81` |
| `s_DesktopBuildPaint` RVA | `0x081d28` |
| 函数大小 | `0xa1f` |
| 参考 build | 29671（参考 RVA `0x2764c`）→ 29 票命中，次高 1 票，函数大小全等 |
| 注入验证 | explorer 内存中 `模块基址 + 0x81d28` 首字节 `0x48` → `0xC3`，其余 15 字节未动 |

## 配置

`bin\config.json`：

```json
{
    "targetExe": "../bin/clear-watermark.cmd",
    "checkInterval": 3,
    "logMaxLines": 2000
}
```

- `targetExe`：explorer 重启后执行的对象。**默认即守卫入口，不要改回 `../tools/ClearWinWatermark.exe`**
  —— 那样会绕过预热与校验，回到「要么 panic、要么静默 patch 错地方」的状态。
- `checkInterval`：轮询间隔（秒）。
- `logMaxLines`：`service.log` 的滚动上限。

**改了文件要不要重启服务？**

| 改动的文件 | 是否要重启 |
|---|---|
| `bin\monitor.ps1` | **要** —— 常驻进程启动时已把旧代码读进内存 |
| `bin\run-watermark-guarded.ps1`、`clear-watermark.cmd` | 不要。每次执行都是新起进程读最新文件，**改完立即生效** |
| `bin\prewarm-rva.py`、`verify-inject.py`、`check-symbols.ps1`、`status.ps1`、`RunManual.ps1` | 不要，同上 |
| `bin\config.json` | 不要（每次执行时读取） |

## 文件结构

```
watermarkservice/
  install.bat / uninstall.bat         安装 / 卸载服务（需管理员）
  status.bat / RunManual.bat          状态体检 / 手动执行一次
  bin/
    monitor.ps1               常驻监控 explorer 重启
    clear-watermark.cmd       命令行入口（转发参数给守卫）
    run-watermark-guarded.ps1 守卫：体检 -> 预热 -> 调 exe -> 复核内存
    prewarm-rva.py            算/校验 RVA、相邻 build 迁移、同机离线播种
    verify-inject.py          读 explorer 内存确认是否已注入
    check-symbols.ps1         Python 不可用时的「符号是否已发布」探测回退
    status.ps1                一体化状态体检
    RunManual.ps1             手动执行一次（走守卫链路）
    config.json               实例配置
  tools/
    nssm.exe                  服务管理器
    ClearWinWatermark.exe     原版清理程序，未做任何修改
  log/                        运行期日志（不进版本库）
```

## 退出码

| 组件 | 码 | 含义 |
|---|---|---|
| `monitor.ps1` 记录 | 0 | 成功（已注入） |
| | 1 | 拿不到可信 RVA，跳过 |
| | 2 | 出错 |
| `prewarm-rva.py --verify` | 0 | 缓存就绪 |
| | 4 | 缓存缺失（本机还没有这个索引的 `.rva`） |
| | 2 | 缓存存在但内容与本机 `shell32` 不匹配 |
| | 3 | 环境错误 |
| `verify-inject.py` | 0 | 已注入 |
| | 1 | 尚未注入 |
| | 2 | 探测失败 |
| | 3 | 环境错误（需 64 位 Python） |

## 常见问题

| 现象 | 原因 | 处理 |
|---|---|---|
| `fetch_pdb.rs:8:47 ... Status(404)` panic | 本 build 的 `shell32.pdb` 尚未发布 | 守卫会先预热 / 迁移；拿不到就跳过不执行。用 `status.bat` 看缓存体检结论 |
| 日志报 `退出码 101` / `无效的窗口句柄` | 服务跑在 `LocalSystem`（session 0），没有交互桌面，exe 最后一步「刷新桌面」必然失败 | 注入其实**已经完成**（exe 已打印 `Injected!`）；守卫会复核内存并判定成功，不是注入失败 |
| 日志写着 Executing 却始终没生效 | 旧版 monitor 用 `Start-Process` 但不看退出码 | 已改为 `-Wait -PassThru` 记录真实退出码 |
| 服务账户下找不到缓存 | `LocalSystem` 的 `%APPDATA%` 指向 `systemprofile`，与登录用户不是同一个目录 | 「⓪ 同机离线播种」复用其它账户档案里已验证的值（本机 `shell32.dll` 是机器级的，校验通过即通用） |
| 在普通用户会话里查服务账户的缓存路径显示"不存在" | 普通用户对该目录**无枚举权限**，`Test-Path` 返回 `False`、`Get-ChildItem` 报「拒绝访问」 | 这是**权限造成的假阴性**，不能据此判断没有缓存；看 `log\rva-cache.log` 的 `[写入]` 行 |
| `.cmd` 首行报 `'锘緻echo' 不是内部或外部命令` | 文件带了 UTF-8 BOM | `.cmd/.bat` 必须**无 BOM** |
| `.ps1` 中文全变乱码、语法报错 | 文件缺 UTF-8 BOM，PowerShell 5.1 按 GBK 解码 | `.ps1` 必须**带 BOM** |

## 环境要求

- Windows 10 / 11
- PowerShell 5.1（系统自带）
- 管理员权限（仅安装 / 卸载 / 重启服务需要）
- Python 3.x（可选；没有则回退到 `check-symbols.ps1`，能力变弱）
- 64 位 Python（仅 `verify-inject.py` 读取 explorer 内存需要）

## 说明

- 本项目只面向**自用机器**清理预览版水印；请自行评估在你的环境中的适用性与合规性。
- 清除效果依赖 explorer 进程内存被改写，**explorer 重启后需要重新注入** —— 这正是服务常驻的意义。
- `tools\ClearWinWatermark.exe` 与 `tools\nssm.exe` 均为**第三方程序的原样副本**，版权归各自作者所有；
  取用时请遵守其原始许可。

## License

[MIT](./LICENSE)
