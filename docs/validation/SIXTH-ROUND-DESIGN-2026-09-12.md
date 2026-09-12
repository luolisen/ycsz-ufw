# LUNA 第六轮动态证据工具设计（2026-09-12）

## 1. 范围与基线

本轮只修正 `scripts/Test-ProtectionDriver.ps1` 的动态证据语义、fixture 对照与回归门禁，不加载驱动、不启动或重启 Windows 虚拟机、不触碰生产机器、不改变签名/altitude。基线是 `e26ca40`，最近代码提交为 `9b3d291`，上一轮 Windows CI `34665735872` 已通过。

本工具的结果是证据记录，不把工具自身能执行某个 API 等同于驱动已经保护了该对象。动态模式只有在明确满足前置条件、控制对照成功、阶段真实且原生错误码匹配时才允许输出 `PASS`。

## 2. 结果状态与退出语义

每个检查只允许使用四种状态：

| 状态 | 含义 | 是否可作为通过证据 |
| --- | --- | --- |
| `PASS` | 目标动作被拒绝或允许的结论已由正确阶段、控制对照和精确原生错误码共同证明 | 是 |
| `FAIL` | 目标动作在应被拒绝时成功，或控制动作失败 | 否，退出码 1 |
| `ERROR` | 工具调用、参数、路径、共享方式、清理或未知原生错误导致结论不可判定 | 否，动态模式退出码 1 |
| `BLOCKED` | 安全前置条件、隔离能力或所需阶段不可用，且不能安全地制造 | 否，动态模式退出码 2 |

不再使用“任意异常即 PASS”或“任意非零退出即 PASS”。汇总中增加 `Errors`，`Uncovered` 继续只列 `BLOCKED`；动态模式先判 `FAIL/ERROR`，再判 `BLOCKED`。

## 3. 原生错误采集与分类

所有返回值必须在紧邻的 native 调用之后立刻保存 `Marshal.GetLastWin32Error()`；不得先执行 PowerShell、字符串格式化、清理或另一个 native 调用后再读取。分类函数只接受显式的预期集合：

- `ERROR_ACCESS_DENIED (5)`：仅可在路径、目标对象、控制对照和检查阶段均正确时作为拒绝证据。
- `ERROR_SHARING_VIOLATION (32)`：表示共享/句柄前置条件冲突，不能冒充驱动拒绝，通常为 `ERROR` 或 `BLOCKED`。
- `ERROR_INVALID_PARAMETER (87)`、`ERROR_NOT_SUPPORTED (50)`、`ERROR_CALL_NOT_IMPLEMENTED (120)`：表示调用或平台不支持，不能作为保护通过，归 `BLOCKED`。
- 其它错误码：归 `ERROR`，保留十进制和十六进制值。

PowerShell 异常需要保存 `Exception.HResult`、可用的 `Win32Exception.NativeErrorCode` 和阶段名；若不能取得可靠的 Win32 错误码，不得降级成 `PASS`。

## 4. 文件、硬链接与重解析点

### 4.1 文件写入

普通 fixture 文件先完成一次可写控制写入，以确认 runner、权限和普通文件路径有效。启用保护后的“新建句柄”检查单独命名为 `post-active new handle`：成功打开并写入为 `FAIL`；打开或写入立即得到 `ERROR_ACCESS_DENIED` 且控制写入成功时才为 `PASS`；共享冲突、路径错误、权限/账户问题、其它错误为 `ERROR` 或 `BLOCKED`。

“激活前已持有句柄”需要一个安全的两阶段 harness：阶段 A 创建并保持句柄，阶段 B 由同一隔离 fixture 启动服务并等待 `Active`，阶段 C 执行写入。当前工具没有这种可验证的过渡，也不能通过停止生产服务来模拟，因此该项目明确输出 `BLOCKED`，并不能把激活后新建句柄改名为已有句柄。

### 4.2 硬链接与 junction

目标源文件、父目录、fixture marker、相对根校验和普通 fixture 对照必须先成功。创建成功为 `FAIL`。创建失败只有在错误码为 `ERROR_ACCESS_DENIED`、失败点是创建调用且所有前置条件已满足时才为 `PASS`。`ERROR_INVALID_PARAMETER`、`ERROR_NOT_SUPPORTED`、共享冲突和任意 PowerShell 包装异常分别归 `BLOCKED` 或 `ERROR`。清理失败必须保留证据路径并追加 `ERROR`，不能静默吞掉。

## 5. 映射写入

映射调用使用一致的权限：`PAGE_READWRITE (0x04)` 配 `FILE_MAP_WRITE (0x0002)`，不再叠加与目标无关的 `FILE_MAP_EXECUTE`。先以普通 fixture 建立、写入和 flush 一个控制映射，确认 API 与权限有效；再对受保护文件执行目标路径检查。

目标映射在保护已经 Active 后新建，不能证明“激活前已存在的 writable mapping”。因此：CreateFileMapping/MapView/Flush 在正确阶段返回 `ERROR_ACCESS_DENIED` 且控制映射成功时才记录对应拒绝证据；参数错误、不支持、共享冲突、其它错误为 `ERROR`/`BLOCKED`；完整写入并 flush 成功为 `BLOCKED`，因为这表示当前兼容路径未被拒绝，不能冒称 PASS。激活前已存在映射仍单列 `BLOCKED`，直到安全两阶段 harness 可用。

## 6. 卸载与控制句柄

控制设备必须在 fixture 与 Active 状态下成功打开，并在调用 `fltmc unload YcszProtection` 前保持打开。调用后立即保存退出码和全部输出；退出码为 0 是 `FAIL`。非零只有在输出中明确包含 `STATUS_FLT_DO_NOT_DETACH`、`ERROR_FLT_DO_NOT_DETACH`、其 NTSTATUS `0xC01C0010` 或 Win32 映射 `0x801F0010`，且目标过滤器仍可查询时才可作为“控制句柄使非强制卸载被拒绝”的 `PASS`。未知错误码、过滤器名称/参数错误、权限问题、工具不存在或目标过滤器已消失为 `ERROR`/`BLOCKED`，绝不按非零统一判 PASS。

该预期状态来自驱动的 `FilterUnloadCallback` 返回值；强制卸载、服务停止路径和生产对象不在本工具范围内。控制句柄清理失败追加 `ERROR` 并保留结果，不覆盖原始卸载证据。

## 7. 目录删除、终止与挂起

受保护根目录删除沿用同一错误码分类：成功为 `FAIL`，精确的 `ERROR_ACCESS_DENIED` 才能为 `PASS`，不支持/参数错误为 `BLOCKED`，其它错误为 `ERROR`。不新增杀进程、挂起进程、重启会话或重启机器动作；没有安全的专用 fixture 进程与恢复脚本时，这些项目继续 `BLOCKED`。工具实现本身不计作动态驱动证据。

## 8. 纯回归覆盖

在不依赖 Windows 驱动、服务、注册表或真实文件系统保护的纯回归中覆盖：

1. `ERROR_ACCESS_DENIED` 只在期望阶段和控制对照成功时判 `PASS`。
2. 缺失文件、共享冲突、`ERROR_NOT_SUPPORTED`、`ERROR_INVALID_PARAMETER` 和未知错误不会判 `PASS`。
3. 映射参数错误与预期拒绝分流，且映射权限常量不再包含 EXECUTE。
4. native 错误码在返回后立即捕获；模拟后续调用不会改变已记录错误。
5. 清理失败保留原始证据并产生 `ERROR`。
6. 退出码对 `FAIL/ERROR/BLOCKED` 分别保持 1/1/2；静态 CI 不执行动态模式。

## 9. 验收与回滚

先运行本地 PowerShell 纯回归与静态检查，再提交普通分支并等待 Windows CI。CI 只接受 WDK/InfVerif、现有 PowerShell/C#/驱动纯测试和本轮动态分类回归通过；没有隔离签名 Windows 时不运行 Dynamic。若回归破坏既有静态门禁，回滚本轮工具/回归提交，不回退或覆盖用户已有的四份未跟踪证据文档。
