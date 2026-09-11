# 自保护组件实现与验证记录

日期：2026-09-12。范围：本仓库隔离工作树。没有连接或修改生产 Windows，也没有安装、签名、加载试验驱动。

## 已实现

- `drivers/YcszProtection/`：共享 IOCTL 协议、Ob callbacks、文件系统 minifilter、x64 WDK vcxproj/INF 和限制说明。
- `src/Ycsz.Core/SelfProtectionDeviceTransport.cs`：固定设备路径、x64 ABI 镜像、盘符到 NT 设备路径转换、状态/能力映射。
- `src/Ycsz.App/Program.cs`：服务启动激活、已认证 IPC 维护租约、维护超时轮询、SCM 停止控制和审计日志。
- `src/Ycsz.App/Ui.cs`：进入/结束自保护维护窗口入口。
- `scripts/build.ps1` / `scripts/build.sh`：显式的可选驱动构建入口；默认构建和安装器不包含驱动。
- `scripts/Test-Windows.ps1`：驱动源文件、协议、用户态接入的静态门禁。

## 已执行检查

| 检查 | 结果 |
| --- | --- |
| Mono C# Core 编译（临时目录） | 通过 |
| Mono C# App 编译（临时目录） | 通过 |
| Mono C# Tests 编译并执行 | 57/57 通过 |
| 协议 x64 固定布局（头部、身份、激活、租约、状态） | 通过，16/1088/2128/40/2152 字节 |
| `bash -n scripts/build.sh` | 通过 |
| `git diff --check` | 通过 |
| WDK C 编译 | 未执行：当前 macOS 没有 WDK/Visual Studio |
| 驱动签名、安装、加载、重启、动态阻断 | 未执行：没有隔离 Windows 靶场 |
| PowerShell 解析器执行 | 未执行：当前环境没有 `pwsh` |

## Windows 待验收矩阵

必须在独立、可恢复、与生产隔离的 Windows x64 靶场中记录 OS/WDK/签名和错误码：

1. 正式唯一 altitude、CAT 和适配目标系统的签名；WDK Release 编译并安装 minifilter。
2. 服务实际激活后，标准用户和提升工具请求终止/挂起服务进程；确认原 PID 仍存活，不用 SCM 重启换 PID 代替通过。
3. 对安装目录专用测试文件执行删除意图打开、已有句柄写入、删除、重命名、覆盖、截断、链接/重解析点操作；比较操作结果和内容哈希。
4. `Stop-Service` 在非维护状态被 SCM 拒绝；已登录管理页进入维护后可在五分钟内停服、更新/卸载，结束或超时后重新保护。
5. 服务异常退出后 SCM 恢复；新服务实例重新绑定，旧 PID/创建时间不能继续获得维护权限。
6. 映射写入、内核请求、硬链接和重解析点、注销/重启、联想同版本镜像兼容性；任何未覆盖路径单独记录，不能扩大成功结论。

当时结论仅覆盖该批源码与用户态回归；后续复审发现下列未闭环问题。驱动仍处于“未 WDK 编译/未签名/未加载/未动态验收”，不能作为生产自保护已通过的证据。

范围缺口：本轮固定协议只保护包含 `Ycsz.exe` 的安装目录；`ProgramData\YcszFirewall` 配置、日志和基线尚未纳入 minifilter 根目录，仍依赖 ACL 与应用恢复逻辑。
本轮 Ob 目标是核心 LocalSystem 服务实例；交互托盘未登记为第二个受保护进程，托盘监督恢复不作为拒绝终止证据。


## 主任务复审（2026-09-12，未通过生产验收）

主任务已亲自修复：
- `FltGetDestinationFileNameInformation` 错误的参数类型和缺失长度参数。
- CREATE disposition 必须取 Options 的高 8 位，原实现误取低位。
- 移除不允许用错误状态拒绝的 CLEANUP 回调；不能声称已阻止先前已标记删除的句柄。
- Push lock 的所有临界区配对禁用/恢复普通 APC。
- Ob 注册的非恒定全局初始化改为 DriverEntry 初始化；修正 UNICODE_STRING 初始化字段数。
- 设备初始化结束清除 DO_DEVICE_INITIALIZING，并补 Wdmsec 链接库。
- 维护退出通信失败后保留租约，以便到期重试；新增回归测试通过，用户态总计 58/58。
- 移除 ServiceBase 在 OnStart 和运行期间修改 CanStop 的调用：.NET Framework 在调用 OnStart 前冻结此属性，该写入会导致启动失败。

仍然阻塞生产验收，不能把本轮修复当作完整防护实现：
1. 激活时仅验证调用者实际映像路径以 Ycsz.exe 结尾，SHA256 为调用者自报，尚未绑定安装时可信服务身份；首次绑定与服务退出后重新绑定存在冒名风险。
2. SCM 原生状态与 ServiceBase 内部状态不一致；OnStop 直接返回仍会被框架报告为 Stopped。必须重新设计受控停止流程并在 Windows 验证，不能宣称服务停止门禁已完成。
3. PREPARE_UNLOAD 打开 DriverUnload 后缺少独立的超时撤销机制；minifilter 卸载回调及完整资源清理协议未闭环。
4. 状态应答核验已在下方续审修复；仍需 Windows 真设备往返验证。
5. WDK 工程尚未实际编译，以上源码修正不等于 Windows 编译/加载成功。altitude、签名、别名/映射写入等仍待解决。

依据：Microsoft Learn 的 FltGetDestinationFileNameInformation、ExAcquirePushLockExclusive、PFLT_PRE_OPERATION_CALLBACK 文档；Microsoft referencesource 的 System.ServiceProcess/ServiceBase.cs。没有连接生产、加载驱动、重启或修改系统安全设置。


### 主任务续审：驱动应答与服务实例（2026-09-12）

- 只接受完整固定长度的状态应答，校验版本、结构大小、保留位、已知状态位及错误状态。
- 核对 PID、创建时间、映像摘要、实例随机标识、映像路径和保护根目录，拒绝截断、旧实例或不同目录的应答。
- 进入维护要求租约 ID 与期限完全匹配；激活/退出要求维护租约已清空。
- 维护期间不再报告进程/文件保护正在生效。
- 修复每次维护重新 CaptureCurrent 导致实例随机标识改变的问题：同一次服务注册复用身份。
- Core/App/Tests 临时目录编译成功，61/61 测试通过，结果见 `self-protection-status-review-results.txt`；`git diff --check` 通过。
- 本次只关闭应答校验缺口，不代表驱动端验证自报摘要已可信；服务身份信任根、SCM 和卸载流程仍是未完成项。


### 主任务续修：认证停服与驱动信任（2026-09-12，源码未部署）

- 去掉原生 SCM 状态写入与 OnStop 直接返回的伪拒绝路径。服务在 Run 前固定 CanStop；驱动已注册时保持 SCM Stop 关闭，改用已认证 IPC 的维护停服入口。
- IPC 回复关闭连接后异步停服，执行前再次检查同一会话的租约；维护结束/过期使排队请求失效。停服与系统关机的清理入口统一标记 stopping，抑制计时器继续操作，并避免重复清理。
- 更新脚本的失败说明明确要求点击“维护停止本机服务”，不把进入维护等同于开放 SCM Stop。
- 驱动改为 Filter Manager 卸载回调内核验当前租约，不再把 DriverUnload 动态开关当作授权。禁止 SCM 服务停止触发卸载，强制卸载不能由回调否决。
- 激活增加 Session 0、LocalSystem、固定产品服务 SID 和预置完整 NT 映像路径核验。信任路径只在驱动加载时从 Parameters 读取；缺少配置则加载失败。

仍未闭环：信任配置安装器、Windows SID/路径验证、控制设备卸载同步、用户态 PREPARE_UNLOAD、签名/正式 altitude、WDK 编译与 Windows 动态验收。进程摘要仍由服务计算；未声称内核重新验证文件签名。服务注册存在性只是应用选择停服模式的依据，不是防管理员修改注册表的机制。

部署边界：本节源代码没有覆盖 `artifacts` 或两台机器。双机已部署版本以 `DEPLOYMENT-2026-09-12.md` 的哈希为准。本轮没有远程操作、重启或加载驱动。

本轮验证：Core/App/Tests 在独立临时目录以 warnaserror 编译通过；现有回归 61/61 通过，见 `self-protection-maintenance-review-results.txt`；`git diff --check` 通过。这些既有测试覆盖协议、租约和托盘恢复，不覆盖本轮新增 SCM/Filter Manager/服务 SID 原生路径，不能作为其动态验收。


### 定时续审：控制连接与普通卸载（2026-09-12）

- 为控制设备加入按 FILE_OBJECT 计数的连接引用。CREATE 与普通卸载状态切换共用锁；卸载开始后拒绝新打开。CLEANUP 成功但保留引用，只有最终 CLOSE 释放，避免句柄已关闭但 I/O 引用仍存在时过早放行。
- 普通卸载要求引用数为零，且实际回调时维护租约仍有效；有连接时拒绝本次卸载，关闭连接后须重新请求。强制卸载的回调不可否决，该路径的并发资源安全仍未验收。
- 修正 INF 中 ActivityMonitor 对应的错误 ClassGuid。
- 修正 Windows 静态脚本对旧 CanStop 写法及文件 CLEANUP 拦截的过时要求。控制设备 CLEANUP 与 minifilter 文件 CLEANUP 不同，前者只做生命周期成功响应，未恢复删除清理拦截。
- 新增 `python3 scripts/test-driver-control.py`，直接提取两段生产 C 函数，用便携桩测试连接、授权过期、重复卸载和异常引用条件。编译开启 Wall/Wextra/Werror，5 组场景通过；输出见 `driver-control-lifecycle-results.txt`。桩不模拟 Windows I/O manager、IRQL、多线程调度或真实卸载，不是 WDK 编译证据。
- INF GUID 与工程 XML 静态检查通过，git diff --check 通过；未改动用户态代码，未重复跑 61 项旧回归。PowerShell 门禁因本机无 pwsh 未执行。

核对依据：微软 [CDO 控制设备卸载示例](https://github.com/microsoft/Windows-driver-samples/blob/main/filesys/miniFilter/cdo/CdoInit.c)、[CDO 连接生命周期](https://github.com/microsoft/Windows-driver-samples/blob/main/filesys/miniFilter/cdo/CdoOperations.c)、[Minifilter INF 文档](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-an-inf-file-for-a-minifilter-driver)。正式安装配置、WDK/InfVerif、签名/altitude、强制卸载及隔离 Windows 验收仍待完成。没有操作生产机器或重启。
