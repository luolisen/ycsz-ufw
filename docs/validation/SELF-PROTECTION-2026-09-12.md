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
| Mono C# Tests 编译并执行 | 63/63 通过 |
| 协议 x64 固定布局（头部、身份、激活、租约、状态） | 通过，16/1088/2128/40/2152 字节 |
| `bash -n scripts/build.sh` | 通过 |
| `git diff --check` | 通过 |
| WDK C 编译 | Windows CI 通过：Release、Universal/WDM、x64，生成 SYS/INF/CAT |
| 驱动签名、安装、加载、重启、动态阻断 | 未执行：CI 产物保持 unsigned，未连接生产或签名靶场 |
| PowerShell 解析器执行 | Windows CI 的 Windows PowerShell 5.1 通过，全部脚本与静态门禁通过 |
| InfVerif | Windows CI 通过：stamped INF 报告 `INF is VALID` |

## Windows 待验收矩阵

必须在独立、可恢复、与生产隔离的 Windows x64 靶场中记录 OS/WDK/签名和错误码：

1. 正式唯一 altitude、CAT 和适配目标系统的签名；WDK Release 编译并安装 minifilter。
2. 服务实际激活后，标准用户和提升工具请求终止/挂起服务进程；确认原 PID 仍存活，不用 SCM 重启换 PID 代替通过。
3. 对安装目录专用测试文件执行删除意图打开、已有句柄写入、删除、重命名、覆盖、截断、链接/重解析点操作；比较操作结果和内容哈希。
4. `Stop-Service` 在非维护状态被 SCM 拒绝；已登录管理页进入维护后可在五分钟内停服、更新/卸载，结束或超时后重新保护。
5. 服务异常退出后 SCM 恢复；新服务实例重新绑定，旧 PID/创建时间不能继续获得维护权限。
6. 映射写入、内核请求、硬链接和重解析点、注销/重启、联想同版本镜像兼容性；任何未覆盖路径单独记录，不能扩大成功结论。

早期结论仅覆盖 CI 之前的源码与用户态回归；后续 Windows CI 已关闭 WDK 编译、INF 校验和脚本门禁，但下列生产验收缺口仍然存在。驱动保持未签名、未安装、未加载、未动态验收，不能作为生产自保护已通过的证据。

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

## Windows CI 复审（2026-09-12，开发分支）

- 分支 `codex/luna-full-delivery-20260912`，提交 `a683f7d`；[GitHub Actions 运行 34641414586](https://github.com/luolisen/ycsz-ufw/actions/runs/34641414586) 在 `windows-2025-vs2026` runner 完成。
- 固定 Microsoft WDK/SDK NuGet `10.0.28000.2526` 的 Release x64 驱动构建通过，工具链生成 `YcszProtection.sys`、stamped `YcszProtection.inf` 和 CAT；独立 `InfVerif /w /v` 输出 `INF is VALID`。
- 同一运行通过用户态 `63/63` 回归、TLS `2/2`、合成网络 `9/9`、Windows PowerShell 5.1 脚本解析与静态门禁、WFP 原生事务回滚验证，以及 disposable Windows 安全集成的 `1 + 32 + 3` 项检查（含服务恢复与设备持久化）。
- 该 CI 只验证 unsigned 构建包和可恢复的测试 fixture；没有安装/加载驱动，没有正式签名、唯一 altitude、强制终止/挂起阻断、文件删除/重命名/映射写入或重启后 minifilter 动态证据。安全集成日志明确未测试客户端 WFP/网络强制，因此不能扩大成功结论。

核对依据：微软 [CDO 控制设备卸载示例](https://github.com/microsoft/Windows-driver-samples/blob/main/filesys/miniFilter/cdo/CdoInit.c)、[CDO 连接生命周期](https://github.com/microsoft/Windows-driver-samples/blob/main/filesys/miniFilter/cdo/CdoOperations.c)、[Minifilter INF 文档](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-an-inf-file-for-a-minifilter-driver)。正式安装配置、WDK/InfVerif、签名/altitude、强制卸载及隔离 Windows 验收仍待完成。没有操作生产机器或重启。


### 第二轮续审：用户会话、ProgramData 与动态验收工具（2026-09-12）

本节覆盖本文件前述历史记录中的第二轮缺口；历史段落保留用于追溯，不应再作为当前协议状态的唯一依据。先写入实施规格 `docs/validation/SECOND-ROUND-IMPLEMENTATION-2026-09-12.md`，随后在独占工作树实施并推送：计划提交 `ee4c4bd`，实现提交 `08a85e9`，Windows PowerShell 门禁修复提交 `97c63c8`，结果序列化兼容性修复提交 `7d0b265`。

本轮源码交付包括：

- 协议升级到 v2，固定 ABI 为头部/身份/激活/托盘/维护/卸载/状态 `16/1088/3152/1104/40/32/4264`；状态同时返回安装根、ProgramData 根、目标会话和托盘身份。
- 服务激活绑定实际 LocalSystem、Session 0、固定服务 SID、PID/创建时间/存活状态、安装时可信 NT 映像路径和可信 ProgramData 根；不接受 IOCTL 自报的任意 PID、路径或普通 SYSTEM 进程作为通用写入例外。
- 托盘注册要求真实进程 PID、创建时间、用户会话、实际映像路径及身份摘要/随机标识；退出、会话变化或停止时撤销注册，旧实例不能凭 PID 重用获得权限。
- minifilter 同时覆盖安装根和 ProgramData 根；删除/重命名/覆盖/截断、已有句柄、硬链接/重解析点及映射相关路径统一经过可信服务写入者门禁，未解析目标按失败关闭处理。
- 安装脚本校验 INF/SYS/CAT 成员与 `CatalogFile=YcszProtection.cat` 绑定，使用 `signtool verify /kp /c`；安装失败恢复旧信任值、服务/驱动状态和已发布驱动包，并用 `Ycsz.exe --protection-status` 区分服务 Running 与实际 v2 激活。
- 新增 `scripts/Test-ProtectionDriver.ps1`：Static 模式输出逐项 PASS/BLOCKED/FAIL JSON；Dynamic 模式必须管理员、显式 `-AllowFixtureMutation`、隔离 fixture 标记、服务/驱动已运行和固定测试根，覆盖已有句柄、映射、硬链接、重解析点、控制句柄并发卸载和根目录。无法制造普通 SYSTEM 身份或真实用户会话重启时明确输出 BLOCKED，不扩大结论。

本轮验证证据：

- 分支 `codex/luna-full-delivery-20260912` 的最终提交 `7d0b265`；[GitHub Actions 运行 34648815207](https://github.com/luolisen/ycsz-ufw/actions/runs/34648815207) 成功。
- Windows `windows-2025-vs2026` runner 的 Release x64 WDK 构建、stamped INF 和 `InfVerif`（`INF is VALID`）通过；同一运行的全部 PowerShell 5.1 解析/静态门禁通过。
- 驱动 Static 矩阵的 14 项源码/ABI/安装回滚检查为 PASS，并记录 3 项 BLOCKED：unsigned 驱动未加载、正式 CAT/唯一 altitude 未提供、终止/映射/链接运行时证据未执行。
- 同一运行通过用户态 `64/64`、TLS `2/2`、合成网络 `9/9`、安装/移除输入 `20` 项、控制生命周期 `5` 组、WFP 事务回滚，以及隔离 Windows 管理安全集成 `1 + 32 + 3` 项检查。以上不等于驱动动态阻断已通过。

仍然明确未完成：没有正式签名/唯一 altitude/CAT 信任包，没有安装或加载生产驱动，没有在隔离 Windows 上完成真实的已有句柄写入、映射写入、硬链接/重解析点、强制终止/挂起、控制句柄并发卸载和用户会话/PID 重启矩阵，也没有重启或生产机器证据。安装包校验和 Dynamic 工具已具备入口，但必须在可恢复签名靶场执行；普通更新流程在驱动仍加载时不能绕过可信服务和认证维护/卸载窗口直接替换受保护文件。

### 第三轮续审：文件身份与完整升级回滚（2026-09-12）

本轮先提交实施设计 `docs/validation/THIRD-ROUND-DESIGN-2026-09-12.md`（`f6dba9e`），随后在同一独占工作树实现。实现提交为 `9176651`，修正 WDK `FltGetFilterFromInstance` 调用约定的 `92bcd56`，以及补齐 Filter Manager filter rundown 引用释放和可移植资源测试的 `4f3d95f`。没有修改主任务保留的两个未跟踪审查文档。

文件身份与别名边界：

- 服务激活前新增只读 `SelfProtectionFilePreflight`，遍历安装根和 ProgramData 根，用 Windows 句柄读取卷序列号、文件 ID、硬链接计数和重解析属性；根不存在、身份不可读、重解析项、文件硬链接计数大于一或重复 `(VolumeSerial, FileIndex)` 都逐项报告并阻止发送激活请求。
- minifilter 在成功 CREATE 后为确认属于产品命名空间的流建立 `FLT_STREAM_CONTEXT`，保存 `FileInternalInformation.IndexNumber`；已有句柄、重命名后的同一流和产品路径首次确认分别经过 context/名称判定。可信服务只允许普通内容更新；重命名/硬链接必须仍落在已确认产品命名空间内，重解析逃逸和未解析的产品源操作拒绝。
- 未知路径、名称解析失败、普通重解析点、`IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` 和 paging/cache write 没有新增全局拒绝。映射写回只以 `MappingWritebackConditionMet` 记录激活前置条件，不声称可以阻断任意 Cache Manager 映射写回。
- 修复了 `FltGetFilterFromInstance` 成功后的 `FltObjectDereference`；context 本体和已有 context 仍分别使用 `FltReleaseContext`。`scripts/test-driver-control.py` 的新增桩测试覆盖 filter 获取失败、context 分配失败、设置失败、已有 context 和成功路径，输出为资源引用平衡通过。

升级与回滚边界：

- `Install-Protection.ps1` 使用 `Get-WindowsDriver -Online` 的安装前后结构化快照，不解析本地化的 `pnputil` `Published Name` 文本；只接受已核验的 YCSZ Provider/Class/INF/CAT 包，删除集合只来自本次确认新增的 YCSZ 包。
- 已有包在变更前必须导出并验证旧 INF/SYS/CAT；同时保存旧信任路径、旧 SID 属性和应用运行状态。`pnputil` 非零返回仍会重扫包清单，部分成功时按 delta 生成回滚计划；若重扫失败则保留状态/备份并报告人工恢复，不猜测副作用。
- 任一加载、激活、卸载拒绝或恢复失败先经过应用/驱动 quiescent gate；不能停稳时不改信任、SID、服务注册或驱动包。回滚不完整时保留旧包备份目录，只有 Commit 后才清理。
- `Test-ProtectionValidation.ps1` 的 46 项 Windows PowerShell 5.1 纯输入/故障注入检查覆盖修改前失败、安装失败（含部分发布）、加载失败、激活失败、卸载拒绝和恢复失败；本机及 Windows CI 的 C# Core/App/Tests 临时目录编译与测试为 `68/68`，TLS `2/2`，合成网络 `9/9`。

### 第三轮 Windows CI 证据

- 分支 `codex/luna-full-delivery-20260912`，最终实现提交 `4f3d95f`；[GitHub Actions 运行 34654419246](https://github.com/luolisen/ycsz-ufw/actions/runs/34654419246) 成功。
- 同一运行通过 WDK Release x64 编译、stamped INF、`InfVerif`、用户态 `68/68`、TLS `2/2`、合成网络 `9/9`、Windows PowerShell 脚本解析、静态驱动门禁和 46 项安装回滚输入检查；隔离 Windows 管理安全检查为 `1 + 32 + 3`。
- 静态驱动矩阵新增的 stream context、文件 ID、paging compatibility、activation preflight、mapped-write status、package delta/snapshot 和 `FltObjectDereference` 门禁均为 PASS；映射写回动态证据、unsigned 驱动加载、正式签名/唯一 altitude 和完整服务写回动态证据仍明确为 BLOCKED。CI 没有安装或加载该 unsigned 驱动，也没有重启、注销或触碰生产环境。

### 第四轮：激活初始化屏障（2026-09-12）

本轮先提交设计 `docs/validation/FOURTH-ROUND-DESIGN-2026-09-12.md`（`c42ea18`），再实施协议和状态机。没有修改主任务保留的未跟踪激活屏障、第三轮记录和复审文档。

- 协议由 v2 升为 v3：`BEGIN_INITIALIZE`、`COMMIT_INITIALIZE`、`ABORT_INITIALIZE` 三个固定 IOCTL；状态加入 `YCP_STATE_INITIALIZING` 和 expected/marked/failure/deadline 字段，`YCP_STATUS` 由 4264 变为 4288 字节。旧版本没有静默兼容路径。
- 用户态 `SelfProtectionCoordinator.Activate` 现在要求 preflight，顺序固定为首次 preflight → Begin → 核验 `Initializing` 且能力为空 → 第二次 preflight → Commit → 核验 `Active` 后才发布能力和映射写回条件。第二次扫描失败、Begin/Commit 应答异常或超时都尝试 Abort；稳定 Active 不会被重复 Begin 替换。
- `SelfProtectionFilePreflight` 以 `GetFileInformationByHandle` 的 `FileAttributes`、文件 ID、硬链接数为权威；路径属性只做一致性检查，并额外以真实句柄检查两个保护根的父目录。属性不一致、重解析、不可读、别名或父级异常都会阻止初始化。
- 初始化态只冻结已确认双根及严格父级的命名空间变化；未知路径、普通非命名空间 I/O、section 同步以及 paging/cache 写入不转成全局拒绝。可信服务扫描的 stream 标记失败计入驱动失败计数，Commit 不能越过该计数。
- 本地临时目录以 `mcs -sdk:4.5 -warnaserror` 编译 Core/App/Tests，C# 回归为 `73/73`；`python3 scripts/test-driver-control.py` 的原有控制/stream/pre-create/namespace 桩和新增初始化屏障桩均通过；`git diff --check` 通过。该结果不等于 WDK 编译或 Windows 动态证据。

- 本轮真实 Windows CI 已完成：分支 `codex/luna-full-delivery-20260912` 的实现提交 `b9f96f3` 对应 [GitHub Actions 运行 34659582962](https://github.com/luolisen/ycsz-ufw/actions/runs/34659582962)，运行时长约 5 分 18 秒并成功。`windows-2025-vs2026` runner 的 WDK Release x64 驱动/INF 构建、`InfVerif`、C# 编译/测试/打包、Windows PowerShell 5.1 解析与静态门禁、驱动静态门禁、维护输入校验、net48、WFP 和隔离 Windows 安全集成步骤均通过。
- 第四轮仍明确 BLOCKED：没有正式签名、唯一 altitude、安装/加载 unsigned 驱动、强制终止/挂起、已有句柄/映射/硬链接/重解析点动态阻断或重启后证据。没有生产驱动安装、加载、重启、注销、关机、账户/网络/Lenovo/SecureBoot/HVCI 变更。

### 第五轮：逐文件覆盖与初始化轮次绑定（2026-09-12）

本轮先提交设计 `docs/validation/FIFTH-ROUND-DESIGN-2026-09-12.md`（`db32aef`），再提交逐文件覆盖实现 `1fb8ed9`，并在真实 WDK 编译反馈后提交内核类型兼容修复 `761ce33`。父任务已有的三个未跟踪审查文档未暂存、未修改。

- 协议升级到 v4：Begin 携带第一次 preflight 的 manifest 数量，新增 `IOCTL_YCP_DECLARE_INITIALIZATION_ENTRY`；每项以卷序列号和 `FILE_INTERNAL_INFORMATION.IndexNumber` 固定识别，Activate/Entry/Status x64 ABI 分别为 3160/56/4296 字节。驱动使用有上限的生产哈希覆盖表，唯一声明/唯一观察才增加覆盖；重复、未知身份、flags/标记失败和容量失败不能越过 Commit。
- minifilter 在 instance setup 的 PASSIVE_LEVEL 阶段缓存卷序列号；post-create 使用实际 FileObject 的文件 ID。pre-create 同一状态快照捕获 owner `PEPROCESS` 引用、单调 generation 和 nonce，post-create 只接受该不可变快照；Abort/超时后的旧轮次回调即使延迟到新 Begin 后，也不能修改新覆盖表。generation 到 `MAXULONGLONG` 时显式拒绝新轮次，不回绕。
- 便携回归直接编译/提取生产实现：覆盖表的重复/缺口、旧轮次、多卷同 FileIndex、失败与引用释放通过；新增 round-binding 回归验证 A 轮 pre → Abort/新轮 Begin → A 轮 post 时 B 轮覆盖仍为零，同轮去重、owner 隔离、标记失败和对象引用平衡通过。`python3 scripts/test-driver-control.py` 全部通过，C# Core/App/Tests 临时目录 `74/74` 通过；`git diff --check` 与 shell 语法检查通过。
- 首次 WDK CI `34664135846` 暴露了 `<stdint.h>` 与 WDK CRT 的宏冲突及 minifilter 指针 typedef 错误；`761ce33` 修复后，最终实现 CI [34664340663](https://github.com/luolisen/ycsz-ufw/actions/runs/34664340663) 在 `windows-2025-vs2026` runner 全部通过：Release x64 WDK、InfVerif、C# 编译/测试/打包、PowerShell 解析与静态门禁、驱动验证矩阵、维护输入、net48、WFP 和 disposable Windows 安全集成。
- 仍明确 BLOCKED：CI 产物保持 unsigned；没有正式签名、唯一 altitude、安装/加载驱动、生产系统修改、重启，亦没有宣称真实终止/挂起、已有句柄写入、映射写回、硬链接/重解析点或用户会话/PID 重启动态证据。映射写回仍是显式未证明条件。
