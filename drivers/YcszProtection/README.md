# YcszProtection 驱动工程

状态：源码与用户态协议已加入仓库，Windows CI 已完成 WDK Release x64 构建及 InfVerif；最近已核实的代码提交 `9b3d291` 对应 [CI 34665735872](https://github.com/luolisen/ycsz-ufw/actions/runs/34665735872)，结果成功。产物仍未签名，未完成驱动安装、加载或动态验收。该目录不会被默认应用安装器打包。

## 实现边界

- `ycsz_protection.c` 使用 Ob callbacks 处理进程句柄的创建和复制，目标同时绑定内核 `PEPROCESS`、PID、进程创建时间以及 `SeLocateProcessImageName` 得到的实际映像路径。保护期间会移除终止、挂起、设置进程信息、写入进程地址空间、复制句柄等危险权限。
- 当前激活目标是以 LocalSystem 运行的核心服务实例；交互托盘是独立用户进程，本轮没有把它登记为第二个受保护实例，也不以托盘自动恢复冒充托盘拒绝终止。
- `ycsz_minifilter.c` 使用文件系统 minifilter 处理 `IRP_MJ_CREATE`、`IRP_MJ_WRITE` 和 `IRP_MJ_SET_INFORMATION`，覆盖写入、删除、覆盖创建、截断、分配长度、重命名和链接目标。保护范围由经过内核校验的本产品实例固定为包含 `Ycsz.exe` 的安装根和可信 `ProgramData` 根。
- 删除意图在创建阶段通过 `FILE_DELETE_ON_CLOSE`/删除访问拦截，重命名和替换在 `SET_INFORMATION` 阶段检查源与目标，保护开启前已取得的句柄在后续写入阶段仍会检查；不拦截 CLEANUP，也不能撤销之前已成功设置的删除意图。内存映射写入、内核请求和名称无法规范化的别名仍是明确的隔离验收边界。
- 设备对象仅允许 `SYSTEM` 打开。控制协议只有固定大小的双阶段初始化、有限期维护、结束维护、准备卸载和状态查询操作，不提供任意 PID、任意路径或任意执行接口。
- 激活身份中的 SHA-256 由用户态服务计算并绑定到状态；当前驱动用它作为不可为空的身份字段保存，不在内核中自行重新计算文件哈希。服务必须先通过固定安装路径和实际进程对象校验，不能把任意管理员提交的摘要当成授权。
- 维护租约最长 15 分钟，过期后过滤器和句柄保护自动恢复。卸载准备是显式维护路径；普通服务停止或驱动卸载不是“被驱动拒绝”的动态验收证据。
- 卸载由 Filter Manager 回调管理，不再动态修改 `DriverUnload`。注册标志拒绝 SCM 服务停止卸载；非强制卸载在实际回调时核验有效维护租约与 PREPARE_UNLOAD。强制卸载回调不能否决，必须清理。控制设备按 FILE_OBJECT 计数，普通卸载拒绝仍有引用的连接，CLEANUP 不提前释放引用；强制卸载与实际 Windows I/O 完成并发仍未验收，不能据此安装到生产。应用尚未接入 PREPARE_UNLOAD。

当前实现明确不声称防御内核句柄、离线磁盘修改、已加载的其他内核代码、所有重解析点/硬链接别名或管理员通过合法系统维护路径进行的操作。文件名解析失败时不阻断未知别名，以免把名称缓存失败误变成系统级死锁；隔离 Windows 验收必须专门覆盖这些边界。

当前协议同时绑定 `ProtectedRoot` 和 `ProtectedDataRoot`，实际分别对应包含 `Ycsz.exe` 的安装目录与可信 `ProgramData\YcszFirewall` 根；其它目录、未解析名称和内核请求仍不在 minifilter 的成功保证范围内。

## WDK 构建

需要 Windows 10/11 x64、Visual Studio 的 Desktop C++ 工具、Windows 10/11 WDK 以及与目标系统匹配的驱动签名渠道。开发机必须使用官方 WDK 工具链，不得通过关闭 Secure Boot/HVCI、启用测试签名或加载未签名驱动绕过验证。

在 **x64 Native Tools Command Prompt for VS** 中，从仓库根目录执行：

```text
msbuild drivers\YcszProtection\YcszProtection.vcxproj /p:Configuration=Release /p:Platform=x64 /m
```

工程输出应位于 `artifacts\driver\Release\`。构建成功只代表编译和包目录生成；还必须单独记录编译器、WDK、INF/CAT、签名、安装、加载、重启和隔离靶场结果。Windows CI 提供未签名的构建产物；它们不是可直接用于生产部署的正式驱动。

## 卸载与维护

正常更新/卸载流程必须先由已认证的服务实例通过 `IOCTL_YCP_ENTER_MAINTENANCE` 获得短租约，在租约内完成必要文件操作，并在结束时发送 `IOCTL_YCP_EXIT_MAINTENANCE`。驱动不会把“管理员”本身当作维护授权，也不会把 SCM 的普通 Stop 当成已授权维护。现有安装器和更新脚本尚未默认安装该驱动，也尚未宣称已经完成这条 Windows 动态流程。

INF 中的 minifilter altitude `385200.1234` 只是源码阶段占位值；提交给 Windows 运行前必须取得正式、唯一且与发布签名相配套的 altitude，并重新生成 CAT 和签名材料。

## 信任配置与停服流程（源码阶段，未部署）

驱动现在要求 Session 0、LocalSystem、启用的 `NT SERVICE\YcszFirewall` 服务 SID，以及安装阶段预置的完整 NT 映像路径同时匹配。路径来自 `Services\YcszProtection\Parameters\TrustedImagePath`（REG_SZ，以 `\Device\` 开头），在驱动加载时读取并固定；缺失或格式不合法时加载失败。IOCTL 不能设置此信任路径。

`scripts/Install-Protection.ps1` 已实现服务 SID、TrustedImagePath 和 TrustedDataRoot 配置及回读核验；仍须在可加载正式签名驱动的隔离 Windows 上验收 SID、NT 路径、错误账户/错误映像拒绝与服务重启后的重新绑定。这里没有执行配置、安装或加载命令。管理员更改服务注册信息、替换可信文件、注册表保护与代码签名验证仍需独立解决，不能把这些条件当作完整的管理员防破坏保证。

应用在进入 ServiceBase.Run 前，根据产品驱动服务是否已注册固定 CanStop。已注册时 SCM Stop 始终不开放；通过已登录管理页进入维护后，使用“维护停止本机服务”。服务先发送回复，再核验当前租约并内部停止。不可在服务运行中临时添加驱动注册后期待其停止权限自动改变；正式安装应先停应用服务、配置驱动，再启动应用服务。未注册驱动时保留普通服务停止与现有更新流程。

这些变更已经过本地 C# 回归和 Windows CI 构建/隔离检查；已加载驱动下的 SCM 停服和驱动行为仍未通过动态验收。

便携控制生命周期检查：`python3 scripts/test-driver-control.py` 从真实 C 源码提取 CREATE/CLOSE 与卸载门禁函数进行桩测试。它验证顺序状态转换，不模拟内核线程、IRQL、I/O manager 或真实卸载；必须另外通过 WDK 和隔离 Windows 检查。

## 第二轮协议与验收（2026-09-12）

第二轮把共享协议升级为 v2：激活请求同时绑定安装根和 `TrustedDataRoot`，状态包含双根和核心/托盘身份，固定 x64 大小为 16/1088/3152/1104/40/32/4264。可信配置由安装器写入 `TrustedImagePath` 与 `TrustedDataRoot`；驱动拒绝旧版本、非精确长度和未配置的 ProgramData 根。

服务通过固定设备路径登记真实用户 session 的托盘实例。驱动只接受已激活的核心服务调用，并重新查验托盘 PID、创建时间、token session、实际映像路径、实例摘要/nonce；保存 `PEPROCESS` 引用，旧进程退出或 session 切换后不能把保护转移给 PID 重用的进程。服务监督器在启动、采用、退出、切换和停机时登记/注销，登记失败不把托盘当作已保护实例继续运行。

文件过滤覆盖双根的已有句柄写入、变更信息、可写 section/cache 映射和 reparse FSCTL。重解析点 FSCTL 对非可信写入者整体拒绝，以免仅凭未解析的目标缓冲区留下别名绕过；受保护变更必须来自已登记核心服务进程。普通 SYSTEM、管理员、用户进程和无法识别的内核请求没有通用豁免。维护租约只暂停进程句柄保护，文件过滤继续存在，准备卸载后才允许真正卸载。

`scripts/Test-ProtectionDriver.ps1 -Mode Static` 在 CI 中检查上述源码、协议、ABI 和缺口；`-Mode Dynamic` 只接受带 `.ycsz-dynamic-fixture` 标记的隔离根、已激活的签名驱动和明确的临时环境。它对已有句柄、映射、硬链接、重解析点、根目录和控制句柄并发卸载输出 `PASS`/`FAIL`/`BLOCKED`，未能制造普通 SYSTEM token、真实 session 重启或正式签名/altitude 时必须输出 `BLOCKED`，不能扩大 unsigned CI 结论。

## 第四轮初始化屏障（2026-09-12）

协议已升级为 v3。服务先发送 `IOCTL_YCP_BEGIN_INITIALIZE`，驱动进入 `YCP_STATE_INITIALIZING`，此时不报告 `ACTIVE`，只对已确认的安装根和 ProgramData 根及其严格父级执行受限命名空间守卫；未知路径、普通非命名空间 I/O、section 同步、paging/cache 写入不被全局拒绝。服务随后重新执行句柄级 preflight，并由成功的 CREATE post-operation 为可信服务扫描确认 stream；任何 stream 标记失败都会增加初始化失败计数。

只有 `IOCTL_YCP_COMMIT_INITIALIZE` 在 deadline 内看到无失败且 marked stream 数覆盖第二次扫描的 expected entries 时才发布 `ACTIVE`；扫描失败、应答丢失、服务进程退出或 120 秒超时通过 `IOCTL_YCP_ABORT_INITIALIZE` 或下一次 Begin 清理初始化上下文。稳定 `ACTIVE` 实例不会被新的 Begin 替换，旧 v2 请求也不会静默按新语义处理。状态 ABI 变为 4288 字节。

`scripts/test-driver-control.py` 现在还编译 `drivers/YcszProtection/tests/initialization_lifecycle.c`，覆盖 Begin 未提前发布 Active、失败计数阻止 Commit、Abort 清理、稳定 Active 不被替换、命名空间边界和超时恢复。该桩与 C# 73/73 回归只能证明便携状态/协议逻辑；WDK 编译、正式签名/唯一 altitude、安装/加载及真实 Windows 动态阻断仍必须在隔离 Windows 完成。

## 第五轮逐文件覆盖证明（2026-09-12）

协议已升级为 v4。第一次句柄级 preflight 生成固定上限的唯一 manifest，服务在 `BEGIN_INITIALIZE` 后逐项发送 `IOCTL_YCP_DECLARE_INITIALIZATION_ENTRY`；驱动以卷序列号和 `FILE_INTERNAL_INFORMATION.IndexNumber` 建立本轮期望集合。第二次 preflight 的可信服务 CREATE post-operation 从真实文件对象取得同一身份并只标记匹配的未观察成员；重复观察不增加 `MarkedEntries`，未知身份、身份查询失败和声明失败阻止 Commit。

卷序列号在 minifilter `InstanceSetupCallback` 的 PASSIVE_LEVEL 阶段缓存到 instance context，post-create 不在不确定 IRQL 下查询卷信息。`YCP_MAX_INITIALIZATION_ENTRIES` 为明确资源上限；Abort、超时、服务退出和卸载释放覆盖表。`initialization_lifecycle.c` 直接 include 驱动实际的 `ycsz_initialization_coverage.c`，覆盖重复/缺口、旧轮次、多卷相同 FileIndex、失败和上限，不再使用独立状态模型冒充生产实现。

post-create 的覆盖记账另绑定 pre-create 捕获的目标 `PEPROCESS` 引用、单调初始化 generation 和 nonce；旧轮次在 Abort/超时后延迟完成，也不能向新轮次覆盖表记账。completion context 分配失败或实际身份标记失败只让当前轮次无法提交，draining/reparse/失败路径均释放引用和上下文，不把缺少上下文扩大为无关 I/O 的全局拒绝。新增便携回归直接提取生产快照/记账函数，验证旧轮拒绝、同轮去重、owner 隔离、失败和引用平衡。

## 初始化超时与资源回收的实际语义

初始化超时或目标进程退出后，状态查询立即按无效初始化报告，初始化限制不再生效。当前没有定时清理线程：覆盖表和目标引用在认证 Abort、下一次 Begin 替换失效初始化或驱动卸载时释放；单次表容量有上限，不能描述为到期立即释放。稳定 Active 不因初始化期限而撤销。延迟完成的回调保留各自引用直至回调清理，旧 generation/nonce 不能贡献新轮覆盖。仍需在可加载的隔离 Windows 中验证长时间挂起 I/O、取消与卸载的并发资源回收。
