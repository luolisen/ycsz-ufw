# YcszProtection 驱动工程

状态：源码与用户态协议已加入仓库；本机没有 Windows WDK，因此尚未完成 Windows 编译、驱动签名、安装或加载验收。该目录不会被默认应用安装器打包。

## 实现边界

- `ycsz_protection.c` 使用 Ob callbacks 处理进程句柄的创建和复制，目标同时绑定内核 `PEPROCESS`、PID、进程创建时间以及 `SeLocateProcessImageName` 得到的实际映像路径。保护期间会移除终止、挂起、设置进程信息、写入进程地址空间、复制句柄等危险权限。
- 当前激活目标是以 LocalSystem 运行的核心服务实例；交互托盘是独立用户进程，本轮没有把它登记为第二个受保护实例，也不以托盘自动恢复冒充托盘拒绝终止。
- `ycsz_minifilter.c` 使用文件系统 minifilter 处理 `IRP_MJ_CREATE`、`IRP_MJ_WRITE` 和 `IRP_MJ_SET_INFORMATION`，覆盖写入、删除、覆盖创建、截断、分配长度、重命名和链接目标。保护根目录由经过内核校验的本产品实例固定为包含 `Ycsz.exe` 的安装目录。
- 删除意图在创建阶段通过 `FILE_DELETE_ON_CLOSE`/删除访问拦截，重命名和替换在 `SET_INFORMATION` 阶段检查源与目标，保护开启前已取得的句柄在后续写入阶段仍会检查；不拦截 CLEANUP，也不能撤销之前已成功设置的删除意图。内存映射写入、内核请求和名称无法规范化的别名仍是明确的隔离验收边界。
- 设备对象仅允许 `SYSTEM` 打开。控制协议只有固定大小的激活、有限期维护、结束维护、准备卸载和状态查询操作，不提供任意 PID、任意路径或任意执行接口。
- 激活身份中的 SHA-256 由用户态服务计算并绑定到状态；当前驱动用它作为不可为空的身份字段保存，不在内核中自行重新计算文件哈希。服务必须先通过固定安装路径和实际进程对象校验，不能把任意管理员提交的摘要当成授权。
- 维护租约最长 15 分钟，过期后过滤器和句柄保护自动恢复。卸载准备是显式维护路径；普通服务停止或驱动卸载不是“被驱动拒绝”的动态验收证据。
- 卸载由 Filter Manager 回调管理，不再动态修改 `DriverUnload`。注册标志拒绝 SCM 服务停止卸载；非强制卸载在实际回调时核验有效维护租约与 PREPARE_UNLOAD。强制卸载回调不能否决，必须清理。控制设备按 FILE_OBJECT 计数，普通卸载拒绝仍有引用的连接，CLEANUP 不提前释放引用；强制卸载与实际 Windows I/O 完成并发仍未验收，不能据此安装到生产。应用尚未接入 PREPARE_UNLOAD。

当前实现明确不声称防御内核句柄、离线磁盘修改、已加载的其他内核代码、所有重解析点/硬链接别名或管理员通过合法系统维护路径进行的操作。文件名解析失败时不阻断未知别名，以免把名称缓存失败误变成系统级死锁；隔离 Windows 验收必须专门覆盖这些边界。

当前协议只有一个 `ProtectedRoot`，实际绑定为包含 `Ycsz.exe` 的安装目录；`ProgramData\YcszFirewall` 的配置、日志和基线不在本轮 minifilter 根目录内，继续依赖现有 ACL/应用恢复路径，不能把它们写成已通过内核防删除。

## WDK 构建

需要 Windows 10/11 x64、Visual Studio 的 Desktop C++ 工具、Windows 10/11 WDK 以及与目标系统匹配的驱动签名渠道。开发机必须使用官方 WDK 工具链，不得通过关闭 Secure Boot/HVCI、启用测试签名或加载未签名驱动绕过验证。

在 **x64 Native Tools Command Prompt for VS** 中，从仓库根目录执行：

```text
msbuild drivers\YcszProtection\YcszProtection.vcxproj /p:Configuration=Release /p:Platform=x64 /m
```

工程输出应位于 `artifacts\driver\Release\`。构建成功只代表编译和包目录生成；还必须单独记录编译器、WDK、INF/CAT、签名、安装、加载、重启和隔离靶场结果。当前仓库没有这些 Windows 输出。

## 卸载与维护

正常更新/卸载流程必须先由已认证的服务实例通过 `IOCTL_YCP_ENTER_MAINTENANCE` 获得短租约，在租约内完成必要文件操作，并在结束时发送 `IOCTL_YCP_EXIT_MAINTENANCE`。驱动不会把“管理员”本身当作维护授权，也不会把 SCM 的普通 Stop 当成已授权维护。现有安装器和更新脚本尚未默认安装该驱动，也尚未宣称已经完成这条 Windows 动态流程。

INF 中的 minifilter altitude `385200.1234` 只是源码阶段占位值；提交给 Windows 运行前必须取得正式、唯一且与发布签名相配套的 altitude，并重新生成 CAT 和签名材料。

## 信任配置与停服流程（源码阶段，未部署）

驱动现在要求 Session 0、LocalSystem、启用的 `NT SERVICE\YcszFirewall` 服务 SID，以及安装阶段预置的完整 NT 映像路径同时匹配。路径来自 `Services\YcszProtection\Parameters\TrustedImagePath`（REG_SZ，以 `\Device\` 开头），在驱动加载时读取并固定；缺失或格式不合法时加载失败。IOCTL 不能设置此信任路径。

**安装器尚未提供上述配置。** 正式集成必须核验服务映像与发布包、配置产品服务 SID，并在隔离 Windows 上核对 SID 常量、NT 路径、错误账户/错误映像拒绝与服务重启后的重新绑定。这里没有执行配置、安装或加载命令。管理员更改服务注册信息、替换可信文件、注册表保护与代码签名验证仍需独立解决，不能把这些条件当作完整的管理员防破坏保证。

应用在进入 ServiceBase.Run 前，根据产品驱动服务是否已注册固定 CanStop。已注册时 SCM Stop 始终不开放；通过已登录管理页进入维护后，使用“维护停止本机服务”。服务先发送回复，再核验当前租约并内部停止。不可在服务运行中临时添加驱动注册后期待其停止权限自动改变；正式安装应先停应用服务、配置驱动，再启动应用服务。未注册驱动时保留普通服务停止与现有更新流程。

这些变更只经过 macOS 上的 C# 编译/回归；SCM 停服和驱动行为均尚未通过 Windows 动态测试。

便携控制生命周期检查：`python3 scripts/test-driver-control.py` 从真实 C 源码提取 CREATE/CLOSE 与卸载门禁函数进行桩测试。它验证顺序状态转换，不模拟内核线程、IRQL、I/O manager 或真实卸载；必须另外通过 WDK 和隔离 Windows 检查。
