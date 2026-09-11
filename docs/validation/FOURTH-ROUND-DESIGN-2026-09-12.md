# 第四轮设计：受限初始化与 Active 确认

日期：2026-09-12。基线：`ea132a8`。本轮保留 `b650132`、`ea132a8` 以及此前的 quiescent、stream context、paging/cache compatibility 和升级回滚修复。只在隔离源码/测试/CI中实施，不安装或加载生产驱动，不修改签名安全设置，不重启、注销或关机。

## 1. 要关闭的竞态与不变量

现有流程是用户态 preflight 完成后直接发送 Activate；扫描完成与驱动开始保护之间存在窗口。第四轮不把第二次扫描当作唯一证明，而是让驱动先进入受限初始化态，在初始化态冻结已确认双根的命名空间，再完成第二次扫描和 stream 标记，最后由同一可信服务显式 Commit。

必须始终成立：

1. `Initializing` 不是 `Active`。初始化期间不报告进程/文件保护能力或映射写回条件；用户态状态只能是 `Starting`/`Initializing`/`Failed`，不能显示“已启用”。
2. 初始化态只守护已确认安装根、ProgramData 根及其严格祖先的命名空间变化：受保护路径的创建/替换/删除、重命名、硬链接和重解析逃逸由现有精确路径/context 规则处理；未知路径、无关系统 I/O、section synchronization 和 paging/cache write 继续放行。
3. 初始化成功的必要条件是：固定服务身份仍匹配；初始化租约未超时；二次扫描的真实句柄属性一致；没有重解析/不可读/硬链接别名；服务扫描涉及的每个产品项都成功建立或确认 stream context；驱动记录的 context 标记失败数为零；Commit 请求的扫描计数满足驱动记录。
4. 只有 Commit 成功并且 QueryStatus 返回 `ACTIVE` 后，用户态才发布 Active 和文件/进程能力。Commit、Abort、超时和进程退出不会把旧的稳定 Active 实例降级；新的 Begin 在旧实例仍存活时返回 busy。

## 2. v3 协议与状态机

协议从 v2 升为 v3，旧请求不得静默按新语义处理。新增：

- `YCP_STATE_INITIALIZING`；状态结构增加 initialization expected/marked/failure counters 和固定 deadline，ABI 由 4264 变为 4288 字节。
- `IOCTL_YCP_BEGIN_INITIALIZE`（复用固定身份与双根的 activate payload）：验证 LocalSystem/service SID、实际映像、固定根后保存目标身份和根，但设置 `Initializing=TRUE`、`Active=FALSE`。
- `IOCTL_YCP_COMMIT_INITIALIZE`：固定大小请求携带 expected scan count、保留字段和当前 service `InstanceNonce`；只允许当前初始化服务调用，检查 deadline、失败数、marked count 和 nonce，然后原子地 `Initializing=FALSE; Active=TRUE`。
- `IOCTL_YCP_ABORT_INITIALIZE`：固定大小请求携带 header 和 nonce；只清理当前初始化态，不得清理稳定 Active 实例。Abort 可在二次扫描失败、Commit/应答失败时由同一服务调用。
- `YCP_INITIALIZATION_TIMEOUT_SECONDS` 固定为有限窗口；不从用户请求接受任意延长值。过期初始化不再参与文件守卫，新的可信 Begin 可以回收已退出/已过期的旧初始化上下文。

用户态 `SelfProtectionCoordinator.Activate` 的事务是：

`初始 preflight → BeginInitialize → Initializing 应答确认 → 二次 preflight（真实句柄扫描并触发 stream 标记） → CommitInitialize → Active 应答确认 → 发布 Active`。

Begin/Commit/Abort 都绑定同一个服务进程身份和 `InstanceNonce`。重复 Active 调用保持已有稳定实例；初始化中的重复调用不产生第二个目标；不同活跃实例返回 busy；服务进程退出或初始化超时由驱动拒绝旧请求并允许新实例恢复。任何 transport 异常先尝试 Abort，Abort 失败也只进入 Failed/超时恢复，不伪造 Active。

## 3. 真实句柄与 stream 标记

`SelfProtectionFilePreflight.ReadIdentity` 不再把 `File.GetAttributes` 作为最终事实：

- 用 `CreateFile` + `FILE_FLAG_OPEN_REPARSE_POINT` 打开每个根/项，`GetFileInformationByHandle` 返回的 `FileAttributes` 决定目录和重解析属性；路径 API 的属性只作一致性比较。
- handle 属性与路径观察不一致、句柄身份不可读、重解析、硬链接数大于一或重复 `(VolumeSerial, FileIndex)` 均失败。根的每个父组件也用真实句柄检查，父组件重解析或不可读不能作为固定根使用；父组件不计入产品 stream expected count。
- 二次扫描发生在 `Initializing` 期间。成功的可信服务 CREATE post-operation 为产品项建立/确认 `FLT_STREAM_CONTEXT`，context 保存 `FileInternalInformation.IndexNumber`；Filter Manager 不支持或 context 分配/设置失败由驱动递增 initialization failure counter。
- 驱动只统计当前初始化目标服务对产品项的标记尝试，重复已有 context 也必须得到成功确认。Commit 要求 failure counter 为零且 marked count 覆盖用户态真实扫描计数；不满足则拒绝 Commit 并保持非 Active。

可信服务在初始化期间只需要读取/打开并标记身份；普通内容写入仍按现有 trusted-writer 规则处理，不能借初始化态绕过 namespace guard。删除重建、卷分离和 File ID 重用依赖 stream context 生命周期，重新打开的新流必须重新标记；旧服务的 context 不得单独使新服务获得 Commit 权限。

## 4. 失败、超时与恢复

- 初始或二次扫描失败：不发送 Commit；发送绑定 nonce 的 Abort；状态 Failed，mapping 条件为 false。
- Begin 返回丢失/应答不属于 Initializing：不发布能力，尝试 Abort；不能证明 Abort 成功时依赖固定初始化 deadline，服务重启后由新 Begin 回收已过期上下文。
- Commit 返回失败/丢失：不发布 Active；尝试 Abort；稳定 Active 实例不会被该事务触碰。
- 服务进程在初始化期间退出：驱动的目标进程身份检查使旧 Commit/Abort 失效；到 deadline 后释放初始化保护上下文，新服务以新 PID/创建时间/nonce重新 Begin。进程退出不把初始化误报为 Active。
- Active 实例的维护租约、退出和强制卸载语义不变；本轮不通过 Abort/超时终止已有效 Active 实例，也不开放 SCM Stop 或全局 I/O 拒绝。

## 5. 测试与验收

便携 C# 测试覆盖：Begin 返回 Initializing 而非 Active、二次扫描失败后 Abort 且状态 Failed、Commit 后才 Active、Commit/Abort transport 异常、重复/旧实例和 mapping 条件保持 false。协议 ABI 测试覆盖 v3 状态/请求尺寸与初始化 status decode。

便携/本地 C 桩覆盖：初始化状态转移、expected/marked/failure 计数、nonce/旧 PID/超时拒绝，以及成功/失败/Abort 不残留错误权限。PowerShell/静态门禁检查 v3 协议消费者、真实 handle 属性字段、初始化守卫和禁止旧 v2 兼容。

真实 Windows CI 必须通过 WDK Release、InfVerif、C#/PowerShell 回归与静态驱动矩阵。正式签名、唯一 altitude、隔离 Windows 上的 driver load、已有句柄/别名/映射/服务写回动态证据仍按 BLOCKED 单列；不能用 unsigned CI、关键词或拒绝 paging write 代替这些证据。
