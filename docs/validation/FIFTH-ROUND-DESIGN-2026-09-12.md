# 第五轮实施设计：初始化的逐文件覆盖证明

日期：2026-09-12。基线为 `64cfa10`，上一批真实 Windows CI `34661290471` 已成功。主任务停止源码编辑，本工作树由本轮独占；不安装或加载驱动，不改签名、altitude、生产系统或主任务已有未提交文档。

## 现状与缺口

当前 `YcpRecordInitializationStream` 只累加 `InitializationMarkedEntries`。因此同一个文件被可信服务重复打开时，计数可以超过实际覆盖集合；`Commit` 只比较数值，无法证明第二次扫描逐个观察到了第一次 preflight 的每个成员。现有 `drivers/YcszProtection/tests/initialization_lifecycle.c` 是独立模型，不能继续作为生产状态机覆盖证明。

## 覆盖证明协议

协议升级为 v4，增加 `IOCTL_YCP_DECLARE_INITIALIZATION_ENTRY`。Begin 请求携带第一次 preflight 得到的 manifest 项数；Begin 成功后，服务逐项发送固定大小的声明请求。每项由以下身份组成：

- `VolumeSerialNumber`：用户态 `GetFileInformationByHandle` 的卷序列号；
- `FileIndex`：同一真实句柄的文件索引；
- 当前初始化 nonce；
- 保留字段必须为零。

驱动为本轮初始化创建有上限的哈希覆盖表。声明阶段只允许当前已认证服务、当前 nonce、当前初始化状态；重复声明、零身份、未知 flags、超过 `YCP_MAX_INITIALIZATION_ENTRIES` 或池分配失败都会使初始化失败，不能静默覆盖或扩容到无界资源。

状态含义改为：`ExpectedEntries` 是已声明的唯一项数，`MarkedEntries` 是已被驱动观察到的唯一身份数，`Failures` 是标记/声明/身份不一致失败数，另报 `UnexpectedEntries` 与 `DuplicateEntries`。Commit 只在声明数等于请求数、唯一匹配数等于声明数、失败数和未知身份数均为零且初始化仍在 deadline 内时发布 Active。重复观察只增加 Duplicate，不增加 Marked；因此重复 A 不能填补缺失的 B。

第二次 preflight 在声明完成后执行。minifilter post-create 从实际打开的文件对象查询 `FILE_INTERNAL_INFORMATION.IndexNumber`，并从实例级缓存取得卷序列号，再把身份交给覆盖表。未匹配身份、旧初始化 nonce、旧服务进程、名称解析/真实身份查询失败均不能增加覆盖数；只有当前目标服务进程的回调可以记录。Abort、超时、服务进程退出、普通卸载和失败清理会释放整张覆盖表。

回调轮次绑定进一步由生产状态实现保证：每次 Begin 在内核锁下递增一个单调 `InitializationGeneration`；达到 `MAXULONGLONG` 时显式拒绝新轮次，不回绕。pre-create 在同一状态快照中捕获目标 `PEPROCESS` 引用、generation 和 nonce，并把它们放入 nonpaged completion context；post-create 只使用该不可变快照，在覆盖表锁内同时核对 owner、generation、nonce 和当前 deadline。Abort/超时后的旧 completion context 即使延迟到新 Begin 之后完成，也不能修改新表。completion context 分配失败或真实身份标记失败只使当前扫描无法 Commit，不把无关 I/O 变成全局拒绝；draining、失败、reparse 和普通 post 路径都释放对象引用与 nonpaged context。

用户态不以成功事件计数或用户态去重作为证明：第一次 manifest 只提供驱动要验证的成员集合，唯一匹配和重复/未知处理全部在驱动覆盖表中完成。第二次 preflight 的 `Passed` 仍是路径、属性、重解析点和硬链接检查；其扫描结果不会替代驱动逐身份观察。

## Windows API 与 IRQL 约束

`FILE_INTERNAL_INFORMATION.IndexNumber` 是文件系统的 8 字节文件引用号；它需要与卷身份组合使用，不能单独跨卷比较。依据：[FILE_INTERNAL_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_internal_information)。

卷序列号在 `InstanceSetupCallback`（PASSIVE_LEVEL）中用 `FltQueryVolumeInformation(..., FileFsVolumeInformation)` 读取并存入 `FLT_INSTANCE_CONTEXT`；post-create 只读取实例上下文，不在不确定 IRQL 下查询卷。依据：[FltQueryVolumeInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltqueryvolumeinformation)、[PFLT_INSTANCE_SETUP_CALLBACK](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_instance_setup_callback)。

文件 ID 查询沿用 `FltQueryInformationFile(..., FileInternalInformation)`，只在 PASSIVE_LEVEL 执行；不满足安全 IRQL 或查询失败时记录失败而不阻塞无关 I/O。目录也作为 manifest 成员，其文件 ID 与所在卷一并匹配；路径属性和目录根仍由用户态句柄级 preflight 验证。`FILE_STANDARD_INFORMATION.Directory` 的语义只用于需要的类型核对，不把不安全的 post-op 查询变成全局拒绝。依据：[FltQueryInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltqueryinformationfile)、[FILE_STANDARD_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_standard_information)。

## 生产代码与回归绑定

把哈希覆盖表的声明、观察、重复、未知身份、计数上限和 Commit 谓词放入驱动实际编译的 `ycsz_initialization_coverage.c/.h`；`ycsz_protection.c` 只负责锁、目标进程/nonce、池生命周期和 IOCTL，minifilter 负责产生真实身份。便携测试直接 include 该生产覆盖实现，不再复制一个独立初始化模型。

至少覆盖：

1. 重复同一个身份不能填补另一个身份缺口；补齐缺口后才可 Commit。
2. 旧覆盖表/旧初始化身份不能贡献新一轮；新一轮必须重新声明和重新观察；A 轮 pre→Abort/超时→B 轮 Begin→A 轮 post 的生产快照回归保持 B 覆盖为零。
3. 未知身份、目录/文件标志不一致、标记失败、声明重复和容量上限均阻止 Commit，但不会拒绝无关路径 I/O。
4. 多卷相同 FileIndex 不冲突；目录和普通文件都能进入 manifest。
5. Abort、超时清理和资源分配失败后不能残留成员；实际 `YcpPreOperationFile` 继续覆盖合法可信服务 CREATE、初始化限制和不相关 I/O。

本轮验证顺序：先提交本设计，再实现协议/驱动/用户态/测试与静态门禁；运行本地 C# 和生产覆盖 helper 回归、`git diff --check`、便携驱动桩；普通推送并等待真实 Windows WDK/InfVerif/PowerShell/安全集成 CI。CI 仍只构建和测试 unsigned 产物，动态签名加载、唯一 altitude、生产安装和真实终止/映射/重启矩阵继续明确 BLOCKED。
