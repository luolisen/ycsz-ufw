# 第三轮细化设计：文件身份、合法写回与完整升级回滚

日期：2026-09-12。基线：`5057690`；必须保留 `bf7fa4c` 与 `5057690`。本设计只针对隔离源码、便携测试和 Windows CI，不安装生产驱动，不调整签名安全设置，不重启/注销。

## 1. 保护边界与不变量

1. 只把已确认属于 YCSZ 安装根或 ProgramData 根的文件标记为产品对象；未知路径、名称解析失败和普通系统缓存请求继续放行，不使用 `STATUS_ACCESS_DENIED` 伪造拒绝。
2. 通过 Filter Manager stream context 绑定文件对象的稳定流身份；context 保存 `FILE_INTERNAL_INFORMATION.IndexNumber` 和产品标记。路径仅用于首次确认命名空间，后续已有句柄、别名和重命名后的同一流优先使用 context。
3. 激活前由服务执行只读 preflight：遍历两个根，拒绝根/子项重解析点、无法读取身份的项、文件硬链接计数大于一和同一卷文件身份对应多个产品路径（硬链接/别名）。失败返回逐项原因，不能进入 Active。
4. 新的重命名/硬链接/重解析点只允许保持在已确认产品命名空间内；可信服务可更新文件内容，但不能借可信写入者创建逃逸别名。未知目录的普通重解析操作不受影响。
5. `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`、paging write、Cache Manager/Modified Page Writer 回调不作为拒绝入口；可写映射只有在激活 preflight 通过、目标流已有产品 context、请求属于合法服务写回且目标仍在产品命名空间时才报告启用，否则状态明确报告 `MappingProtectionUnavailable`，不声称映射阻断。

## 2. 内核身份/context 设计

- 增加 `YCP_STREAM_CONTEXT` 和 Filter Manager context registration。post-create 在成功打开后查询规范化名称；若属于保护根，则查询 `FileInternalInformation`，创建/保留 stream context。context cleanup 只清理非分页池对象，不持有易失的路径指针。
- pre-operation 先从 `FltGetStreamContext` 获取实际流身份，再用名称作为未建立 context 时的首次判定。源文件和目标文件分别记录 `Resolved/Protected`；已保护源但目标无法解析的命名空间重写按产品操作拒绝，未知文件仍放行。
- 修改、删除、截断、重命名、硬链接使用 context + 目标名称判定；可信服务只绕过普通内容写入，不能绕过产品别名/重解析逃逸规则。context 随流删除而失效，重新创建的同路径文件必须重新建立身份。
- 卷分离、文件删除重建、文件 ID 重用由 stream context 生命周期隔离；同一 context 不跨新流复用。动态工具用产品/非产品对照验证这些分支。

## 3. 用户态激活 preflight 与可写映射状态

- 新增独立的 `SelfProtectionFilePreflight`（Windows 句柄身份 API）和结果对象：根存在性、重解析项、无法读取项、硬链接计数、重复 `(VolumeSerial, FileIndex)`、扫描计数；结果可序列化到日志/状态。
- `SelfProtectionCoordinator.Activate` 在发送激活 IOCTL 前执行 preflight；失败状态为 Failed/Unavailable，保留逐项错误，绝不调用 Activate。已有四参数构造器保持兼容，生产 HostService 注入真实 preflight，测试注入 fixture preflight。
- `YCP_STATUS`/用户态状态新增只读映射启用条件字段或能力位；只有 preflight 通过且服务写回路径满足条件才报告映射能力。内核不通过缓存回调拒绝合法后台写回。
- 动态工具覆盖：非产品文件正常写、产品已有句柄写失败、别名/硬链接/重解析逃逸失败、产品根内合法服务写回成功；不能制造身份时输出 BLOCKED。

## 4. 安装包 delta 与升级回滚状态机

阶段固定为：`Preflight` → `Capture` → `Quiesce` → `SnapshotAfterInstall` → `ValidateNewPackage` → `WriteTrust` → `Load` → `ProbeActivation` → `Commit`。

- 用 `Get-WindowsDriver -Online` 的结构化对象快照比较安装前后，仅接受 Provider/Class/INF/CAT 完全匹配的 YCSZ 包；不再解析 `pnputil` 英文 `Published Name`。安装前后新增/消失集合和原有包集合写入事务日志。
- 已有 YCSZ 包时，变更前必须成功导出并验证可恢复的旧包、旧信任值、旧 SID 类型、应用运行状态；无法导出或验证则在 `Quiesce` 前拒绝升级。
- `pnputil` 返回错误后仍重新读取包清单；若部分安装成功，只处理清单中本次新增且已确认属于 YCSZ 的包。其他厂商包、原有 YCSZ 包和未确认对象永不删除。
- 任一安装/加载/激活/卸载拒绝/恢复失败均先确认应用与驱动 quiescent；不能停稳则保持所有信任、服务注册、驱动包和应用文件不变并报告人工维护动作。停稳后才恢复旧包/信任/SID/应用状态。
- Commit 后才清理临时旧包备份；回滚失败保留备份和事务日志，不声称成功。正常更新沿用认证维护和 PREPARE_UNLOAD，不开 SCM 旁路。

## 5. 测试矩阵与完成条件

- 便携 C#：身份 preflight 的空根、重解析、重复 FileIndex、无法读取、删除重建、路径大小写和正常树；协调器失败时不得调用 transport。
- 便携 PowerShell：包 delta（零/一/多新增、部分失败、原包保留）、六个故障注入点（修改前、安装、加载、激活、卸载拒绝、恢复失败）及 quiescent gate。
- Windows CI：WDK/InfVerif、全部现有回归、静态源门禁；Dynamic 只在显式隔离 fixture + 签名加载条件满足时运行，否则逐项 BLOCKED。
- 交接时必须报告最终 commit、CI URL、每项 PASS/BLOCKED、未覆盖的正式签名/唯一 altitude/真实动态项目；不得把 unsigned CI 或静态关键词检查写成生产阻断证据。
