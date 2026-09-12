# 完整交付九项最终差距审计

日期：2026-09-13  
范围依据：`docs/LUNA-FULL-DELIVERY-2026-09-12.md:14-24`  
审计工作树：`codex/luna-full-delivery-20260912`  
可复核 CI：[`34713169738`](https://github.com/luolisen/ycsz-ufw/actions/runs/34713169738)，对应提交 `6de1bb86f7115ea674f18d08208fa0a8c97e2d7c`。该运行通过，但仍按脚本输出保留 `BLOCKED`；CI 不是正式签名、驱动加载或生产验收证据。

## 结论口径

本轮已完成源码、用户态协议、静态门禁、隔离临时目录边界和动态验收夹具的准备；没有安装或加载未验证驱动，没有修改生产服务，没有重启系统。产品的“防强制结束/防删除”不能在正式签名驱动、唯一 altitude 和隔离 Windows 动态证据缺失时标记为完成。

状态含义：

- `已验证`：有当前 CI 或便携测试的直接结果，但不扩大到未覆盖的 Windows 内核语义。
- `部分完成`：源码和独立测试准备存在，仍有真实 Windows、签名、部署或运行时缺口。
- `BLOCKED`：当前环境或合法外部条件不足，脚本必须保留未覆盖状态；不是失败，也不是已完成。

## 九项审计

### 1. 完整 Windows 驱动构建

- 要求：真实 WDK 编译、INF/SYS/日志、签名、CAT 和 altitude 实际状态。
- 位置：`drivers/YcszProtection/YcszProtection.vcxproj`、`drivers/YcszProtection/YcszProtection.inf`、`.github/workflows/windows-build.yml:21-58`、`drivers/YcszProtection/README.md:20-36`。
- 证据：CI `34713169738` 的 WDK Release x64 步骤生成 `YcszProtection.sys`、stamped INF 和 CAT；同一运行的 `InfVerif` 输出 `INF is VALID`。`Test-ProtectionDriver -Mode Static` 的源码/ABI/安装回滚门禁无 `FAIL`。
- 状态：**部分完成**。
- 未完成/阻塞：CI 明确是 unsigned driver 流程；`YcszProtection.inf` 的 `385200.1234` 仍是占位 altitude。没有正式、唯一 altitude、适配目标系统的签名 CAT/驱动，也没有安装/加载结果，因此不能交付生产驱动。

### 2. 核心服务进程保护

- 要求：阻断终止、挂起和提升工具危险句柄；固定真实实例，处理 PID 重用、创建时间和重绑定。
- 位置：`drivers/YcszProtection/ycsz_protection.c:275-304,753-849,1732-1763`；`src/Ycsz.Core/SelfProtection.cs:231-275`；`src/Ycsz.Core/SelfProtectionDeviceTransport.cs:252-298`。
- 证据：Ob callback 同时处理新建/复制句柄并移除 `PROCESS_TERMINATE`、`PROCESS_SUSPEND_RESUME` 等权限；目标按 `PEPROCESS`、PID、创建时间和退出状态匹配。CI 的 C# 回归为 `75/75`，便携 pre-operation 桩为 `16` 组通过，静态矩阵检查通过。
- 状态：**部分完成**。
- 未完成/阻塞：没有在加载该驱动的隔离 Windows 中用标准用户和提升工具实际发起终止/挂起并证明 PID 不变；PID 重用、服务重启重绑定和真实 Ob callback 仍属于动态门槛。

### 3. 文件保护与清理边界

- 要求：安装目录和配置/基线根防删除、重命名、替换、截断、写入，覆盖已有句柄、映射、硬链接、重解析点和目录自身删除。
- 位置：`drivers/YcszProtection/ycsz_minifilter.c:296-319,432-575,657-679`；`drivers/YcszProtection/README.md:9-18`；`scripts/Protection-Validation.ps1:144-182,398-473`；`scripts/Test-ProtectionFixtureBoundary.ps1:122-237`。
- 证据：minifilter 源码覆盖 `IRP_MJ_CREATE`、`IRP_MJ_WRITE`、`IRP_MJ_SET_INFORMATION` 和文件系统控制请求，并区分双根、可信写入者、流上下文和 reparse。fixture 清理现按同一 `DELETE | FILE_READ_ATTRIBUTES` 句柄读取身份，并用 `SetFileInformationByHandle(FILE_DISPOSITION_INFO)` 处置；受控替换回归验证旧句柄不会处置替代对象。CI 输出 `22 fixture-boundary integration checks`，无服务、驱动或系统配置改动。
- 状态：**部分完成**。
- 未完成/阻塞：这是 Windows 临时目录和源代码边界证据，不是 minifilter 已加载后的运行证据。CI 静态矩阵仍将 pre-existing writable mappings、termination/mapping/link runtime evidence 和 two-phase dynamic harness 标为 `BLOCKED`；真实缓存映射、已有句柄写入、防删除/重命名/替换和受保护根目录本身仍需隔离 Windows 动态验收。

### 4. 托盘与恢复

- 要求：学生端托盘可恢复；核心服务异常退出由 SCM 恢复；托盘若要防结束必须单独验收。
- 位置：`src/Ycsz.App/Program.cs:154-184,236-265`；`src/Ycsz.App/TrayLifecycle.cs`；`src/Ycsz.Core/SelfProtection.cs:293-316`；`scripts/Test-Security.ps1:76-116`；`README.md:69-89`。
- 证据：托盘监督器有会话切换、唯一实例、退出后重启和驱动登记/注销路径；服务设置 SCM failure actions 并在隔离 Windows 安全测试中通过服务重启/持久化检查。C# 回归覆盖托盘恢复、采用已有实例、会话退出释放、启动退避和维护停服不重启。
- 状态：**部分完成**。
- 未完成/阻塞：核心服务恢复与托盘监督逻辑有测试，但没有已加载驱动的真实托盘终止阻断证据。当前设计只在驱动确认后登记托盘，不以恢复行为冒充“托盘不可结束”；托盘动态保护仍未验收。

### 5. 安装、信任和服务身份

- 要求：固定服务 SID、Session 0、LocalSystem、完整可信 NT 映像路径；配置、验证、失败回滚和更新顺序完整。
- 位置：`scripts/Install-Protection.ps1:80-189,190-260`；`scripts/Test-ProtectionDriver.ps1:517-595`；`src/Ycsz.App/Program.cs:134-150`；`drivers/YcszProtection/ycsz_protection.c:740-805`。
- 证据：安装脚本已实现 `TrustedImagePath`、`TrustedDataRoot`、服务 SID、driver-store 包快照、CAT 成员核验、停止顺序和失败回滚；动态前置检查严格要求 `Win32_Service` 的 `YcszFirewall` 为 `LocalSystem`、精确 `--service` 映像、Stopped/Running 阶段和 Session 0。CI 隔离安全检查通过 LocalSystem、自动启动和引号路径检查。
- 状态：**部分完成**。
- 未完成/阻塞：没有执行真实安装脚本、签名驱动加载、错误账户/错误映像拒绝和更新回滚的动态验证；安装器默认不生成/打包未验证驱动。服务自报或静态存在的路径不能替代代码签名和实际信任验证。

### 6. 维护、升级、卸载闭环

- 要求：认证会话和短租约、PrepareUnload、控制连接关闭、FilterUnload、结果核验、应用停服/恢复及租约过期撤销。
- 位置：`src/Ycsz.Core/SelfProtection.cs:318-407`；`src/Ycsz.App/Program.cs:186-249`；`src/Ycsz.Core/SelfProtectionDeviceTransport.cs:120-143,281-298`；`drivers/YcszProtection/ycsz_protection.c:1277-1310,1705-1729`。
- 证据：用户态已接入 `self-protection-prepare-unload`；维护窗口上限 15 分钟，停服派发前重新核验会话/租约，失败状态保留租约并允许到期重试。便携生命周期测试 `6` 组通过，C# `75/75` 通过；CI 的 PowerShell/安装回滚门禁通过。
- 状态：**部分完成**。
- 未完成/阻塞：真实 Filter Manager `fltmc unload`、连接保持期间的普通卸载拒绝、认证准备后成功卸载、应用恢复以及强制卸载差异尚未在加载驱动的隔离 Windows 运行。便携桩不模拟 I/O manager、IRQL 或真实并发。

### 7. 驱动生命周期与并发

- 要求：FILE_OBJECT 引用计数、普通卸载等待引用为零、强制卸载和并发请求安全。
- 位置：`drivers/YcszProtection/ycsz_protection.c:1680-1729,1783-1847`；`drivers/YcszProtection/ycsz_protection.h:74`；`drivers/YcszProtection/tests/control_lifecycle.c`；`scripts/Test-ProtectionDriver.ps1:712-730`。
- 证据：Filter Manager 回调使用 `YcpFilterUnloadAuthorized`，控制设备按打开的 FILE_OBJECT 计数，普通卸载要求无连接且满足状态/租约，mandatory unload 单独处理；便携测试 `6` 组覆盖引用、租约、重复 close、mandatory callback 和 cleanup。
- 状态：**部分完成**。
- 未完成/阻塞：没有在 WDK/Windows 上验证强制卸载与进行中的 I/O、请求取消、文件回调和控制连接并发；动态脚本只能在实际驱动已运行时执行该部分，当前 CI 没有加载 unsigned driver。

### 8. 安装体验与通用客户端

- 要求：管理端桌面快捷方式、按计算机名展示、镜像/同名隔离身份、内置与不内置 .NET 4.8 两套包，导出可选。
- 位置：`README.md:11-19,43-55,69`；`src/Ycsz.App/ClientPackage.cs`；`src/Ycsz.Probes/SecurityProbe.cs:80-110`；`scripts/verify-package.py`；`scripts/Update-Installed.ps1:45-58`。
- 证据：CI 的 `75/75` C# 回归和 Windows 安全集成通过通用 ZIP、同名计算机独立身份、认证心跳改名、导出复用、运行库选择、runtime-free 包和桌面快捷方式相关检查；CI 还通过 9 个 .NET 处理分支。README 明确记录两套管理端/客户端安装器和不复制已初始化配置的边界。
- 状态：**已实现并有隔离回归；发布验收仍由主任务复核**。
- 未完成/阻塞：这项不依赖内核驱动的主要行为已具备证据；仍不能把独立 Windows 安全集成测试扩大为所有真实镜像部署、旧系统 .NET 安装/重启和多机网络联调。

### 9. README、安装说明、验收文档和版本一致性

- 要求：文档、安装恢复、证据、版本和发布包一致；不把未验收驱动放入正式安装包。
- 位置：`README.md:1-21,71-99,101-132,142-158`；`drivers/YcszProtection/README.md:1-18,20-48`；`docs/validation/EIGHTH-ROUND-DESIGN-2026-09-13.md`；`docs/validation/TWO-PHASE-DYNAMIC-HARNESS-2026-09-13.md`；本文件。
- 证据：README 仍明确 v1.0.1、双运行时包、管理员恢复、驱动默认不构建/不随安装器生成，以及签名、altitude、动态验收未完成；`Test-Windows -Mode Static` 通过默认安装器不包含未验证驱动的门禁；本轮新增的句柄绑定清理和两阶段流程均有单独设计/操作文档。最终 CI `34713169738` 的所有工作流步骤通过。
- 状态：**部分完成，等待主任务最终发布审查**。
- 未完成/阻塞：正式签名/加载证据、动态验收产物和生产发布批准仍缺失；在这些条件满足前，只能发布不包含自保护驱动的已验证应用包，不能把 README 的源码状态改写为“驱动已完成”。

## 本轮新增交付与保留边界

1. `scripts/Protection-Validation.ps1` 已移除 fixture 清理的路径删除兜底；身份核验、删除处置和关闭后观测绑定到同一真实句柄。创建失败路径若无法确认实体身份则保留证据并报告。
2. `scripts/Test-ProtectionFixtureBoundary.ps1` 已加入普通文件、空目录、junction、硬链接、非空目录、共享冲突、身份错配和同句柄受控替换回归；外部 sentinel 和替代对象独立检查。
3. `scripts/Test-ProtectionDriver.ps1 -Mode TwoPhase` 已加入准备/激活/验证状态、manifest 身份、同一进程持有的 ReadWrite handle/mapping、外部 `ACTIVATED` signal、超时/拒绝保留证据；脚本不启动或停止服务，state 与 signal 明确不能使用同一路径。
4. 两阶段模式没有在当前环境被冒充执行。缺少正式 signed driver、唯一 altitude 和可恢复隔离服务时，实际激活、已有句柄/映射跨激活连续性、后续 minifilter/Ob/FilterUnload 操作继续保持 `BLOCKED`。

## 外部完成条件

- 取得与目标 Windows 相配套的正式驱动签名渠道和唯一 minifilter altitude，重新生成并验证 CAT/签名材料。
- 在一次性可恢复 Windows 环境中安装并加载该签名驱动，按 `TWO-PHASE-DYNAMIC-HARNESS-2026-09-13.md` 运行 Prepare → 外部激活 → Verify；保留实际 SCM、Session 0、签名、Trusted roots、协议、对象身份和每个操作的原始结果。
- 动态证据通过后，由主任务复核最终 diff、CI、安装包内容和发布文档，再决定是否发布；不得以本轮 CI 绿灯替代上述条件。
