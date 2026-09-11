# 自保护第二轮实施方案（2026-09-12）

## 目标与边界

本轮只在仓库和可复现的 Windows CI/隔离靶场工具内完成开发与验证，不触碰生产 Windows、生产账号、Lenovo 配置、重启/注销、签名证书、Secure Boot/HVCI 或正式 minifilter altitude。现有 `3f887d2` 及其之前的工作必须保留，`docs/validation/MAIN-REVIEW-AFTER-LUNA-2026-09-12.md` 是主任务工作树中的用户文档，不删除、不覆盖。

本轮交付四类可审计结果：

1. 服务在 session 0 中由驱动认证，驱动只接受真实服务实例激活；服务为真实、当前用户 session 的托盘实例登记目标，登记包含 PID、创建时间、session、镜像路径、摘要和实例 nonce，拒绝任意 PID、PID 重用和旧 session 目标。
2. 安装目录与 `ProgramData\YcszFirewall` 都由内核文件过滤保护；ProgramData 写入只对已经由驱动认证的产品服务实例合法，普通 SYSTEM、管理员或其他进程不获得泛化豁免。协议、驱动状态、C# 镜像和 ABI 测试同步升级。
3. 安装前完成 INF/SYS/CAT 成员绑定校验；失败时恢复服务、注册表信任值和驱动注册状态；卸载前继续要求认证维护租约、真实过滤器卸载和精确产品包身份；激活判定必须确认设备/过滤器/协议状态，不能把 SCM `Running` 当作激活成功。
4. 增加可自动化的隔离 Windows 动态验收工具，覆盖已有句柄、映射写、目录/文件删除、硬链接、重解析点和并发卸载；无法在 unsigned CI 或缺少正式签名/隔离加载环境执行的项目必须输出 `blocked` 与未覆盖原因，不得输出成功。

## 协议 v2 和 ABI 设计

共享头文件 `drivers/YcszProtection/ycsz_protection_protocol.h` 与 `src/Ycsz.Core/SelfProtectionDeviceTransport.cs` 必须同时改为版本 2。所有输入结构使用 `Header.Size == sizeof(struct)` 和 IOCTL 输入长度精确相等；状态输出要求 `OutputBufferLength == sizeof(YCP_STATUS)`、返回长度精确相等、`Status.Size` 精确相等。旧版本、截断、尾随字段和未知状态位全部拒绝。

固定布局如下（x64/Pack=8，`WCHAR` 为 2 字节）：

| 结构 | v2 设计 | 预期大小 |
| --- | --- | ---: |
| `YCP_CONTROL_HEADER` | 不变 | 16 |
| `YCP_PROCESS_IDENTITY` | 将原 `Reserved` 明确改名为 `SessionId`；服务为 0，托盘必须大于 0 | 1088 |
| `YCP_ACTIVATE_REQUEST` | 服务身份 + 安装根 + `ProtectedDataRoot` | 3152 |
| `YCP_TRAY_REQUEST` | Header + 托盘身份，用于登记/注销 | 1104 |
| `YCP_MAINTENANCE_REQUEST` | 不变 | 40 |
| `YCP_UNLOAD_REQUEST` | 不变 | 32 |
| `YCP_STATUS` | 原服务状态 + `ProtectedDataRoot` + `TrayIdentity` | 4264 |

新增 `IOCTL_YCP_REGISTER_TRAY`、`IOCTL_YCP_UNREGISTER_TRAY`，并新增 `YCP_STATE_TRAY_REGISTERED`、`YCP_STATE_DATA_ROOT`。登记/注销只能由已认证的服务目标调用，驱动通过 `PsLookupProcessByProcessId`、创建时间、实际镜像路径和 token session 再验证托盘对象；旧目标仍存活时不允许静默替换，旧目标退出或显式注销后才可登记新实例。驱动持有 `PEPROCESS` 引用并在清理、退出、替换时释放，因而 PID 重用不能继承保护。

激活请求中的 ProgramData 根必须与安装时写入 `Parameters\TrustedDataRoot` 的 NT 路径完全一致，不能由服务任意选择保护范围。状态输出同时报告两个根和两个身份，用户态按完整字段验证，不只验证 PID 或 Running 状态。

## 托盘生命周期

`TraySupervisor` 在采用已有实例、启动新实例、session 切换、实例退出、维护停机和服务停机时调用登记/注销回调。服务端回调按 PID 重新读取真实进程路径、创建时间、session 和镜像摘要，并确认命令行仍是固定安装路径的 `--tray`；托盘自身不直接打开驱动设备。登记失败时托盘实例不得被当作已保护实例继续运行，监督器记录失败并按既有退避重试。

测试必须覆盖：session 切换注销旧 PID、同 PID 不同创建时间被拒绝、旧进程退出后允许新实例、重复登记幂等、服务停止时注销以及登记失败不留下未保护的“成功”状态。

## 文件和写入授权

驱动保存安装根和 ProgramData 根，路径匹配必须是边界前缀，包含根目录本身。安装目录和 ProgramData 的创建写入、覆盖、截断、删除、重命名、替换、硬链接、重解析点和映射写都进入统一的文件变更判定。

文件过滤不再按 `RequestorMode == KernelMode` 全部放行。对受保护路径的变更，过滤器必须通过 `FltGetRequestorProcess`（无有效进程则拒绝）确认请求进程就是已登记的服务实例；普通 SYSTEM、管理员、用户进程和其他内核来源不得获得产品根的泛化豁免。认证维护只改变进程句柄保护和停机流程；过滤器在真正卸载前仍保护两个根，服务实例是唯一合法写入者。

新增/加强的过滤入口：

- 已有句柄的 `IRP_MJ_WRITE`、`SET_INFORMATION`、删除/重命名/链接和覆盖；
- `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION`、修改写/缓存刷新相关入口，对可写映射拒绝或仅允许服务实例；
- `IRP_MJ_FILE_SYSTEM_CONTROL` 中设置/删除 reparse point 等会改变路径语义的操作；
- 目的地解析失败、请求进程无法识别等安全不确定情况按拒绝处理，并在动态工具中记录。

驱动控制设备的打开对象仍计数到最终 `CLOSE`，`CLEANUP` 不提前释放引用；普通卸载、强制卸载、租约过期和并发关闭必须保持现有 fail-closed 语义。强制卸载不能被代码声称为可阻止成功，只能记录 Filter Manager 的真实结果。

## 安装、回滚、CAT 与激活

安装脚本在任何注册表、驱动存储或服务变更前验证：固定 INF 文件名、Provider/Class、`CatalogFile`、SYS/CAT 有效签名、CAT 对本包 INF 和 SYS 的成员绑定、镜像路径、LocalSystem、服务 SID 和路径转换。生产路径找不到 `signtool verify /kp /c` 时失败，不以普通 Authenticode 的 SYS/CAT 签名替代目录成员校验。

安装过程记录并可恢复：原服务运行状态、原 `TrustedImagePath`、原 `TrustedDataRoot`、驱动是否已注册和是否由本次启动。失败时停止本次启动的服务，恢复两个信任值，删除本次新注册的驱动（只删除已确认的产品包），并尽力恢复原应用状态；每个回滚失败都写入明确的结果，不伪造完整回滚。

成功判定必须同时满足：`YcszProtection` 服务已运行、`fltmc` 能看到目标过滤器、固定控制设备可打开、服务通过 v2 `QUERY_STATUS` 收到精确长度且含 ACTIVE/PROCESS_CALLBACK/FILE_FILTER/DATA_ROOT 状态、返回身份和双根匹配本次实例。任何一项缺失都标记安装失败并进入回滚。

卸载脚本继续先确认应用停服、过滤器查询成功、认证 `PREPARE_UNLOAD` 租约有效、控制句柄和 open-file 引用归零，再卸载并删除精确 OEM INF；查询失败、过滤器仍在运行、包身份不匹配或服务删除失败时不删除任何后续对象。

## 动态验收工具

新增 `scripts/Test-ProtectionDriver.ps1`，默认只读/静态模式；`-Mode Dynamic` 必须要求管理员、明确的临时 fixture 根、目标服务/过滤器不存在冲突、正式签名包和可恢复隔离 Windows。工具输出 JSON/文本结果，每项含 `pass`、`blocked` 或 `fail`、错误码和清理结果：

| 场景 | 必须观察 |
| --- | --- |
| 已有句柄 | 激活前打开句柄，激活后写、删除、改名；操作被拒绝且数据未变化 |
| 可写映射 | 创建可写映射并刷新/写入；被拒绝或明确记录不支持的文件系统/路径 |
| 根目录与普通 SYSTEM | 删除根目录、普通 SYSTEM 写入和其他进程写入被拒绝；服务实例写入可审计 |
| 硬链接/重解析点 | 受保护源/目的地不能绕过过滤；不支持的 FSCTL 必须 blocked，不得 pass |
| PID/session/restart | 旧托盘退出、PID 重用模拟/真实创建时间变化、session 切换后旧目标不再受保护，新目标需重新登记 |
| 并发卸载 | 控制句柄、文件句柄、关闭竞态下普通卸载不成功；准备租约、句柄归零后的真实结果单独记录 |

工具的 static 模式可在当前 CI 执行并检查源代码、协议版本、ABI 常量、测试入口和“未覆盖”清单。当前 unsigned CI 不执行驱动加载；没有正式签名、唯一 altitude、隔离安装和可回滚环境时，dynamic 模式返回 `blocked` 并把缺口写入结果文件。

## 验证与停止条件

代码变更后依次运行本地可用测试、`git diff --check`、PowerShell 解析/纯函数门禁、C# 回归、协议固定大小/状态篡改测试、WDK Release x64 编译和 InfVerif。Windows CI 必须继续保留原有用户态、TLS、合成网络、WFP 回滚、disposable 安全集成和 unsigned 事实标记。

只有代码、静态门禁、ABI、回滚逻辑和动态工具的可执行部分完成后，才向主任务报告；正式签名/CAT 信任、唯一 altitude、真实驱动加载、重启后行为和真实终止/映射/链接阻断仍属于隔离 Windows 外部条件，不能用 unsigned CI 绿色替代。
