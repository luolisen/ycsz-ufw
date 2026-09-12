# 第八轮交付设计：句柄绑定清理与两阶段动态验收

日期：2026-09-13  
基线：`3f03573` (`Clean owned junctions with native directory removal`)  
范围：仅本项目源码、PowerShell 验证工具和隔离临时目录；不安装/加载未验证驱动，不重启，不修改生产服务、签名策略或 Secure Boot/HVCI。

## 1. 已确认的问题

暂停验收报告已经确认：`Test-ProtectionFixtureOwnedIdentity` 会先按路径打开并校验卷序列号/文件索引，随后关闭句柄；`Remove-ProtectionFixtureOwnedPath` 再按路径调用 `RemoveDirectory` 或 `Remove-Item`。身份检查与删除不是同一个内核对象上的原子链路，因此在两者之间发生替换时，理论上可能删除替代对象。目录、联接点和硬链接也必须共享同一安全边界，不能通过“类型不同”绕过该问题。

本轮的完成条件不是继续增加普通临时目录数量，而是让清理动作满足以下不变量：

1. 通过带 `DELETE` 权限的句柄打开目标，并在该句柄上重新读取对象身份。
2. 身份不匹配、重解析类型不匹配、硬链接约束不满足或打开失败时，不执行任何路径删除。
3. 删除只通过同一句柄上的 `SetFileInformationByHandle(FILE_DISPOSITION_INFO)` 标记完成；关闭句柄前后都不回退到 `Remove-Item`、`DeleteFile(path)` 或 `RemoveDirectory(path)`。
4. 受控替换成功后，旧对象的句柄处置不能删除新对象；替代对象的字节、身份和外部 sentinel 必须由测试独立确认。
5. 创建失败路径如果已经拿到对象身份，也只能走上述句柄绑定清理；如果身份尚未确认，则保留证据并报告失败，不能猜测路径归属。

## 2. 实现方案

### 2.1 Native binding

在共享 PowerShell 验证绑定中增加 `FILE_DISPOSITION_INFO`（信息类值 4）和 `SetFileInformationByHandle`。清理句柄使用 `DELETE | FILE_READ_ATTRIBUTES`，正常 share mask 为 `FILE_SHARE_READ | FILE_SHARE_WRITE`，因此其他进程不能在验证句柄持有期间重命名、替换或删除路径。测试专用的受控替换分支可以显式允许 `FILE_SHARE_DELETE`，但必须仍然在原句柄上执行处置，并在结果中记录替代对象。

`GetFileInformationByHandle` 的结果由同一句柄产生。目录使用 `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`，联接点必须保持重解析标志，普通目录必须没有该标志，文件/硬链接必须是普通文件。硬链接允许链接计数大于 1，但清理验证必须证明 sentinel 目标仍然存在且内容不变。

### 2.2 Owned cleanup contract

将“路径身份核验”和“句柄实体身份核验”拆成共享谓词。`Remove-ProtectionFixtureOwnedPath` 改为：

1. 按 exact path 打开删除句柄。
2. 立即在该句柄上查询实体并匹配 `Kind`、卷序列号、文件索引以及适用的 hard-link count。
3. 可选地在句柄仍持有期间执行测试 hook；hook 只用于受控替换尝试，不能授权任意路径。
4. 空目录/联接点/文件均调用同一个句柄处置函数。非空目录由 Windows 返回的失败保留并报告；不再先用路径枚举再删除。
5. `SetFileInformationByHandle` 成功后关闭句柄。关闭后只做证据查询：若路径不存在，原对象删除得到确认；若路径上是不同身份的替代对象，报告“原对象已处置、替代对象保留”；若仍是原身份，报告错误。任何证据查询失败都不能触发第二次路径删除。

所有 fixture 创建 helper 的异常路径遵循同一契约：文件在写入期间保留创建句柄，成功读取身份后才允许清理；目录/硬链接/联接点在身份查询失败时保留证据，不再使用路径删除兜底。

## 3. Windows 临时目录回归

`Test-ProtectionFixtureBoundary.ps1` 保持唯一 GUID 临时根和外部 sentinel，并新增以下独立检查：

- 普通文件：在身份检查与处置之间，用共享删除句柄执行 `MoveFileEx(..., MOVEFILE_REPLACE_EXISTING)`，把候选替代文件换到原路径；旧 Owned 句柄的处置必须只影响旧对象，替代文件的身份/字节保持不变。
- 普通文件、空目录、联接点：均通过句柄绑定清理；联接点清理不得触碰目标目录。
- 非空目录、共享冲突、Owned 身份不匹配：返回 `ERROR`，保留证据，不执行路径删除。
- 硬链接：删除 link path 后，外部 sentinel 仍存在且 fingerprint 不变。
- 创建失败/清理失败：验证不会通过 `Remove-Item`、递归删除或未验证路径来“收尾”。

测试只操作它自己创建的临时根；失败时保留无法确认归属的路径，并在输出中列明，不触碰 `YcszFirewall` 或 `YcszProtection` 服务。

## 4. 两阶段动态验收准备

现有 dynamic runner 的 pre-active 项目必须继续标记为未覆盖，不能把“文件预先存在”冒充为“激活前已持有句柄/映射”。本轮准备一个显式的两阶段 fixture contract：

- Phase 0/Prepare：读取并固定 disposable manifest、服务镜像、ProtectedRoot、ProtectedDataRoot 和真实 SCM 绑定；在激活动作前建立受控的持有句柄与可写文件映射，记录对象身份、映射能力和持有状态。
- Phase 1/Activate：只允许外部隔离 harness 在已确认的真实服务身份上完成激活；脚本不自动重启或修改未知服务。
- Phase 2/Verify：激活成功后，先验证 Phase 0 的持有对象确实是同一身份，再执行新句柄、硬链接、联接点、映射写入、目录删除、维护/卸载并发等操作；每个失败都必须绑定实际阶段和独立 ordinary control。

如果缺少已签名、可加载的驱动和隔离服务，Prepare/Activate/Verify 均输出 `BLOCKED` 及缺失条件；不能伪造 post-active 结果，也不能把普通 fixture 控制失败归因于驱动。

## 5. 最终九项需求审计

实现结束后新增最终 gap audit，逐项引用 `docs/LUNA-FULL-DELIVERY-2026-09-12.md` 的九项需求，记录：当前源码/脚本、已验证证据、未实现或未运行项、外部阻塞条件。签名、唯一 altitude、真实 driver load、实时终止/映射/卸载证据仍分别保留为外部环境门槛，不因 CI 或静态匹配通过而改写为完成。

## 6. 验证与回滚

验证顺序：PowerShell 语法与纯测试 → Windows 临时目录回归 → Windows CI 全流程 → 读取 CI 输出并更新 gap audit。若句柄处置在 Windows 语义上对硬链接、联接点或替换表现不同，优先保留失败证据并收紧清理契约，不恢复路径删除。回滚边界为本轮提交；不使用 `git reset --hard`，不覆盖用户未跟踪的验收文档。
