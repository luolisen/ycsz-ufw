# LUNA 第七轮 fixture 边界设计（2026-09-12）

## 1. 范围与证据边界

基线为 `bd836d5`，CI `34668438932` 已通过。本轮只修正动态证据 runner 的 fixture 实体边界、对象所有权、SCM/保护根绑定，以及无驱动 Windows 临时目录集成回归；不加载驱动、不启动或重启服务、不调用生产卸载、不改变签名/altitude/SecureBoot/HVCI。

本轮不把“路径字符串位于 fixture 子目录”当成实体安全，也不把“文件存在”当成本次创建所有权。无法在句柄身份和清理边界上闭环的检查输出 `BLOCKED`，不扩大为保护通过证据。

## 2. 设计决定

### 2.1 实体树检查与稳定句柄范围

在 Dynamic 的任何写入前，逐组件枚举 fixture 根、两个保护根、服务映像所在父目录、marker、manifest 和 manifest 中的预置文件。fixture 根及这些稳定父组件都用 `CreateFile(..., FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)` 作为最终组件打开，并通过 `GetFileInformationByHandle` 立即取得属性、卷序列号、文件索引和硬链接数；父 junction、mount/reparse、最终 reparse 和多链接普通文件均拒绝。fixture 根必须是严格存在的目录，不能等于其父目录或通过父 junction 到达。预置保护样本在前置阶段按 manifest 逐一重新打开并核对身份/长度；为了不让 runner 自己持有的句柄改变 post-Active 新句柄和映射的共享语义，样本句柄不跨越目标操作保留，目标操作前仍再次用句柄实体核对。

句柄在整个 Dynamic 检查期间保留，且 fixture 根句柄不共享 `DELETE`，防止测试期间替换/重命名外层 fixture。目标根本身在“删除根目录”检查前不能同时持有阻止删除的句柄；该破坏性项目因此在当前 runner 中保持 `BLOCKED`，不把一次属性检查冒充抗竞态证明。受保护样本只读核验其 manifest 中的身份、长度、非 reparse 和单链接条件，不加入清理清单。

### 2.2 显式 manifest 与参数绑定

Dynamic 要求 fixture 根下的 `.ycsz-dynamic-fixture.json`，而不是只接受空 marker。manifest 至少包含：

```json
{
  "FixtureId": "guid",
  "FixtureRoot": "C:\\Temp\\fixture-guid",
  "ProtectedRoot": "C:\\Temp\\fixture-guid\\app",
  "ProtectedDataRoot": "C:\\Temp\\fixture-guid\\data",
  "ServiceImagePath": "C:\\Temp\\fixture-guid\\app\\Ycsz.exe",
  "ProtectedFiles": [
    { "Path": "...\\app\\existing-handle.bin", "Length": 4096,
      "VolumeSerial": 1, "FileIndex": 2, "NumberOfLinks": 1 }
  ]
}
```

manifest 的四个路径必须与本次参数逐一按 Windows 大小写不敏感规则相等，且全部通过实体树检查。预置文件的长度、卷序列号、文件索引、链接数必须匹配；不匹配、缺项或重复路径为 `BLOCKED`。

前置检查还必须读取真实 `Win32_Service`：`YcszFirewall` 状态为 Running、StartName 为 LocalSystem、`PathName` 必须严格等于带引号的用户 `ServiceImagePath` 加唯一 `--service` 参数；`ProcessId` 必须存在，且当前进程 Session 0、实际映像路径和启动身份都与该路径一致。任何服务查询/进程查询失败先 `BLOCKED`，不执行 fixture 变更。

不新增协议字段。驱动已有 `YCP_STATUS` 的双根校验由服务 transport 在 `--protection-status` 中执行；runner 同时要求 `YcszProtection\Parameters\TrustedImagePath` 等于该服务映像的 NT 路径，`TrustedDataRoot` 等于用户 `ProtectedDataRoot` 的 NT 路径，并要求 `--protection-status` 成功。这样只宣称“SCM、信任配置、用户参数和服务状态一致”，不伪造一个当前协议未公开的独立 kernel root 查询。

### 2.3 本次创建对象与清理所有权

所有普通对照对象使用 GUID 后缀和 `CreateNew`/原生 `CreateDirectoryW`，已有同名文件、目录、硬链接或 junction 一律拒绝，绝不使用 `WriteAllText` 覆盖或 `-Force` 接管。每次成功创建都记录句柄身份、类型和路径到本次 owned 清单。

清理只接受 owned 清单中的精确路径，并在删除前重新打开实体、核验卷序列号/文件索引/类型；缺失视为已清理，身份变化或清理异常记录 `ERROR` 并保留路径。预置保护样本、fixture 根、外部 sentinel 和未知目录永远不进 owned 清单；清理不使用对未知路径的递归删除。

### 2.4 动态检查命名调整

普通文件写入、映射、硬链接、junction 和目录删除的 control 对照继续先完成；目标检查使用本次唯一对象。已有保护样本只用于只读的 post-Active 新句柄/映射检查，仍不能声称激活前已有句柄/映射。保护根本身的递归删除在无法同时保持实体身份与允许删除的安全句柄时输出 `BLOCKED`。

## 3. 无驱动临时目录集成回归

新增 `scripts/Test-ProtectionFixtureBoundary.ps1`，只在当前用户临时目录创建一次性测试树，不加载服务或驱动，测试并清理以下场景：

1. fixture 父级 junction 指向外部目录：实体树校验必须拒绝，外部 sentinel 字节保持不变。
2. 普通对照文件/目录存在同名对象：CreateNew/目录创建必须拒绝且原内容保持不变。
3. 外部 sentinel 的硬链接落入 fixture：单链接/身份校验必须拒绝，不能删除或修改 sentinel。
4. manifest 的根、服务映像和双保护根不匹配：全部在写入前拒绝。
5. 已拥有文件被持有冲突句柄时清理失败：返回 `ERROR`、保留路径和字节；释放句柄后只清理该 owned 文件。

测试自身使用相同的身份校验和精确 owned 清理；最终只在确认测试根仍为本次创建的目录且内容为空后删除测试根，否则保留证据并失败。该集成回归不代表驱动已加载或真实保护成立。

## 4. 验收、退出与回滚

先提交本设计，再实现共享实体/所有权 helper、Dynamic 前置绑定和临时目录回归；本机仅运行静态审计，Windows CI 运行 PowerShell 解析、纯分类回归和新集成回归。普通推送后核对 CI HEAD 与日志。若新回归失败，回滚本轮提交，不覆盖父任务已有未跟踪文档；正式签名 Windows、真实 driver Dynamic、启用前对象两阶段 harness 仍记录为未完成。
