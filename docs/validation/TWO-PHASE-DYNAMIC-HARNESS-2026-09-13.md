# 两阶段 Windows 动态验收夹具

日期：2026-09-13  
实现入口：`scripts/Test-ProtectionDriver.ps1 -Mode TwoPhase`

## 用途与边界

该模式把“激活前已持有句柄/可写映射”和“激活后操作”放在同一个 PowerShell 进程中。它只接受 disposable fixture：`FixtureRoot`、`ProtectedRoot`、`ProtectedDataRoot` 和 `ServiceImagePath` 必须是 fixture 内的精确路径；SCM 中的 `YcszFirewall` 必须严格指向带唯一 `--service` 的该映像、运行账户必须是 `LocalSystem`，并且开始准备时服务必须已经 `Stopped`。

脚本不启动、停止、重启或修改服务，不安装或加载驱动，不改变签名策略，不重启系统。外部隔离 harness 负责在 `Prepared` 状态下完成真实服务激活，并在确认 `--protection-status` 成功后把 signal 文件内容改为精确的 `ACTIVATED`。

## 调用

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\Test-ProtectionDriver.ps1 `
  -Mode TwoPhase -AllowFixtureMutation `
  -FixtureRoot C:\Temp\ycsz-dynamic-fixture-<id> `
  -ProtectedRoot C:\Temp\ycsz-dynamic-fixture-<id>\app `
  -ProtectedDataRoot C:\Temp\ycsz-dynamic-fixture-<id>\data `
  -ServiceImagePath C:\Temp\ycsz-dynamic-fixture-<id>\app\Ycsz.exe `
  -WaitTimeoutSeconds 120 `
  -ResultPath C:\Temp\ycsz-dynamic-fixture-<id>\two-phase-results.json
```

默认会在 fixture 根下创建唯一的 `.ycsz-two-phase-<runid>.json` 状态文件和 `.signal` 文件。也可以用 `-TwoPhaseStatePath`、`-ActivationSignalPath` 指定 fixture 内的新叶路径；两者不能覆盖现有对象。

状态依次包含 `Preparing`、`Prepared`、`ActiveVerified`、`Verified`，失败或超时则为 `PrepareFailed`、`ActivationRejected` 或 `ActivationTimeout`。准备阶段会对 manifest 中每个样本打开 `ReadWrite` 句柄，核对卷序列号、FileIndex、长度、硬链接数，并创建 `PAGE_READWRITE`/`FILE_MAP_WRITE` 且不含 execute 的映射；写入一个字节后立即恢复原值并 flush，随后仍保持句柄和 mapping view。

外部流程必须按以下顺序操作：

1. 等待状态为 `Prepared`，读取状态中的精确服务映像和路径。
2. 只在一次性隔离 Windows 中，确认 SCM/驱动签名、TrustedImagePath、TrustedDataRoot 和产品数据根都属于同一 fixture 后激活该服务。
3. 使用同一 fixture 映像执行 `--protection-status`，确认当前协议返回 Active；不要仅以服务状态 Running 作为信号。
4. 将状态文件旁的 signal 文件内容写为 `ACTIVATED`，保持其文件身份不变。
5. 脚本会重新读取真实 SCM 服务、Session 0 进程、可信双根和当前协议，然后运行既有 post-active 操作矩阵。所有对象都由同一进程保留到验证结束。

如果缺少已签名、可加载驱动、唯一 altitude 或隔离服务绑定，脚本会保留状态和 signal 作为证据，输出 `BLOCKED`，并明确不把 post-active 操作或预先存在的文件冒充为已完成动态证据。
