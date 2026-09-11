# Luna Max 执行结果（2026-09-11）

## 范围

仅在当前隔离工作树 `/Users/alan/.codex/worktrees/6be0/ycsz-ufw` 修改和验证。没有连接 STU01、教师端、联想平台、向日葵/向日葵以外的生产控制面，没有安装驱动，没有改变 Secure Boot、HVCI、测试签名或系统安全配置。保留工作树开始时的未提交修改；本轮没有发布正式版或覆盖交付 artifacts。

## 攻击面与实现

### 托盘异常退出与会话切换

- 新增 `src/Ycsz.Core/TraySupervisor.cs`：可注入的会话/运行时抽象，处理活动会话变更、已有实例接管、异常退出后的指数退避、失败日志节流、维护停止和句柄释放。
- 新增 `src/Ycsz.App/TrayLifecycle.cs`：通过 WTS 枚举活动交互会话；通过 `WTSQueryUserToken`、用户环境块和 `CreateProcessAsUser`，以目标登录用户普通令牌启动固定安装目录的 `Ycsz.exe --tray`。
- 托盘使用按会话的全局互斥体加既有 Local 互斥体；服务只有在固定映像路径匹配时才认定已有托盘，不把会话 0 的服务进程当作托盘。
- `HostService` 在启动/停止/系统关机时启动或停止监督器。服务异常被杀时由既有 SCM failure actions 重启服务，新的服务进程重新接管托盘；正常停止时监督器先停止，不会反向拉起服务。

### 维护关闭与原位更新回滚

- `--close-ui` 现在先检查 `YcszFirewall` 已为 Stopped；服务未停止时拒绝执行，因此不能借关闭 UI 停服。
- 关闭范围仅为固定路径、非会话 0 的交互 `Ycsz` 进程，并等待退出；服务句柄不会被 Kill。
- `scripts/Update-Installed.ps1` 使用 `Stop-InstalledServiceAndCloseUi`；成功更新和异常回滚都执行 Stop + Wait + Close UI 后才覆盖文件，并重新确保 SCM failure actions/failure flag。
- 安装器不再从提升的安装器进程直接启动托盘，交由服务通过用户普通令牌启动；内置/非内置运行库、通用客户端及计算机名称逻辑未改变。

### 自保护组件（未宣称驱动完成）

- `src/Ycsz.Core/SelfProtection.cs` 实现协议模型和用户态维护状态机：固定服务/映像身份、PID/启动时间、SHA-256、实例 nonce、进程/文件/服务停止三项能力、有限维护租约和过期关闭。
- 无驱动或能力不完整时状态只能是未启用/不完整/失败；状态文字明确显示“内核自保护未启用”，不会将重启恢复冒充拒绝终止。
- 没有默认安装的内核驱动；Ob callbacks、minifilter、WDK 编译、正式签名、加载和 Windows 动态攻击测试仍未完成。

## 验证步骤与结果

### 本地临时编译和测试

未写入已有 `artifacts`，使用临时目录执行等价的 mcs 编译链：

```text
mcs -sdk:4.5 -target:library -optimize+ -warnaserror ... src/Ycsz.Core/*.cs
mcs -sdk:4.5 -platform:x64 -target:winexe -optimize+ -warnaserror ... src/Ycsz.App/*.cs
mcs -sdk:4.5 -platform:x64 -target:exe -optimize+ -warnaserror ... src/Ycsz.Tests/*.cs
mono Ycsz.Tests.exe
```

结果：`RESULT 54/54 passed; Windows integration NOT executed`。

新增隔离测试分别覆盖：缺失实例恢复、已有实例不重复启动、会话退出释放、启动失败退避、正常维护停止不恢复、驱动不可用、能力不完整、身份校验、维护授权、维护过期关闭和可逆恢复。

### 尚未执行

- 当前 macOS 环境没有 `pwsh`，因此 `scripts/Test-Windows.ps1 -Mode Static` 未执行；PowerShell/NSIS/Windows csc 的验证需在 Windows CI 或专用 Windows 靶场复核。
- 没有真实 WDK，因此未构建或签名任何驱动；没有交互 Windows 靶场，因此未进行托盘用户令牌、会话切换、异常杀托盘、异常杀服务、PID 保持、文件删除阻断或重启兼容性验收。
- 没有把未签名/未加载驱动加入安装包，也没有把用户态 fake transport 测试记录为驱动通过。

## 风险与剩余工作

1. Windows 动态测试必须在独立、可恢复且确认不存在既有 `YcszFirewall` 服务和 ProgramData 配置的专用机器执行；生产 STU01 不得作为靶场。
2. 全局互斥体和托盘恢复是生命周期协调机制，不是管理员对进程/文件的安全边界；自保护仍需签名 Ob callbacks/minifilter，并验证维护授权不会被伪造。
3. `CreateProcessAsUser`、WTS token、互斥体 ACL 和 x64 `STARTUPINFO` 需要 Windows 实机验证；本地 mcs 编译只能证明语法/链接和状态机，不证明 Win32 运行时行为。
4. 驱动交付还缺 WDK、代码签名渠道、驱动验证、蓝屏/死锁回归、维护恢复和文件别名/重解析点/硬链接边界测试。在这些条件满足前，自保护状态必须保持未启用。
