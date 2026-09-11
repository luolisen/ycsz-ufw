# Luna 交付复核及修复

任务 01a08eb1-2488-7743-8454-e31bbd0a0e73 已处于 idle 后接手。工作树为 6be0/ycsz-ufw；基础提交 a5a659462845df56c946038e2578b9b6d25d3695，加未提交改动。未操作生产机器、未提交或发布。

## 攻击面、发现及修复

| 路径 | 发现 | 修复与验证 |
| --- | --- | --- |
| 托盘连续崩溃 | CreateProcess 成功立即清零失败次数，随后崩溃始终只等首档时间 | 累积快速崩溃，持续健康一分钟才清零。新增测试在旧代码失败、修复后通过。 |
| 已有托盘识别 | 全局 Mutex 加路径匹配可能把同会话管理窗口当作托盘，并保留不必要的 Mutex 句柄 | 查询候选进程真实命令行并解析，只有独立 --tray 参数才接管；释放未选中候选对象。增加 System.Management 构建引用。编译通过，WMI 动态路径待 Windows 验证。 |
| 更新回滚 | 忽略停止服务/关闭 UI 失败后继续覆盖文件 | 清理失败即停止覆盖并报告备份位置及两阶段错误，防止混合版本。脚本为人工静态复核，未声称 Windows 执行通过。 |
| 维护关闭 UI | 访问拒绝和等待退出超时被忽略 | 将关闭失败传递给维护工具，避免误报可覆盖文件。编译通过。 |
| Windows 关机 | 共用清理路径在 OnShutdown 中调用 RequestAdditionalTime | 仅在服务 Stop 路径申请额外时间，关机继续执行清理。编译通过，关机行为待实测。 |

## 验证步骤和证据

使用 mcs -sdk:4.5 -platform:x64 -warnaserror 编译当前 Core、App、Tests 到 /tmp/ycsz-review-20260911，未覆盖发行 artifacts。通过 mono 执行测试。使用 Luna 原 TraySupervisor 与相同新测试构建对照，出现预期的快速崩溃回归失败。

证据保存在 validation/luna-review-20260911：旧实现 regression-before.txt、新实现 test-results.txt 和当前源码 SOURCE-SHA256SUMS。git diff --check、bash -n scripts/build.sh 通过。

## 剩余条件与风险

当前仍没有正式驱动实现和已签名驱动，SelfProtectionCoordinator 只是未接入真实驱动的用户态协议/状态机；不能算防结束、防删除完成。监督器当前只监督选中的一个活动会话，多活动会话不是已完成能力。

本轮没有运行 PowerShell 解释器、Windows WTS/WMI 动态测试、交互托盘恢复、SCM 异常恢复或驱动测试；现有生产 Windows 不是可使用的靶场。需要独立可恢复的 Windows 环境及驱动构建/签名条件。尤其要验证原有托盘接管、反复崩溃、正常停止与失败回滚。上述限制未解决前，不部署生产环境或发布已验收正式版。
