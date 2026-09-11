# STU01 防破坏验收记录（2026-09-11）

## 范围与攻击面

授权目标为向日葵学生端 STU01、已安装的 YCSZ 1.0.1，以及本仓库安装程序。检查学生交互账户、任务管理器对应的服务进程、服务控制权限和安装目录权限。不得以隐藏目录作为防删除验收依据。

## 验证步骤与实机结果

| 验证 | 实际结果 |
| --- | --- |
| `net user lenovo` | Lenovo 属于 Administrators，本次诊断 PowerShell 也以管理员身份运行。 |
| `get-service ycszfirewall`、`get-process ycsz` | 首次检查服务为 Stopped，找不到 Ycsz 进程；无法仅据此确定此前是结束进程还是正常停服。 |
| `start-service ycszfirewall` 后再次查询 | Running，已恢复服务，并执行 `Ycsz.exe --tray` 恢复入口。 |
| `sc.exe qc ycszfirewall` | AUTO_START、LocalSystem，程序路径为 `C:\Program Files\YcszFirewall\Ycsz.exe --service`。不存在尚未提升为 SYSTEM 的问题。 |
| `sc.exe sdshow ycszfirewall` | 管理员具有服务停止等维护权限；普通已认证用户没有停止权限。 |
| `icacls .` 和 `icacls ycsz.exe`（安装目录内） | Users 为 RX，Administrators 与 SYSTEM 为 F。管理员账户仍具有删除权限。 |
| `attrib +h ycszfirewall` 后 `attrib ycszfirewall` | 安装目录显示 H，实机隐藏属性已生效。 |

## 修改

客户端安装分支默认设置安装目录 Hidden；原位更新脚本也对客户端设置 Hidden。服务、卸载入口和现有 ACL 保持可维护。隐藏仅减少误操作，不改变访问权限。

## 风险与尚未通过项

- 当前学生账户是管理员，不能据普通用户 ACL 宣称满足防停止、防强删要求。服务已是 SYSTEM，进一步提高运行身份不能自动解决此权限模型问题。
- 本次未删除生产程序文件，也未再次主动终止生产服务；磁盘强制删除的动态验收未完成。
- 托盘是交互用户进程，其退出不能作为后台保护正常运行的证据；当前托盘没有自动恢复机制。
- 应先确定学生使用标准账户、教师保留独立管理员维护账户的部署方式，再执行标准用户结束服务进程、停止服务、删除同 ACL 测试文件的验收。现有 Lenovo 账户未降权，避免影响联想平台和远程维护。
- 当前状态不标记为防破坏验收通过，也不据此发布已通过验收的正式版本。

## 恢复

教师管理员可用 `attrib -h "C:\Program Files\YcszFirewall"` 取消目录隐藏；正常卸载和管理员恢复入口继续保留。此次服务恢复未更改客户端身份和策略。
