# 双端应用更新 2026-09-12

本次已构建最新应用、两种学生端安装器、两种完整安装器；61/61 用户态回归通过。未包含未验证驱动。

## 学生端 STU01（学生1）

- 传输目录：C:\Users\Lenovo\Desktop\ycsz-student-update-0912。
- 更新脚本返回 PASS：四个程序文件哈希全部一致，settings 身份和基线保留，服务 Running。
- 备份：C:\ProgramData\YcszUpdateBackup-20260912-012612。
- 更新后服务 PID 6328/session0，托盘 PID 6564/session1。
- 日志明确提示驱动未启用；policy revision 7、解冻状态保留。
- 无系统重启、注销、驱动安装或网络配置修改。

## 教师端

- 实时 hostname 为 DESKTOP-1GDR6B7（备注教师端）。
- 传输目录：C:\Users\Lenovo\Desktop\ycsz-manager-update-0912。
- 更新返回 PASS：六个文件（含两种客户端安装器）哈希一致，settings 身份与基线保留，服务 Running。
- 备份：C:\ProgramData\YcszUpdateBackup-20260912-013351。
- 服务 PID 1804/session0，托盘 PID 22940/session2。
- 桌面 YCSZ Manager 快捷方式创建成功，双击并使用已有管理凭据登录成功。
- 管理端列表显示 STU01，最新心跳 UTC 2026-09-11 17:34:52；未下发新策略。
- 通用客户端生成窗口显示“自动采用各自的计算机名称”，提供“内置 .NET Framework 4.8”复选框。只检查界面，没有新建注册包。
- 完成后锁定并关闭管理界面，保留服务及托盘。没有系统重启或注销。

## 构建与边界

应用文件版本仍为 1.0.1.0，通过部署清单 SHA256 区分本轮修订。两台机器均部署同一组最新应用文件。程序和两种导出安装器已更新，不包含未验收的内核驱动；防强制结束、防删除不因本次升级而视为通过。

本次创建 `/Users/alan/.codex/skills/sunlogin-windows-maintenance/SKILL.md`，技能校验器返回 Skill is valid。
