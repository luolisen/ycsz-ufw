# 2026-09-11 远程管理端 v0.2.0 重装验收

主机：DESKTOP-1GDR6B7。通过向日葵远程桌面和文件传输执行，用户授权更新，并追加要求先卸载再清理。

## 执行结果

- 初始维护更新已备份并成功启动 v0.2.0；收到用户追加要求后，转为完整卸载与全新安装。
- 使用管理页卸载入口，通过原管理密码验证，确认向导目标为 `C:\Program Files\YcszFirewall`，点击卸载。详情显示 `DeleteService 成功`、文件删除和卸载完成。
- 远程画面存在延迟：密码验证后卸载确认页迟到。期间打开的备份目录卸载向导已取消；未执行手工删除服务的备用脚本。
- 清理脚本确认旧服务与卸载注册表登记不存在，归档残留配置并清空原路径。输出 `CLEAN PASS`。
- 执行正式发布的 v0.2.0 完整安装程序，选择管理端，沿用用户给定密码初始化。向导显示安装成功。
- 重装后 `Get-Service YcszFirewall` 为 Running；`sc.exe qc` 为 AUTO_START、LocalSystem，路径为 `"C:\Program Files\YcszFirewall\Ycsz.exe" --service`。
- 安装后 Ycsz.exe SHA-256 与已验证的 Windows 发布产物完全相同：`961e9efb8615ac88c373dcf7ef1c628533de5ccf8aaa74e79ed215639afd6fbf`。
- 实际密码登录成功，管理页状态“操作完成”，可见“生成通用客户端包”和“停用通用接入包”；客户端列表为空。验收后点击“锁定并关闭”。

## 恢复位置与安装来源

- 维护前备份：`C:\ProgramData\YcszUpgradeBackup-20260911-025448`，包含 program、config 和 upgrade.log。
- 卸载后残留归档：`C:\ProgramData\YcszRemoved-20260911-025954`。
- 以上目录仅 SYSTEM 与 Administrators 可访问；旧配置已移出原活动路径，没有导回新安装。
- 安装包 SHA-256：`b8c26d3eec38591f40916df80f0aaf818d0cffc8298ea9cc2295337905cf2746`，在远程启动前已校验。
- 正式版本：https://github.com/luolisen/ycsz-ufw/releases/tag/v0.2.0

## 验收边界

本次验证管理端卸载、清理、完整安装、服务配置、发布文件一致性及 GUI 登录。未重启 Windows，未新增客户端、生成实际接入包或执行 WFP 多机联调。密码不记录在文档或脚本中。本记录作为 v0.2.0 发布后的实机验收补充；安装程序和原交付 ZIP 保持原有哈希。
