# 2026-09-11 管理端安装恢复记录

## 范围

用户授权无人值守卸载 RAV、重试管理端安装，并使用其提供的管理密码。密码不写入此记录或脚本。

测试主机：`DESKTOP-1GDR6B7`，通过向日葵远程桌面操作。

## 已完成

- RAV Endpoint Protection 7.7.6：原厂卸载向导显示“已卸载”，Windows 已安装应用搜索 RAV 无结果。
- 原安装在 RAV 移除后继续，返回“服务创建失败”；详情显示 `sc.exe create` 参数帮助。`Get-Service YcszFirewall` 当时确认服务不存在。
- 修复 `installer/Ycsz.nsi` 的 `binPath` 参数：NSIS 的 `$\"` 只生成引号，还必须保留传给 Windows 命令行解析器的反斜杠，使含空格的可执行文件路径作为服务路径内部的引号保留。
- 使用旧卸载入口验证管理密码，完成未完成安装的卸载。
- 将旧配置目录重命名为 `C:\ProgramData\ycszfirewall-before-servicefix-20260911`，保留 manager.bin、manager.pfx、settings.bin，不读取其内容。
- 重新安装 `Ycsz-Setup-0.1.0-servicefix-x64.exe`，选择管理端并按用户指定密码初始化。安装向导显示安装完成。

## 实机验收证据

以下结果来自本次远程 Windows 画面中的实际命令输出：

```text
Get-Service YcszFirewall
Status: Running
DisplayName: YCSZ Education Firewall

sc.exe qc YcszFirewall
TYPE: 10 WIN32_OWN_PROCESS
START_TYPE: 2 AUTO_START
BINARY_PATH_NAME: "C:\Program Files\YcszFirewall\Ycsz.exe" --service
SERVICE_START_NAME: LocalSystem
```

从安装目录启动 Ycsz.exe 后出现密码验证窗口；提交用户指定密码后，成功显示“YCSZ 教育机房防火墙 · 管理端”，状态“操作完成”，可见客户端设备、网络与 hosts、安全事件、统一白名单标签。客户端列表为空。

## 构建与完整性

```text
makensis -INPUTCHARSET UTF8 -V2 -DOUTPUT_FILE=../artifacts/Ycsz-Setup-0.1.0-servicefix-x64.exe installer/Ycsz.nsi
结果：退出码 0

7zz t artifacts/Ycsz-Setup-0.1.0-servicefix-x64.exe
结果：Everything is Ok

SHA-256:
8b7e33b864fa26d3e6bcf2873b7f05e72b891c878c526a39da2f0021a391faef
```

Windows 桌面的 Get-FileHash 结果与本地上述哈希一致。新包保留旧应用二进制，只修复 NSIS 服务命令；没有重建应用或宣称新增应用测试结果。

## 验收边界

本次验证管理端安装、服务运行/自动启动配置与密码登录。未执行 Windows 重启、第二台客户端注册、WFP 阻断、网络回滚或端到端策略测试；仍为工程预览，不代表完整机房防护验收。未推送或发布远端。
