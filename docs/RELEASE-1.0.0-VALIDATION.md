# v1.0.0 正式发布验收

日期：2026-09-11。源代码提交：`ef5aa22d9da515c093f2d79fce6fe0114ff13e6c`。

## 构建与自动化验证

[Windows CI 34520982369](https://github.com/luolisen/ycsz-ufw/actions/runs/34520982369) 成功。44 项逻辑/ABI、2 项回环 TLS、9 项隔离网络逻辑、39 项安全检查、9 种 .NET 前置安装分支通过；PowerShell 语法及四种 NSIS 打包通过。微软离线运行库通过固定 SHA-256 和 Windows Authenticode 签名校验。

发布的四个安装器来自该次原生 Windows 构建。最终校验值见 `artifacts/DELIVERY-SHA256SUMS`，构建来源见 `artifacts/release-provenance.txt`。内置完整包含两种客户端安装器；不内置包不含运行库。

## 远程管理端实机

向日葵主机 `DESKTOP-1GDR6B7`：先通过原管理密码正常卸载 v0.2.0，确认服务及安装登记移除，再归档配置残留至仅管理员与 SYSTEM 可访问的 `C:\ProgramData\YcszRemoved-20260911-034355`，然后安装最终 v1.0.0 内置完整包。

安装程序 SHA-256：`0400d0f24343d56bfc14de46e23c251d0b3a5884c732490784e6dcb5b7c047e0`。

实际验收通过：程序和安装登记版本 1.0.0，六个安装文件哈希匹配发布产物，服务运行、身份与路径、卸载入口、配置 ACL、DPAPI 二进制配置、PE 格式、SCM 恢复配置正常；TLS 17443 由产品服务监听。宿主 .NET Release=533509，走已有运行库跳过分支。原管理密码登录成功。

远程验证记录：`C:\Users\lenovo\Desktop\ycsz-final100\verification.txt`。

管理端实际勾选和取消“内置 .NET Framework 4.8”，分别成功导出至 Documents：

| 测试文件 | 实际字节数 |
| --- | ---: |
| ycsz-test-no-runtime.zip | 135211 |
| ycsz-test-with-runtime.zip | 123030239 |

测试结束已停用全部测试通用接入包并锁定关闭管理界面。测试 ZIP 和加密接入配置不上传仓库或发布页。

## 验证边界

本次是管理端卸载、清理、安装、登录和双版本导出实机验收。缺少 .NET 4.8 的旧 Windows 实际安装及重启路径，仅完成前置逻辑的隔离分支测试，尚未完成真实旧系统测试。不内置管理端在线下载内置客户端安装器的路径未在该主机实测。客户端 WFP 实际阻断、网卡/代理回滚、多机策略联调及 Windows 重启仍待独立验收。未在管理主机启用客户端网络阻断。
