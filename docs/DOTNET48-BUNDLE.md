# .NET Framework 4.8 离线依赖计划与验收

## 交付目标

- 完整安装包与客户端专用安装包均包含微软官方 .NET Framework 4.8 离线运行库。
- 已安装 4.8 或更新版本直接跳过；缺少时先运行微软安装程序，再检查注册表确认运行库可用。
- 返回 3010/1641 时停止本次产品安装，提示重启后重新运行；不自动重启，不提前创建产品配置和服务。
- 取消、失败及安装后检测不通过时停止产品安装并保留错误码。
- 只在构建时下载依赖；最终用户安装不需要联网下载运行库。客户端注册仍需访问管理端。
- 固定官方下载地址及 SHA-256，Windows 构建同时校验微软数字签名。依赖二进制不提交 Git。

## 官方依据

- https://dotnet.microsoft.com/en-us/download/dotnet-framework/net48
- https://learn.microsoft.com/en-us/dotnet/framework/deployment/deployment-guide-for-developers

## 验收范围

本地两种安装包编译、内嵌运行库 SHA-256 与应用文件对比通过；损坏的运行库文件会在打包前被拒绝。Windows CI 结果与远程安装验证见本版发布验收记录。缺少 .NET 4.8 的旧版 Windows 实际安装/重启流程需独立虚拟机验证，不能用现代 Windows 已预装运行库的测试替代。

## 固定依赖

- 文件：`NDP48-x86-x64-AllOS-ENU.exe`
- SHA-256：`0a3a390c47e639d0f7fc65b21195fee6b7f65b066f80f70c60fab191d14b7e40`
- 构建下载：`python3 scripts/fetch-net48.py`，Python 3.8+；Windows 构建额外检查 Authenticode 微软签名。
- 运行参数：`/passive /norestart /ChainingPackage YcszFirewall`。返回需要重启时退出码为 3010；取消或失败保留错误码；报告成功但未检测到运行库时返回 1603。
- `scripts/Test-Net48.ps1` 用同一份 NSIS 分支函数运行 9 种模拟结果，不修改实际运行库。

## 安装包与导出选项

发布四个安装程序：完整管理端与客户端专用安装器，各有内置运行库、不内置运行库两种。`NoRuntime` 文件不包含微软运行库；缺少 .NET 4.8 时说明所需环境并停止。

管理端“生成通用客户端包”增加“内置 .NET Framework 4.8”选项。完整内置版管理端保存两种客户端安装器，均可离线导出。不内置版管理端只携带轻量客户端安装器；选择内置版时，从本项目 v1.0.0 发布页读取 SHA-256 清单，下载并核验安装器，缓存至当前用户 LocalAppData。每次使用此下载缓存前需联网读取发布清单校验；不上传注册包、密码或设备信息。获取失败时不创建接入包。
