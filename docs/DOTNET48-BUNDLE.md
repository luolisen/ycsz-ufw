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

待完成：两种安装包编译、内嵌运行库完整性检查、依赖状态分支测试和 Windows CI。缺少 .NET 4.8 的旧版 Windows 实际安装/重启流程需独立虚拟机验证，不能用现代 Windows 已预装运行库的测试替代。
