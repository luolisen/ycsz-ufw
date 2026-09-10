# YCSZ 教育机房防火墙

用于 Windows 教育机房的管理端与客户端：集中下发网站白名单、控制客户端网络出口、检查网络配置变更，并记录安全事件。管理端生成一份通用客户端安装包，可在多台电脑上分别安装；客户端自动以 Windows 计算机名称显示，每台设备使用独立身份和认证凭据。

当前版本为 **v0.2.0 工程预览版**。已完成 Windows 自动化验证和管理端实机卸载、重装、登录验收；完整客户端网络阻断与多机联调仍待验证。产品提供网络与配置保护，不提供磁盘快照或整机重启还原。

## 下载

前往 [v0.2.0 发布页](https://github.com/luolisen/ycsz-ufw/releases/tag/v0.2.0) 下载。

| 文件 | 用途 |
| --- | --- |
| `Ycsz-Setup-0.2.0-x64.exe` | 完整安装包。安装管理端时选此文件，内含生成通用客户端包所需的安装程序 |
| `Ycsz-Client-Setup.exe` | 客户端专用安装程序；单独下载不含管理端接入配置 |
| `Ycsz-0.2.0-delivery.zip` | 发布时的完整交付快照，包含源码、文档、构建脚本与安装包 |
| `DELIVERY-SHA256SUMS` | 两个安装程序及完整交付 ZIP 的 SHA-256 校验值 |
| `MANAGER-REINSTALL-2026-09-11.md` | 发布后补充的管理端实机重装验收记录 |

发布附件中的安装程序来自通过验证的原生 Windows CI 构建，来源见 [release-provenance.txt](artifacts/release-provenance.txt)。发布后的验收文档作为独立附件补充，原交付 ZIP 保持原有哈希；最新说明以本仓库为准。

## 系统要求

- Windows 10/11 x64、.NET Framework 4.8、Windows PowerShell 5.1。
- 安装、卸载和管理员恢复需要 Windows 管理员权限及 UAC 授权。
- 管理端使用固定 IPv4；客户端初始化时须能连接管理端 TCP 17443。
- 日常受控用户应使用标准用户账户。

安装程序自动创建管理端入站规则，范围为域/专用网络、本地子网。跨 VLAN 部署需要管理员按实际客户端来源配置精确子网范围。

## 安装管理端

1. 运行 `Ycsz-Setup-0.2.0-x64.exe`，安装角色选择“管理端”。
2. 设置并确认至少 12 字符的管理密码，完成初始化。
3. 从开始菜单打开管理界面，用管理密码登录。
4. 确认服务运行正常后，生成通用客户端包。

管理端默认安装在 `C:\Program Files\YcszFirewall`，配置与日志位于 `C:\ProgramData\YcszFirewall`。配置使用 Windows DPAPI 加密，并限制文件访问权限；密码不以明文保存，也不可找回。

## 生成与安装通用客户端包

1. 在管理端点击“生成通用客户端包”，填写管理端固定 IPv4 和注册包密码，导出 ZIP。
2. 将 ZIP 分发到客户端，注册包密码另行传递。
3. 每台电脑先解压全部文件，再运行其中的 `Ycsz-Client-Setup.exe`。保持它与 `client.ycsz` 在同一目录。
4. 安装角色自动锁定为客户端；输入本机管理密码及注册包密码，完成注册与网络基线保存。
5. 返回管理端刷新设备列表，按计算机名称找到设备。

同一 ZIP 可以重复部署多台电脑，每台安装都会生成独立 ID 和凭据；同名计算机不会合并。计算机改名后，管理端通过认证心跳更新显示名称。**不要复制或克隆已初始化的 `ProgramData\YcszFirewall` 配置来部署其他电脑。**

通用包需要 v0.2.0 或更新版管理端。旧版单设备 `.ycsz` 注册包仍可通过选择文件导入。当前上限为 64 台设备、32 个通用接入包。

## 日常管理

| 操作 | 行为 |
| --- | --- |
| 冻结/解冻出口 | 对选中设备应用或解除本产品的出口限制；解冻后进程、代理和配置保护继续执行 |
| 统一白名单 | 编辑允许访问的站点域名，下发到客户端 |
| 网络与 hosts | 查看并修改所选客户端的配置基线 |
| 安全事件 | 查看客户端上报的检测与处理记录 |
| 停用通用接入包 | 停止所有已有通用包的新注册，已安装设备的独立凭据继续有效 |
| 撤销接入 | 撤销选中设备的接入身份 |
| 锁定并关闭 | 退出当前管理会话 |

安装后重新登录 Windows 可启动托盘，也可运行 `Ycsz.exe --tray`。按住 Shift 并左键点击托盘，输入密码进入管理界面。

## 卸载、重装与恢复

本版安装器不支持直接覆盖已有安装。管理端重装按以下顺序执行：

1. 备份 `C:\ProgramData\YcszFirewall` 到仅管理员可访问的位置。
2. 从本机管理页点击“卸载本机软件”，或使用控制面板卸载入口；通过 UAC 和管理密码验证后，在卸载向导中完成卸载。
3. 确认旧服务和安装登记已移除，再清理原安装目录。卸载会保留配置与日志，需将残留 `C:\ProgramData\YcszFirewall` 移至安全归档位置。
4. 运行新版完整安装包，选择管理端并重新初始化。
5. 验证服务、管理端登录和设备接入。

全新初始化不会自动导回旧设备、策略或证书。已有客户端依赖原管理端身份，需要保留接入关系时，应先制定配置恢复方案；不要直接重建管理端后认为旧客户端会自动迁移。本次已验证的实机重装在客户端列表为空时完成，见 [重装验收记录](docs/MANAGER-REINSTALL-2026-09-11.md)。

管理员紧急恢复，在管理员 PowerShell 中执行：

```powershell
& "$env:ProgramFiles\YcszFirewall\Ycsz.exe" --recover
```

恢复会停止服务；对客户端移除本产品的 WFP 规则并恢复本产品更改的审计设置。它不会删除网卡、清空全局防火墙或删除用户资料。服务保持停止，再次启动服务会重新应用策略。

## 已验证范围

| 验证环境 | 结果 |
| --- | --- |
| Windows CI | 44 项逻辑/ABI、2 项真实回环 TLS、9 项隔离网络逻辑测试通过；PowerShell 语法检查和 NSIS 打包通过 |
| 一次性 Windows 安全测试环境 | 36 条 PASS，覆盖标准用户权限限制、管理认证、设备身份隔离、撤销、服务恢复与持久化等 |
| 远程 Windows 管理主机 | v0.2.0 正常卸载、残留清理、完整安装、原密码登录通过；服务为 Running / AUTO_START / LocalSystem，程序哈希与发布产物一致 |

安全测试包含以无害程序副本验证进程名称检测，详细步骤与证据见 [通用客户端与反破坏验证](docs/UNIVERSAL-CLIENT-SECURITY.md)。这不代表完成了所有提权路径测试。客户端 WFP 实际阻断、网卡/代理回滚、双机策略联调及 Windows 重启场景仍待验收。

## 已知限制

- 防破坏针对标准用户；合法 Windows 管理员仍保留停止、恢复和卸载能力，不承诺抵御 SYSTEM、内核或离线磁盘修改。
- 网站白名单按域名解析出的 IP 放行 TCP 80/443。共享 CDN IP 可能使其他域名一并可达；不解密 TLS，不提供严格 HTTPS 域名过滤。
- 预置域名是待审核候选，不是全部备案网站，也未逐项实时核验 ICP 备案。站点的依赖域名需要管理员补齐。
- 进程按文件名识别，改名可规避名称匹配。网络出口限制是独立机制。
- DNS/DHCP、回环及限定程序的管理通道有必要例外；既有系统防火墙规则仍会影响访问。
- 可恢复网卡配置，不能自动重建已删除的第三方驱动或硬件。新增 IP 网卡的处理是禁用，不删除驱动。
- 通用包及密码泄露可能被用于占用设备配额，应停用旧包并重新生成。本地管理接口仍有可用性方面的已知限制，详见专项验证报告。
- 安装器与程序尚未进行商业代码签名。

## 从源码构建

程序使用 C#、WinForms 与 Windows 服务，编译目标为 .NET Framework 4.5 API，运行环境要求 .NET Framework 4.8；无需 NuGet 依赖。

Windows：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1
```

macOS 安装 Mono 和 NSIS 后：

```sh
./scripts/build.sh
```

输出包括 `artifacts/Ycsz-Setup-0.2.0-x64.exe` 和 `artifacts/Ycsz-Client-Setup.exe`。macOS 可设置 `YCSZ_PWSH=/path/to/pwsh`，同时执行回环 TLS 和 PowerShell 语法检查。

安全集成测试只在一次性 Windows 虚拟机运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-Security.ps1 -DisposableVm
```

该测试会创建临时标准用户及测试服务；检测到已有 YcszFirewall 服务、配置或 TCP 17443 监听时会拒绝执行。

## 项目文档

- [任务规格](TASK.md) · [执行计划](PLAN.md) · [架构说明](docs/ARCHITECTURE.md)
- [初始验证记录](docs/SECURITY-VALIDATION.md) · [Windows 验收清单](docs/WINDOWS-USER-TEST-CHECKLIST.md)
- [v0.1.0 安装恢复记录](docs/INSTALLER-RECOVERY-2026-09-11.md)
- [v0.2.0 管理端重装验收](docs/MANAGER-REINSTALL-2026-09-11.md)
- [通用客户端与反破坏验证](docs/UNIVERSAL-CLIENT-SECURITY.md)
