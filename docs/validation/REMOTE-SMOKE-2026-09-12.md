# 用户请求测试：2026-09-12

本次实际通过向日葵连接 STU01（备注学生1），没有重启、部署或加载驱动。

- 本地最新 Core/App/Tests 编译成功，61/61 通过；bash 语法与 git diff --check 通过。
- 远程 `get-service ycszfirewall` 为 Running。
- `sc.exe query ycszprotection` 返回 1060，指定服务未安装；当前没有内核防护验收条件。
- 测试前托盘 PID 1560/session1，核心 PID 9428/session0。
- `taskkill /pid 1560 /f` 显示成功结束进程；后续查询托盘已自动恢复为 PID 8384/session1，核心仍为 PID 9428/session0，服务 Running。

结论：当前已安装版的托盘终止后恢复通过；这同时证明托盘可以被强制结束，不能标为防终止通过。本地最新开发代码没有在本次部署到学生机。防删除未执行破坏性试验，防终止/防删除总体仍未通过验收。后续需完成代码缺口及独立 Windows WDK/签名/加载验证。
