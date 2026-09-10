using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Ycsz {
    public static class Theme {
        public static readonly Color Blue=Color.FromArgb(31,90,152), Pale=Color.FromArgb(239,245,251), Ink=Color.FromArgb(30,48,67);
        public static void Style(Form f,string title,int width,int height) { f.Text=title; f.Size=new Size(width,height); f.MinimumSize=new Size(width,height); f.StartPosition=FormStartPosition.CenterScreen; f.Font=new Font("Microsoft YaHei UI",9); f.BackColor=Color.White; f.ForeColor=Ink; f.Icon=SystemIcons.Shield; }
        public static Label Header(string title,string subtitle) { return new Label { Text=title+Environment.NewLine+subtitle,Dock=DockStyle.Top,Height=88,BackColor=Blue,ForeColor=Color.White,Padding=new Padding(22,15,12,0),Font=new Font("Microsoft YaHei UI",12,FontStyle.Bold) }; }
        public static Button Button(string text,EventHandler action) { var b=new Button { Text=text,AutoSize=true,Height=34,Padding=new Padding(8,3,8,3),FlatStyle=FlatStyle.Flat,BackColor=Pale,Margin=new Padding(4) }; b.Click+=action; return b; }
        public static TextBox Box(bool password=false) { return new TextBox { Width=300,UseSystemPasswordChar=password,Margin=new Padding(5),MaxLength=password?256:32767 }; }
        public static void Row(TableLayoutPanel panel,string caption,Control control) { int row=panel.RowCount++; panel.RowStyles.Add(new RowStyle(SizeType.AutoSize)); panel.Controls.Add(new Label { Text=caption,AutoSize=true,Anchor=AnchorStyles.Left,Margin=new Padding(5,12,10,8) },0,row); control.Anchor=AnchorStyles.Left|AnchorStyles.Right; panel.Controls.Add(control,1,row); }
    }
    public sealed class PasswordDialog : Form {
        readonly TextBox password=Theme.Box(true); readonly Label error=new Label { AutoSize=true,ForeColor=Color.Firebrick,MaximumSize=new Size(350,0) };
        public string Session,Role; readonly PasswordRecord local; readonly LoginGate gate=new LoginGate();
        public PasswordDialog(string title,string subtitle,PasswordRecord record) {
            local=record; Theme.Style(this,title,460,265); FormBorderStyle=FormBorderStyle.FixedDialog; MaximizeBox=false; MinimizeBox=false;
            Controls.Add(Theme.Header(title,subtitle??"请输入管理密码"));
            var panel=new FlowLayoutPanel { Dock=DockStyle.Bottom,Height=130,Padding=new Padding(22,4,20,8),FlowDirection=FlowDirection.TopDown };
            password.Width=380; panel.Controls.Add(password); panel.Controls.Add(error);
            var button=Theme.Button("验证",async(s,e)=>await Login()); panel.Controls.Add(button); AcceptButton=button; Controls.Add(panel);
        }
        async Task Login() {
            Enabled=false; string value=password.Text; password.Clear();
            try {
                if(local!=null) { bool ok=await Task.Run(()=>gate.Check(value,local)); if(!ok) throw new InvalidOperationException("密码错误或尝试频繁，请稍后重试"); }
                else { var reply=await Task.Run(()=>Ipc.Call(new Packet { Op="login",Password=value })); Session=reply.Token; Role=reply.Data; }
                value=null; DialogResult=DialogResult.OK; Close();
            } catch(Exception e) { error.Text=e.Message; } finally { value=null; Enabled=true; }
        }
    }
    public sealed class TrayContext : ApplicationContext {
        readonly NotifyIcon tray; bool opened; readonly Timer timer=new Timer { Interval=15000 };
        public TrayContext() {
            tray=new NotifyIcon { Icon=SystemIcons.Shield,Text="YCSZ 机房防护 · SHIFT + 点击管理",Visible=true };
            tray.MouseClick+=(s,e)=> { if(e.Button==MouseButtons.Left && (Control.ModifierKeys&Keys.Shift)==Keys.Shift && !opened) { opened=true; try { Program.OpenConsole(); } finally { opened=false; } } };
            timer.Tick+=async(s,e)=> { RefreshProxy(); try { var status=await Task.Run(()=>Ipc.Call(new Packet { Op="status" })); string text="YCSZ · "+status.Status; tray.Text=text.Substring(0,Math.Min(63,text.Length)); } catch { tray.Text="YCSZ · 服务不可用，请联系管理员"; } }; timer.Start();
        }
        static void RefreshProxy() { InternetSetOption(IntPtr.Zero,39,IntPtr.Zero,0); InternetSetOption(IntPtr.Zero,37,IntPtr.Zero,0); }
        [DllImport("wininet.dll",SetLastError=true)] static extern bool InternetSetOption(IntPtr internet,int option,IntPtr buffer,int size);
        protected override void Dispose(bool disposing) { if(disposing) { timer.Dispose(); tray.Visible=false; tray.Dispose(); } base.Dispose(disposing); }
    }
    public sealed class ConsoleForm : Form {
        readonly string token,role; readonly DataGridView clients=new DataGridView(); readonly ListBox events=new ListBox { Dock=DockStyle.Fill,HorizontalScrollbar=true };
        readonly Label status=new Label { Dock=DockStyle.Top,Height=54,Padding=new Padding(12),BackColor=Theme.Pale };
        readonly TextBox whitelist=new TextBox { Multiline=true,Dock=DockStyle.Fill,ScrollBars=ScrollBars.Both };
        readonly Timer timer=new Timer { Interval=12000 }; ClientState selected; bool busy;
        readonly TabControl tabs=new TabControl { Dock=DockStyle.Fill,Padding=new Point(14,7) };
        public ConsoleForm(string session,string r) {
            token=session; role=r; Theme.Style(this,"YCSZ 教育机房防火墙 · "+(role=="manager"?"管理端":"客户端"),1040,700);
            Controls.Add(tabs); Controls.Add(status); Controls.Add(Theme.Header("YCSZ  教育机房防火墙",role=="manager"?"设备管理 · 策略下发 · 安全事件":"客户端管理 · 配置基线 · 安全事件"));
            var page=new TabPage(role=="manager"?"客户端设备":"本机状态") { BackColor=Color.White }; tabs.TabPages.Add(page);
            var actions=new FlowLayoutPanel { Dock=DockStyle.Top,Height=48,Padding=new Padding(6) };
            actions.Controls.Add(Theme.Button("刷新",async(s,e)=>await RefreshData()));
            if(role=="manager") {
                actions.Controls.Add(Theme.Button("生成通用客户端包",async(s,e)=>await Enroll()));
                actions.Controls.Add(Theme.Button("解冻出口",async(s,e)=>await Thaw(true)));
                actions.Controls.Add(Theme.Button("冻结出口",async(s,e)=>await Thaw(false)));
                actions.Controls.Add(Theme.Button("停用通用接入包",async(s,e)=> { if(MessageBox.Show("停用所有已导出的通用接入包？已注册设备不受影响；新安装需重新生成通用包。","停用接入包",MessageBoxButtons.YesNo)==DialogResult.Yes) await Perform(()=>Call("disable-bundles")); }));
                actions.Controls.Add(Theme.Button("撤销接入",async(s,e)=>await Revoke()));
                clients.Dock=DockStyle.Fill; clients.ReadOnly=true; clients.AllowUserToAddRows=false; clients.AllowUserToDeleteRows=false; clients.MultiSelect=false; clients.SelectionMode=DataGridViewSelectionMode.FullRowSelect; clients.AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill; clients.BackgroundColor=Color.White; clients.RowHeadersVisible=false; clients.AutoGenerateColumns=false;
                foreach(var col in new[]{new[]{"Name","设备名称"},new[]{"LastSeen","最近在线 UTC"},new[]{"Status","防护状态"}}) clients.Columns.Add(new DataGridViewTextBoxColumn { DataPropertyName=col[0],HeaderText=col[1] });
                clients.SelectionChanged+=async(s,e)=> { if(!busy) await LoadSelected(); };
                page.Controls.Add(clients);
            } else { var note=new Label { Dock=DockStyle.Fill,Padding=new Padding(25),Text="防护由 Windows 服务运行。关闭此窗口不会停止防护。\r\n\r\n重新打开管理页需要 SHIFT + 点击托盘并输入密码。\r\n\r\n网络配置变更请进入“网络与 hosts”页。",Font=new Font(Font.FontFamily,12) }; page.Controls.Add(note); }
            page.Controls.Add(actions);
            var net=new TabPage("网络与 hosts") { BackColor=Color.White }; tabs.TabPages.Add(net);
            var netActions=new FlowLayoutPanel { Dock=DockStyle.Top,Height=56,Padding=new Padding(8) };
            netActions.Controls.Add(Theme.Button("编辑所选设备基线",async(s,e)=>await EditNetwork()));
            if(role=="client") netActions.Controls.Add(Theme.Button("接纳当前网络为基线",async(s,e)=> { if(MessageBox.Show("将当前网络、网卡及 hosts 接纳为新基线。确认这些配置已经过管理员核验？","接纳基线",MessageBoxButtons.YesNo,MessageBoxIcon.Question)==DialogResult.Yes) await Perform(()=>Call("accept-baseline")); }));
            net.Controls.Add(new Label { Dock=DockStyle.Fill,Padding=new Padding(24,72,24,24),Text="只对当前所选客户端操作。远程变更先下发，客户端实际应用后回报。\r\n\r\n错误的 IP、DNS 或路由可能中断管理连接，请在受控环境验证。\r\n删除的网卡驱动或硬件需要管理员重新安装；配置快照无法重建驱动。" }); net.Controls.Add(netActions);
            var ev=new TabPage("安全事件"); ev.Controls.Add(events); tabs.TabPages.Add(ev);
            if(role=="manager") {
                var allow=new TabPage("统一白名单"); tabs.TabPages.Add(allow); allow.Controls.Add(whitelist);
                allow.Controls.Add(new Label { Dock=DockStyle.Top,Height=92,Padding=new Padding(12),Text="每行一个准确域名、IP 或 CIDR。网站放行 TCP 80/443；不支持 URL 路径和通配符。\r\n候选域名须自行审阅备案与教学用途。域名解析为 IP 放行，无法隔离同一 CDN IP 上的其他域名。\r\nDNS/DHCP、回环及限定程序的管理通道为必要例外。" });
                var save=Theme.Button("下发至所有客户端",async(s,e)=>await Perform(()=>Call("set-allow",Json.Encode(Rules.Validate(whitelist.Lines))))); save.Dock=DockStyle.Bottom; allow.Controls.Add(save);
            }
            var footer=new FlowLayoutPanel { Dock=DockStyle.Bottom,Height=48,FlowDirection=FlowDirection.RightToLeft,Padding=new Padding(4) };
            footer.Controls.Add(Theme.Button("锁定并关闭",(s,e)=>Close())); footer.Controls.Add(Theme.Button("卸载本机软件",(s,e)=>Uninstall())); Controls.Add(footer);
            Shown+=async(s,e)=> { await RefreshData(); if(role=="manager") await Perform(()=>{var p=Call("allow"); return p;},p=>whitelist.Lines=Json.Decode<List<string>>(p.Data).ToArray()); timer.Start(); };
            timer.Tick+=async(s,e)=> { if(!busy && tabs.SelectedIndex!=3) await RefreshData(); };
            FormClosed+=(s,e)=> { timer.Stop(); Task.Run(()=>{try{Call("logout");}catch{}}); };
        }
        Packet Call(string op,string data=null) { return Ipc.Call(new Packet { Op=op,Token=token,Data=data }); }
        async Task Perform(Func<Packet> work,Action<Packet> done=null) {
            if(busy) return; busy=true; UseWaitCursor=true; timer.Stop();
            try { var p=await Task.Run(work); if(done!=null) done(p); status.Text=p.Status??"操作完成"; }
            catch(Exception e) { MessageBox.Show(this,e.Message,"操作失败",MessageBoxButtons.OK,MessageBoxIcon.Error); }
            finally { busy=false; UseWaitCursor=false; if(!IsDisposed) timer.Start(); }
        }
        async Task RefreshData() {
            string id=SelectedId();
            if(role=="manager") {
                await Perform(()=>Call("list"),p=> {
                    var nodes=Json.Decode<List<ClientState>>(p.Data);
                    // WinForms binding requires properties, so expose anonymous view rows.
                    clients.DataSource=nodes.Select(c=>new { c.Id,c.Name,LastSeen=c.LastSeen??"未连接",Status=(c.Revoked?"[已撤销] ":"")+(c.Status??"等待上线")+" · 策略 "+c.AppliedRevision+"/"+c.Policy.Revision }).ToList();
                    foreach(DataGridViewRow row in clients.Rows) if((string)row.DataBoundItem.GetType().GetProperty("Id").GetValue(row.DataBoundItem,null)==id) { row.Selected=true; clients.CurrentCell=row.Cells[0]; break; }
                });
                await LoadSelected();
            } else await Perform(()=>Call("details"),ShowDetails);
        }
        string SelectedId() { if(role=="client") return selected==null?null:selected.Id; if(clients.CurrentRow==null || clients.CurrentRow.DataBoundItem==null) return null; var value=clients.CurrentRow.DataBoundItem; return (string)value.GetType().GetProperty("Id").GetValue(value,null); }
        async Task LoadSelected() { string id=SelectedId(); if(id!=null) await Perform(()=>Ipc.Call(new Packet { Op="details",Token=token,Id=id }),ShowDetails); }
        void ShowDetails(Packet p) { selected=Json.Decode<ClientState>(p.Data); events.Items.Clear(); foreach(var item in selected.Events.AsEnumerable().Reverse()) events.Items.Add(item.Utc+" · "+item.Kind+" · "+(item.Success?"成功":"告警/失败")+" · "+item.Detail); p.Status=selected.Name+" · "+selected.Status+" · 出口策略 "+selected.AppliedRevision+"/"+selected.Policy.Revision+" · 网络版本 "+selected.AppliedNetworkRevision; }
        async Task Thaw(bool value) { string id=SelectedId(); if(id==null) return; await Perform(()=>Ipc.Call(new Packet { Op="thaw",Token=token,Id=id,Thawed=value })); await RefreshData(); }
        async Task Revoke() { string id=SelectedId(); if(id==null) return; if(MessageBox.Show("撤销接入后，该客户端仍执行最后策略；需本机管理员恢复或卸载。继续？","撤销接入",MessageBoxButtons.YesNo)==DialogResult.Yes) { await Perform(()=>Ipc.Call(new Packet { Op="revoke",Token=token,Id=id })); await RefreshData(); } }
        async Task EditNetwork() {
            if(selected==null || selected.Network==null) { MessageBox.Show("请选择已上线并报告网络基线的客户端"); return; }
            string id=selected.Id;
            using(var editor=new NetworkEditor(selected.Network)) if(editor.ShowDialog(this)==DialogResult.OK) await Perform(()=>Ipc.Call(new Packet { Op="set-network",Token=token,Id=id,Network=editor.Result }));
        }
        async Task Enroll() {
            using(var dialog=new EnrollmentForm()) if(dialog.ShowDialog(this)==DialogResult.OK) {
                var host=dialog.HostAddress; var pass=dialog.ExportPassword; bool includeRuntime=dialog.IncludeRuntime;
                using(var save=new SaveFileDialog { Filter="通用客户端安装包|*.zip",FileName="Ycsz-Client-"+DateTime.Now.ToString("yyyyMMdd-HHmmss")+".zip" }) if(save.ShowDialog(this)==DialogResult.OK) {
                    string filename=save.FileName;
                    await Perform(()=> { string installer=ClientPackage.ResolveInstaller(includeRuntime); var p=Ipc.Call(new Packet { Op="create-bundle",Token=token,Data=host }); ClientPackage.Export(filename,Crypto.Seal(p.Data,pass),installer,includeRuntime); return new Packet { Ok=true,Status="通用客户端 ZIP 已保存；同一份包可安装多台，名称自动采用计算机名称" }; });
                }
                pass=null;
            }
            await RefreshData();
        }
        void Uninstall() { try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName=Path.Combine(Store.Bin,"Uninstall.exe"),Verb="runas",UseShellExecute=true }); Close(); } catch(Exception e) { MessageBox.Show(e.Message); } }
    }
    public sealed class EnrollmentForm : Form {
        readonly TextBox host=Theme.Box(),password=Theme.Box(true),confirm=Theme.Box(true);
        readonly CheckBox runtime=new CheckBox { Text="内置 .NET Framework 4.8（体积较大）",Checked=true,AutoSize=true };
        public bool IncludeRuntime { get { return runtime.Checked; } }
        public string HostAddress { get { return host.Text.Trim(); } } public string ExportPassword { get { return password.Text; } }
        public EnrollmentForm() {
            Theme.Style(this,"生成通用客户端包",650,460); var fields=new TableLayoutPanel { Dock=DockStyle.Fill,ColumnCount=2,Padding=new Padding(16) };
            Theme.Row(fields,"客户端名称",new Label { Text="自动采用各自的计算机名称",AutoSize=true }); Theme.Row(fields,"管理端固定 IPv4",host); Theme.Row(fields,"注册包密码（≥12 字符）",password); Theme.Row(fields,"再次输入注册包密码",confirm);
            Theme.Row(fields,"运行环境",runtime); Theme.Row(fields,"",new Label { Text="不内置版需客户端已有 .NET 4.8。管理端缺少内置版安装器时，需联网从本项目正式发布页获取并校验。",AutoSize=true,MaximumSize=new Size(430,0) });
            var button=Theme.Button("生成通用客户端 ZIP",(s,e)=> { try { Crypto.ValidatePassword(password.Text); if(password.Text!=confirm.Text) throw new ArgumentException("两次密码不一致"); IPAddress ip; if(!IPAddress.TryParse(host.Text,out ip)) throw new ArgumentException("IP 地址无效"); DialogResult=DialogResult.OK; } catch(Exception ex) { MessageBox.Show(ex.Message); } }); Theme.Row(fields,"",button); Controls.Add(fields);
        }
    }
    public sealed class NetworkEditor : Form {
        readonly NetworkSnapshot original; readonly DataGridView grid=new DataGridView { Dock=DockStyle.Fill,AllowUserToAddRows=false,AllowUserToDeleteRows=false,RowHeadersVisible=false,AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill };
        readonly TextBox hosts=new TextBox { Dock=DockStyle.Fill,Multiline=true,ScrollBars=ScrollBars.Both,AcceptsReturn=true,AcceptsTab=true,MaxLength=1000000 };
        public NetworkSnapshot Result;
        public NetworkEditor(NetworkSnapshot snapshot) {
            original=Json.Copy(snapshot); Theme.Style(this,"授权编辑网络基线",1100,600);
            var tabs=new TabControl { Dock=DockStyle.Fill }; var network=new TabPage("网卡 / 地址 / DNS"); var hostsPage=new TabPage("hosts"); tabs.TabPages.Add(network); tabs.TabPages.Add(hostsPage); network.Controls.Add(grid); hostsPage.Controls.Add(hosts); Controls.Add(tabs);
            grid.Columns.Add(new DataGridViewTextBoxColumn { Name="Name",HeaderText="网卡",ReadOnly=true });
            foreach(string title in new[]{"启用","DHCP","自动 DNS"}) grid.Columns.Add(new DataGridViewCheckBoxColumn { HeaderText=title });
            foreach(string title in new[]{"静态地址 IP/前缀（分号分隔）","默认网关","IPv4 DNS（分号分隔）"}) grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText=title });
            grid.Columns.Add(new DataGridViewCheckBoxColumn { HeaderText="自动 IPv6 DNS" }); grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText="IPv6 DNS（分号分隔）" });
            foreach(var a in original.Adapters) { var route=a.Routes.FirstOrDefault(r=>r.Prefix=="0.0.0.0/0"); grid.Rows.Add(a.Name,a.Enabled,a.Dhcp,a.DnsAutomatic,String.Join(";",a.Addresses.Select(x=>x.Address+"/"+x.Prefix)),route==null?"":route.NextHop,String.Join(";",a.Dns),a.DnsV6Automatic,String.Join(";",a.DnsV6)); }
            hosts.Text=System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(original.HostsBase64));
            var button=Theme.Button("保存并申请应用",(s,e)=>Save()); button.Dock=DockStyle.Bottom; Controls.Add(button);
            Controls.Add(new Label { Text="仅编辑已有网卡；路由和绑定未显示部分保持基线值。错误配置可能断网。",Dock=DockStyle.Top,Height=42,Padding=new Padding(10) });
        }
        void Save() {
            try {
                grid.EndEdit(); var output=Json.Copy(original);
                for(int i=0;i<output.Adapters.Length;i++) {
                    var a=output.Adapters[i]; var row=grid.Rows[i]; a.Enabled=Convert.ToBoolean(row.Cells[1].Value); a.Dhcp=Convert.ToBoolean(row.Cells[2].Value); a.DnsAutomatic=Convert.ToBoolean(row.Cells[3].Value);
                    a.Addresses=Split(row.Cells[4].Value).Select(x=> { var parts=x.Split('/'); if(parts.Length!=2) throw new ArgumentException("地址格式须为 IP/前缀"); return new IpSetting { Address=parts[0],Prefix=Int32.Parse(parts[1]) }; }).ToArray();
                    if(a.Dhcp && !original.Adapters[i].Dhcp) a.Addresses=a.Addresses.Where(x=>x.Address.Contains(":")).ToArray();
                    string gateway=Convert.ToString(row.Cells[5].Value).Trim(); var routes=a.Routes.Where(r=>r.Prefix!="0.0.0.0/0").ToList(); if(gateway.Length>0) { var old=a.Routes.FirstOrDefault(r=>r.Prefix=="0.0.0.0/0" && r.NextHop==gateway); routes.Add(new RouteSetting { Prefix="0.0.0.0/0",NextHop=gateway,Metric=old==null?256:old.Metric }); } a.Routes=routes.ToArray();
                    a.Dns=a.DnsAutomatic?new string[0]:Split(row.Cells[6].Value); if(!a.DnsAutomatic && a.Dns.Length==0) throw new ArgumentException("手工 DNS 不能为空");
                    a.DnsV6Automatic=Convert.ToBoolean(row.Cells[7].Value); a.DnsV6=a.DnsV6Automatic?new string[0]:Split(row.Cells[8].Value); if(!a.DnsV6Automatic && a.DnsV6.Length==0) throw new ArgumentException("手工 IPv6 DNS 不能为空");
                }
                string previous=System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(original.HostsBase64));
                if(hosts.Text!=previous) { output.HostsBase64=Convert.ToBase64String(new System.Text.UTF8Encoding(false).GetBytes(hosts.Text)); output.HostsExists=true; }
                output.Validate(); Result=output; DialogResult=DialogResult.OK;
            } catch(Exception e) { MessageBox.Show(e.Message,"配置无效"); }
        }
        static string[] Split(object value) { return Convert.ToString(value).Split(new[]{';','\r','\n'},StringSplitOptions.RemoveEmptyEntries).Select(x=>x.Trim()).Where(x=>x.Length>0).ToArray(); }
    }
    public sealed class SetupForm : Form {
        readonly ComboBox role=new ComboBox { DropDownStyle=ComboBoxStyle.DropDownList,Width=300 };
        readonly TextBox password=Theme.Box(true),confirm=Theme.Box(true),package=Theme.Box(),packagePassword=Theme.Box(true);
        readonly Label message=new Label { AutoSize=true,MaximumSize=new Size(520,0) };
        public SetupForm(bool clientOnly=false) {
            Theme.Style(this,"YCSZ 初始化",670,480); FormBorderStyle=FormBorderStyle.FixedDialog; MaximizeBox=false;
            Controls.Add(Theme.Header("首次安装初始化","密码不会明文保存；安装后在管理端注册客户端"));
            var fields=new TableLayoutPanel { Dock=DockStyle.Bottom,Height=330,ColumnCount=2,Padding=new Padding(20) };
            role.Items.AddRange(new object[]{"管理端","客户端"}); role.SelectedIndex=clientOnly?1:0; role.Enabled=!clientOnly;
            Theme.Row(fields,"安装角色",role); Theme.Row(fields,"本机管理密码（≥12 字符）",password); Theme.Row(fields,"再次输入密码",confirm);
            package.ReadOnly=true; var file=new FlowLayoutPanel { AutoSize=true }; file.Controls.Add(package); file.Controls.Add(Theme.Button("选择…",(s,e)=> { using(var open=new OpenFileDialog { Filter="注册包|*.ycsz" }) if(open.ShowDialog()==DialogResult.OK) package.Text=open.FileName; }));
            Theme.Row(fields,"客户端注册包",file); Theme.Row(fields,"注册包密码",packagePassword);
            var button=Theme.Button("完成初始化",async(s,e)=>await Initialize()); Theme.Row(fields,"",button); Theme.Row(fields,"",message); Controls.Add(fields);
            role.SelectedIndexChanged+=(s,e)=> { file.Enabled=packagePassword.Enabled=role.SelectedIndex==1; }; file.Enabled=packagePassword.Enabled=clientOnly;
            if(clientOnly && File.Exists(Path.Combine(Store.Bin,"client.ycsz"))) package.Text=Path.Combine(Store.Bin,"client.ycsz");
        }
        async Task Initialize() {
            Enabled=false;
            try {
                string secret=password.Text; Crypto.ValidatePassword(secret); if(secret!=confirm.Text) throw new ArgumentException("两次密码不一致");
                string r=role.SelectedIndex==0?"manager":"client",filename=package.Text,packageSecret=packagePassword.Text;
                await Task.Run(()=> {
                    if(Store.Exists("settings.bin")) throw new InvalidOperationException("已存在配置；请先通过管理入口卸载，避免覆盖现有基线");
                    Store.Initialize();
                    var settings=new Settings { Role=r,Password=Crypto.HashPassword(secret) };
                    if(r=="manager") {
                        settings.PfxPassword=Crypto.Token(); PowerShell.Run("certificate",Json.Encode(new { Path=Store.PathFor("manager.pfx"),Password=settings.PfxPassword }));
                        var cert=new X509Certificate2(Store.PathFor("manager.pfx"),settings.PfxPassword,X509KeyStorageFlags.MachineKeySet); try { settings.CertificateHash=Crypto.Sha256(cert.RawData); } finally { cert.Reset(); }
                        Store.Save("manager.bin",new ManagerState());
                    } else {
                        if(!File.Exists(filename) || new FileInfo(filename).Length>Wire.MaxFrame) throw new InvalidDataException("请选择有效注册包");
                        var e=Json.Decode<Enrollment>(Crypto.Open(File.ReadAllBytes(filename),packageSecret));
                        EnrollmentRegistry.Validate(e);
                        if(e.Universal) {
                            var bundle=e;
                            e=Store.Exists("pending-enrollment.bin")?Store.Load<Enrollment>("pending-enrollment.bin"):null;
                            if(!EnrollmentRegistry.SameBundle(e,bundle)) e=EnrollmentRegistry.NewIdentity(bundle,Environment.MachineName);
                            EnrollmentRegistry.Validate(e); e.Name=EnrollmentRegistry.ComputerName(Environment.MachineName);
                            // Persist the identity before contacting the server so lost responses are retryable.
                            Store.Save("pending-enrollment.bin",e);
                            var registered=Wire.Heartbeat(bundle,new Packet { Op="register",Id=e.ClientId,Token=bundle.Token,BundleId=bundle.BundleId,Name=e.Name,Data=e.Token });
                            if(!registered.Ok) throw new InvalidOperationException(registered.Error??"管理端拒绝注册");
                        }
                        e.Name=EnrollmentRegistry.ComputerName(Environment.MachineName);
                        settings.Enrollment=e;
                        // Verify server identity and credential BEFORE applying any firewall policy.
                        var baseline=PowerShell.Capture(); var response=Wire.Heartbeat(e,new Packet { Op="heartbeat",Events=new List<SecurityEvent>(),Network=baseline,Status="安装初始化验证" });
                        if(!response.Ok || response.Policy==null) throw new InvalidOperationException("管理端未确认接入："+response.Error);
                        response.Policy.Allow=Rules.Validate(response.Policy.Allow);
                        Store.Save("client.bin",new ClientDisk { Baseline=baseline,Policy=response.Policy }); Store.Save("installation-baseline.bin",baseline);
                    }
                    Store.Save("settings.bin",settings);
                    try { File.Delete(Store.PathFor("pending-enrollment.bin")); } catch(IOException ex) { Store.Log("Pending enrollment cleanup: "+ex.GetType().Name); }
                });
                password.Clear(); confirm.Clear(); packagePassword.Clear(); secret=null; packageSecret=null; DialogResult=DialogResult.OK;
            } catch(Exception e) { message.Text=e.Message; } finally { Enabled=true; }
        }
    }
}
