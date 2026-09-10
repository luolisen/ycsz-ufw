using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Ycsz;
class TlsProbe {
    static int Main(string[] args) {
        var cert=new X509Certificate2(args[0],"ycsz-test-only-123");
        try {
            Probe(cert,Crypto.Sha256(cert.RawData),true);
            Probe(cert,new string('0',64),false);
            Console.WriteLine("RESULT 2/2 real loopback TLS transport probes passed on this host runtime"); return 0;
        } catch(Exception e) { Console.WriteLine("FAIL "+e); return 1; } finally { cert.Reset(); }
    }
    static void Probe(X509Certificate2 cert,string pin,bool shouldSucceed) {
        var listener=new TcpListener(IPAddress.Loopback,0); listener.Start(); int port=((IPEndPoint)listener.LocalEndpoint).Port;
        Exception serverError=null;
        var server=new Thread(()=> {
            try { using(var socket=listener.AcceptTcpClient()) using(var stream=new SslStream(socket.GetStream(),false)) { stream.ReadTimeout=5000; stream.WriteTimeout=5000; stream.AuthenticateAsServer(cert,false,SslProtocols.Tls12,false); var request=Wire.Receive(stream); if(request.Op!="heartbeat") throw new Exception("wrong frame"); Wire.Send(stream,new Packet { Ok=true,Data="TLS echo" }); } }
            catch(Exception e) { serverError=e; }
        }) { IsBackground=true };
        server.Start(); bool succeeded=false;
        try { var reply=Wire.Heartbeat(new Enrollment { Host="127.0.0.1",Port=port,CertificateHash=pin,ClientId="fixture",Token="fixture" },new Packet { Op="heartbeat" }); succeeded=reply.Ok && reply.Data=="TLS echo"; }
        catch(AuthenticationException) { if(shouldSucceed) throw; }
        catch(System.IO.IOException) { if(shouldSucceed) throw; }
        finally { listener.Stop(); server.Join(8000); }
        if(succeeded!=shouldSucceed) throw new Exception("pin validation result unexpected");
        if(shouldSucceed && serverError!=null) throw serverError;
        Console.WriteLine("PASS "+(shouldSucceed?"TLS 1.2 pinned certificate and framed heartbeat":"mismatched certificate pin rejected"));
    }
}
