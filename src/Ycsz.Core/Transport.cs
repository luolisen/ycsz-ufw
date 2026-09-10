using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Ycsz {
    public static class Wire {
        public const int MaxFrame = 1024 * 1024;
        public static void Send(Stream stream, Packet packet) {
            var bytes = Encoding.UTF8.GetBytes(Json.Encode(packet)); if (bytes.Length > MaxFrame) throw new InvalidDataException("消息过大");
            var length = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(bytes.Length)); stream.Write(length,0,4); stream.Write(bytes,0,bytes.Length); stream.Flush();
        }
        public static Packet Receive(Stream stream) {
            byte[] length = Read(stream,4); int size = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(length,0));
            if (size <= 0 || size > MaxFrame) throw new InvalidDataException("消息长度无效");
            var result = Json.Decode<Packet>(Encoding.UTF8.GetString(Read(stream,size))); if (result == null) throw new InvalidDataException("空消息"); return result;
        }
        static byte[] Read(Stream stream,int size) { var data = new byte[size]; int done = 0; while (done < size) { int got = stream.Read(data,done,size-done); if (got == 0) throw new EndOfStreamException(); done += got; } return data; }
        public static bool CertificateAccepted(X509Certificate certificate,string pin) {
            if(certificate==null) return false;
            var cert=new X509Certificate2(certificate);
            try { return DateTime.UtcNow>=cert.NotBefore.ToUniversalTime() && DateTime.UtcNow<=cert.NotAfter.ToUniversalTime() && Crypto.EqualText(Crypto.Sha256(cert.RawData),pin); } finally { cert.Reset(); }
        }
        public static Packet Heartbeat(Enrollment enrollment, Packet packet) {
            using (var tcp = new TcpClient()) {
                var pending = tcp.BeginConnect(enrollment.Host,enrollment.Port,null,null);
                using (pending.AsyncWaitHandle) if (!pending.AsyncWaitHandle.WaitOne(8000)) throw new TimeoutException("管理端连接超时");
                tcp.EndConnect(pending); tcp.ReceiveTimeout = 12000; tcp.SendTimeout = 12000;
                using (var tls = new SslStream(tcp.GetStream(),false,(sender,cert,chain,errors) => CertificateAccepted(cert,enrollment.CertificateHash))) {
                    tls.ReadTimeout = 12000; tls.WriteTimeout = 12000;
                    tls.AuthenticateAsClient(enrollment.Host,null,SslProtocols.Tls12,false);
                    packet.Id = enrollment.ClientId; packet.Token = enrollment.Token; Send(tls,packet); return Receive(tls);
                }
            }
        }
    }
}
