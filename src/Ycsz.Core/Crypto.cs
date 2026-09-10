using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Ycsz {
    public static class Crypto {
        public const int Iterations = 210000;
        public static byte[] Random(int size) { byte[] b = new byte[size]; using (var r = RandomNumberGenerator.Create()) r.GetBytes(b); return b; }
        public static string Token() { return Convert.ToBase64String(Random(32)); }
        public static void ValidatePassword(string password) { if (password == null || password.Length < 12 || password.Length > 256) throw new ArgumentException("密码须为 12–256 个字符"); }
        static byte[] Derive(string password, byte[] salt, int count, int size) { using (var d = new Rfc2898DeriveBytes(password, salt, count)) return d.GetBytes(size); }
        public static PasswordRecord HashPassword(string password) {
            ValidatePassword(password); byte[] salt = Random(32);
            return new PasswordRecord { Salt = Convert.ToBase64String(salt), Iterations = Iterations, Hash = Convert.ToBase64String(Derive(password,salt,Iterations,32)) };
        }
        public static bool Verify(string password, PasswordRecord record) {
            if (password == null || password.Length > 256 || record == null || record.Iterations < 100000 || record.Iterations > 1000000) return false;
            try { return Equal(Derive(password,Convert.FromBase64String(record.Salt),record.Iterations,32),Convert.FromBase64String(record.Hash)); } catch { return false; }
        }
        public static bool Equal(byte[] a, byte[] b) { if (a == null || b == null) return false; int diff = a.Length ^ b.Length; for (int i = 0; i < a.Length; i++) diff |= a[i] ^ (i < b.Length ? b[i] : 0); return diff == 0; }
        public static bool EqualText(string a,string b) { return a != null && b != null && Equal(Encoding.UTF8.GetBytes(a),Encoding.UTF8.GetBytes(b)); }
        public static string Sha256(byte[] data) { using (var h = SHA256.Create()) return BitConverter.ToString(h.ComputeHash(data)).Replace("-","").ToLowerInvariant(); }
        // Versioned encrypt-then-MAC envelope. Authenticate BEFORE CBC decryption.
        public static byte[] Seal(string text, string password) {
            ValidatePassword(password); byte[] salt = Random(32), iv = Random(16), key = Derive(password,salt,Iterations,64), cipher;
            using (var aes = Aes.Create()) { aes.Key = Slice(key,0,32); aes.IV = iv; using (var enc = aes.CreateEncryptor()) { var bytes = Encoding.UTF8.GetBytes(text); cipher = enc.TransformFinalBlock(bytes,0,bytes.Length); } }
            byte[] body;
            using (var ms = new MemoryStream()) { ms.Write(new byte[]{89,67,83,90,1},0,5); ms.Write(salt,0,32); ms.Write(iv,0,16); ms.Write(cipher,0,cipher.Length); body = ms.ToArray(); }
            using (var mac = new HMACSHA256(Slice(key,32,32))) { var tag = mac.ComputeHash(body); var result = new byte[body.Length+32]; Buffer.BlockCopy(body,0,result,0,body.Length); Buffer.BlockCopy(tag,0,result,body.Length,32); Array.Clear(key,0,key.Length); return result; }
        }
        public static string Open(byte[] data, string password) {
            if (data == null || data.Length < 101 || data.Length > 1024*1024 || !Equal(Slice(data,0,5),new byte[]{89,67,83,90,1})) throw new InvalidDataException("注册包格式无效");
            ValidatePassword(password); var key = Derive(password,Slice(data,5,32),Iterations,64);
            try {
                using (var mac = new HMACSHA256(Slice(key,32,32))) if (!Equal(mac.ComputeHash(data,0,data.Length-32),Slice(data,data.Length-32,32))) throw new CryptographicException("注册包密码错误或内容被篡改");
                using (var aes = Aes.Create()) { aes.Key = Slice(key,0,32); aes.IV = Slice(data,37,16); using (var dec = aes.CreateDecryptor()) return Encoding.UTF8.GetString(dec.TransformFinalBlock(data,53,data.Length-85)); }
            } finally { Array.Clear(key,0,key.Length); }
        }
        static byte[] Slice(byte[] input,int offset,int count) { var b = new byte[count]; Buffer.BlockCopy(input,offset,b,0,count); return b; }
    }
    public sealed class LoginGate {
        int failures; DateTime next = DateTime.MinValue;
        public bool Check(string password, PasswordRecord record) {
            lock (this) {
                if (DateTime.UtcNow < next) return false;
                if (Crypto.Verify(password,record)) { failures = 0; return true; }
                failures++; next = DateTime.UtcNow.AddSeconds(Math.Min(60,Math.Pow(2,Math.Min(failures,6)))); return false;
            }
        }
    }
}
