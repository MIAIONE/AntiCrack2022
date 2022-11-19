using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using Windows.Security.Cryptography.DataProtection;
using Windows.Storage.Streams;

namespace AntiCrack2022
{
    internal class App
    {
        private static readonly DynamicLoader Loader = new();
        private static readonly AntiDebugger AntDb = new(Loader);
        
        
        public static void Main()
        {
            
            AntDb.Watch();
            CheckDebugger();
            var ssk = GetSecureString(GetPassword());
            CheckDebugger();
            Console.WriteLine("Please input code:");
            CheckDebugger();
            if (VerifyString(ssk, Console.ReadLine()))
            {
                CheckDebugger();
                Console.WriteLine(new char[] { 'S', 'u', 'c', 'e', 's','s' });
                
            }
            else
            {
                CheckDebugger();
                Console.WriteLine(new char[] { 'E','r','r','o','r'});
            }
            Console.ReadKey();
        }
        private static void CheckDebugger()
        {
            if (AntDb.IsDebug())
            {
                Environment.Exit(0);
            }
        }

        private static SecureString GetSecureString(params char[] text)
        {
            var result = new SecureString();
            foreach (char c in text)
            {
                result.AppendChar(c);
            }
            result.MakeReadOnly();
            return result;
        }
        private static bool VerifyString(SecureString ss, string? exString)
        {
            IntPtr uniStr = IntPtr.Zero;
            try
            {
                uniStr = SecureStringMarshal.SecureStringToCoTaskMemUnicode(ss);
                var acString = Marshal.PtrToStringUni(uniStr);
                if(acString is not null)
                {
                    return acString == exString;
                }
                return false;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (uniStr != IntPtr.Zero)
                    Marshal.ZeroFreeCoTaskMemUnicode(uniStr);
            }
        }
        private static char[] GetPassword()
        {
            var rsa = new RSACng(2048);
            return Convert.ToHexString(rsa.ExportRSAPrivateKey()).ToCharArray();
        }
    }
}