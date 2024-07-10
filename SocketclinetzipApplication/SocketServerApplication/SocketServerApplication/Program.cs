using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace SocketServerApplication
{
    public class Program
    {
        static readonly byte[] Key = Encoding.ASCII.GetBytes("A4B94C4D3E2F6A1C5B2F1A4B9D3C4E8F"); // 32 bytes for AES-256
        static readonly byte[] IV = Encoding.ASCII.GetBytes("A1B2C3D4E5F60708"); // 16 bytes for AES
        static void Main(string[] args)
        {
            
            try
            {
                string serverIp = "127.0.0.1";
                int serverPort = 65432;
                string message = "Set";

                TcpClient client = new TcpClient();
                client.Connect(serverIp, serverPort);
                NetworkStream stream = client.GetStream();

                byte[] data = EncryptionHelper.EncryptStringToBytes_Aes(message, Key, IV);
                stream.Write(data, 0, data.Length);

                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    byte[] encryptedResponse = new byte[bytesRead];
                    Array.Copy(buffer, 0, encryptedResponse, 0, bytesRead);
                    Console.WriteLine($"Received encryptedResponse: {encryptedResponse}");
                    string response = EncryptionHelper.DecryptStringFromBytes_Aes(encryptedResponse, Key, IV);
                    Console.WriteLine($"Received: {response}");
                }

                client.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        public static class EncryptionHelper
        {
            public static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
            {
                if (plainText == null || plainText.Length <= 0)
                    throw new ArgumentNullException("plainText");
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");

                byte[] encrypted;

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Key;
                    aesAlg.IV = IV;

                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(plainText);
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }

                return encrypted;
            }

            public static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
            {
                if (cipherText == null || cipherText.Length <= 0)
                    throw new ArgumentNullException("cipherText");
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");

                string plaintext = null;

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Key;
                    aesAlg.IV = IV;

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }

                return plaintext;
            }
        }
    }
}




