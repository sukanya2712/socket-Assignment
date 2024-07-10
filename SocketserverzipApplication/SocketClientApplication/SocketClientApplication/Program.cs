using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;


namespace SocketClientApplication
{
    public class Program
    {
        static readonly Dictionary<string, Dictionary<string, int>> dataCollection = new Dictionary<string, Dictionary<string, int>>()
        {
        { "SetA", new Dictionary<string, int> { { "One", 1 }, { "Two", 2 } } },
        { "SetB", new Dictionary<string, int> { { "Three", 3 }, { "Four", 4 } } },
        { "SetC", new Dictionary<string, int> { { "Five", 5 }, { "Six", 6 } } },
        { "SetD", new Dictionary<string, int> { { "Seven", 7 }, { "Eight", 8 } } },
        { "SetE", new Dictionary<string, int> { { "Nine", 9 }, { "Ten", 10 } } }
        };


        static readonly byte[] Key = Encoding.ASCII.GetBytes("A4B94C4D3E2F6A1C5B2F1A4B9D3C4E8F"); // 32 bytes for AES-256
        static readonly byte[] IV = Encoding.ASCII.GetBytes("A1B2C3D4E5F60708"); // 16 bytes for AES

        static void Main(string[] args)
        {
            TcpListener server = new TcpListener(IPAddress.Any, 65432);
            server.Start();
            Console.WriteLine("Server started and listening...");

            while (true)
            {
                TcpClient client = server.AcceptTcpClient();
                Thread clientThread = new Thread(new ParameterizedThreadStart(HandleClient));
                clientThread.Start(client);
            }
        }

        static void HandleClient(object clientObj)
        {

            TcpClient client = (TcpClient)clientObj;
            NetworkStream stream = client.GetStream();

            byte[] buffer = new byte[1024];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            byte[] encryptedMessage = new byte[bytesRead];
            Array.Copy(buffer, 0, encryptedMessage, 0, bytesRead);
            Console.WriteLine($"ReceivedencryptedMessage: {encryptedMessage}");
            string message = EncryptionHelper.DecryptStringFromBytes_Aes(encryptedMessage, Key, IV);
            Console.WriteLine($"Received Actualmessage: {message}");

            string responseMessage;
            if (message.Length < 4)
            {
                byte[] response = Encoding.ASCII.GetBytes("EMPTY");
                stream.Write(response, 0, response.Length);
                client.Close();
                return;
            }
            else
            {
                string setKey = message.Substring(0, 4);
                string itemKey = message.Substring(4);

                if (dataCollection.ContainsKey(setKey) && dataCollection[setKey].ContainsKey(itemKey))
                {
                    int value = dataCollection[setKey][itemKey];
                    for (int i = 0; i < value; i++)
                    {
                        string currentTime = DateTime.Now.ToString();
                        byte[] response = EncryptionHelper.EncryptStringToBytes_Aes(currentTime, Key, IV);
                        stream.Write(response, 0, response.Length);
                        Thread.Sleep(1000);
                    }
                    return;
                }
                else
                {
                    responseMessage = "EMPTY";
                }
            }

            byte[] encryptedResponse = EncryptionHelper.EncryptStringToBytes_Aes(responseMessage, Key, IV);
            stream.Write(encryptedResponse, 0, encryptedResponse.Length);

            client.Close();
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





