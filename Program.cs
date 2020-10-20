using System;
using System.IO;
using System.Security.Cryptography;
using CommandLine;
using System.Collections.Generic;

namespace CreateEncryptionKeyFiwire
{
    class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                Parser.Default.ParseArguments<CommandLineOptions>(args)
                  .WithParsed(HandleParsed)
                  .WithNotParsed(HandleParseError);
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }

        private static void HandleParsed(CommandLineOptions options)
        {
            byte[] encrypted = EncryptStringToBytes(
                plainText: GetValueToEncrypt(options.SharedSecret), 
                Key: Convert.FromBase64String(options.KeyValue), 
                IV: Convert.FromBase64String(options.IVValue)
            );

            Console.WriteLine(Convert.ToBase64String(encrypted));
            Console.ReadKey();
        }

        private static void HandleParseError(IEnumerable<Error> errs)
        {
            foreach(var err in errs)
            {
                Console.WriteLine(err.ToString());
            }
        }

        private static string GetValueToEncrypt(string sharedValue)
        {
            return $"{DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss")}|{sharedValue}";
        }

        private static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            using RijndaelManaged rijAlg = new RijndaelManaged
            {
                BlockSize = 128,
                KeySize = 256,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC,
                Key = Key,
                IV = IV
            };

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

            // Create the streams used for encryption.
            using MemoryStream msEncrypt = new MemoryStream();                
            using CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
            {
                //Write all data to the stream.
                swEncrypt.Write(plainText);
            }

            // Return the encrypted bytes from the memory stream.
            return msEncrypt.ToArray();
        }
    }
}
