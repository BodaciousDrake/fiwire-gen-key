using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CreateEncryptionKeyFiwire
{
    /// <summary>
    /// This program serves to generate a b64 encoded string that is used
    /// as an authentication key for Fiwire.
    /// </summary>
    class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                //get settings from appsettings.json
                var builder = new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                    .Build();
                var appSettings = new FiwireSettings();
                builder.Bind("FiwireSettings", appSettings);
               
                //get the encrypted string as a bytearray
                byte[] encrypted = EncryptStringToBytes(
                    plainText: GetValueToEncrypt(appSettings.SharedSecret), 
                    key: Encoding.ASCII.GetBytes(appSettings.Key),
                    IV: Encoding.ASCII.GetBytes(appSettings.IV)
                );

                //print the encrypted string to the console using b64 encoding (end of program)
                Console.WriteLine(Convert.ToBase64String(encrypted));
                
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }

        /// <summary>
        /// The actual value that is encrypted is the current date/time
        /// and a shared key provided by Fiserv.
        /// </summary>
        /// <param name="sharedValue">The shared key provided by Fiserv</param>
        /// <returns>A formatted string ready to be encrypted</returns>
        private static string GetValueToEncrypt(string sharedValue)
        {
            return $"{DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss")}|{sharedValue}";
        }

        /// <summary>
        /// Take a given string and encrypt it according to Fiwire requirements
        /// </summary>
        /// <param name="plainText">The text to be encrypted</param>
        /// <returns>the encrypted string</returns>
        private static byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] IV)
        {
            //setup the Rijndael encryption
            using RijndaelManaged rijAlg = new RijndaelManaged
            {
                BlockSize = 128,
                KeySize = 256,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC,
                Key = key,
                IV = IV
            };

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = rijAlg.CreateEncryptor();

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
