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

                //print the encrypted string to the console
                Console.WriteLine(EncryptString(
                    plainText: GetValueToEncrypt(appSettings.SharedSecret),
                    key: appSettings.Key,
                    IV: appSettings.IV
                ));                
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message}");
            }
        }

        /// <summary>
        /// The actual value that is encrypted is the current date/time
        /// and a shared value provided by Fiserv.
        /// </summary>
        /// <param name="sharedValue">The shared value provided by Fiserv</param>
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
        private static string EncryptString(string plainText, string key, string IV)
        {
            //setup the Rijndael encryption
            using var rijAlg = new RijndaelManaged
            {
                BlockSize = 128,
                KeySize = 256,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC,
                Key = Encoding.ASCII.GetBytes(key),
                IV = Encoding.ASCII.GetBytes(IV)
            };

            // Create an encryptor to perform the stream transform.
            var encryptor = rijAlg.CreateEncryptor();

            // Create the streams used for encryption.
            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using (var swEncrypt = new StreamWriter(csEncrypt))
            {
                //Write all data to the stream.
                swEncrypt.Write(plainText);
            }

            // Return the encrypted bytes from the memory stream encoded with b64
            return Convert.ToBase64String(msEncrypt.ToArray());
        }
    }
}
