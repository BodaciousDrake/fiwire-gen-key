﻿using Microsoft.Extensions.Configuration;
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
                Console.WriteLine(Encrypt(
                    plainText: GetValueToEncrypt(appSettings.SharedSecret), 
                    skey: appSettings.Key,
                    sIV_value: appSettings.IV,
                    keySize: 256
                ));
                
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

        public static string Encrypt(string plainText,
                                     string skey,
                                     string sIV_value,
                                     int keySize)
        {
            RijndaelManaged myRijndael = new RijndaelManaged
            {
                Mode = CipherMode.CBC,
                BlockSize = 128,
                KeySize = keySize,
                Padding = PaddingMode.PKCS7,
                IV = Encoding.ASCII.GetBytes(sIV_value),
                Key = Encoding.ASCII.GetBytes(skey)
            };

            //Get an encryptor.
            var encryptor = myRijndael.CreateEncryptor(myRijndael.Key, myRijndael.IV);
            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);

            //Convert the data to a byte array.
            var toEncrypt = Encoding.ASCII.GetBytes(plainText);

            //Write all data to the crypto stream and flush it.
            csEncrypt.Write(toEncrypt, 0, toEncrypt.Length);
            csEncrypt.FlushFinalBlock();

            // return the encrypted array of bytes encoded using b64
            return Convert.ToBase64String(msEncrypt.ToArray());
        }
    }
}
