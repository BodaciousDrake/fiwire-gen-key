using System;
using System.IO;
using System.Security.Cryptography;
using CommandLine;
using System.Collections.Generic;

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
                //parse the command line arguments
                Parser.Default.ParseArguments<CommandLineOptions>(args)
                  .WithParsed(HandleParsed)
                  .WithNotParsed(HandleParseError);
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }

        /// <summary>
        /// If all the required command line arguments are present,
        /// this method does the work of generating the required string.
        /// </summary>
        /// <param name="options">options from the command line</param>
        private static void HandleParsed(CommandLineOptions options)
        {
            //get the encrypted string as a bytearray
            byte[] encrypted = EncryptStringToBytes(
                plainText: GetValueToEncrypt(options.SharedSecret), 
                Key: Convert.FromBase64String(options.KeyValue), 
                IV: Convert.FromBase64String(options.IVValue)
            );

            //print the encrypted string to the console using b64 encoding (end of program)
            Console.WriteLine(Convert.ToBase64String(encrypted));
        }

        /// <summary>
        /// If the command line option requirements are not met, 
        /// spit out the errors on the command line.
        /// </summary>
        /// <param name="errs">a list of errors from parsing the command line options</param>
        private static void HandleParseError(IEnumerable<Error> errs)
        {
            foreach(var err in errs)
            {
                Console.WriteLine(err.ToString());
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
        /// <param name="Key">The private key (provided by Fiserv)</param>
        /// <param name="IV">The initialization vector (provided by Fiserv)</param>
        /// <returns></returns>
        private static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            //setup the Rijndael encryption
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
