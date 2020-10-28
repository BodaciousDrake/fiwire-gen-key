using CommandLine;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Linq;
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
                //parse command line arguments, if any
                var parsedArgs = Parser.Default.ParseArguments<CommandLineOptions>(args)
                    .WithParsed(PerformEncryptionOperation) //valid settings, so do work
                    .WithNotParsed(errors => //invalid settings, print errors
                    {
                        //don't include helprequested error
                        var err = errors
                            .Where(e => !(e is HelpRequestedError))
                            .Select(e => e.ToString());

                        if (err.Count() > 0)
                            Console.WriteLine($"Error parsing command line arguments: {string.Join(", ", err)}");
                    });
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message}");
            }
        }

        /// <summary>
        /// If the user supplied valid cmd line args and we found the settings file
        /// then perform the encrypt/decrypt operation.
        /// </summary>
        /// <param name="opts">The options from the command line (optional)</param>
        private static void PerformEncryptionOperation(CommandLineOptions opts)
        {
            //get settings from appsettings.json
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory());

            //set default value for settings file name
            var fileName = "appsettings.json";

            //check to see if the user specified an alternate location for the appsettings
            if (opts.AppSettingsPath != null)
            {
                //set the working directory to the user-specified directory
                builder.SetBasePath(Path.GetDirectoryName(opts.AppSettingsPath));

                //if the user did not specify a file name, default to appsettings.json
                //otherwise, use the name they specified
                if (Path.HasExtension(opts.AppSettingsPath))
                    fileName = Path.GetFileName(opts.AppSettingsPath);
            }

            var built = builder
                .AddJsonFile(fileName, optional: false, reloadOnChange: true)
                .Build();

            //bind the settings file to a settings object
            var appSettings = new FiwireSettings();
            built.Bind("FiwireSettings", appSettings);

            //setup the encryption based on fiserv settings
            var rijAlg = GetRijndaelManaged(appSettings.Key, appSettings.IV);

            //check to see if the user requested a decrypt
            if (!string.IsNullOrWhiteSpace(opts.ToDecrypt))
                Console.WriteLine(DecryptString(opts.ToDecrypt, rijAlg));
            else  // print the encrypted string to the console
                Console.WriteLine(EncryptString(GetValueToEncrypt(appSettings.SharedSecret), rijAlg));
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
        /// Build an encryptor based on the correct settings
        /// </summary>
        /// <param name="key">The key to use to encrypt/decrypt</param>
        /// <param name="IV">The initialization vector to use</param>
        /// <returns>An encryptor using Fiserv's settings</returns>
        private static RijndaelManaged GetRijndaelManaged(string key, string IV)
        {
            return new RijndaelManaged
            {
                BlockSize = 128,
                KeySize = 256,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC,
                Key = Encoding.ASCII.GetBytes(key),
                IV = Encoding.ASCII.GetBytes(IV)
            };
        }

        /// <summary>
        /// Take a given string and encrypt it according to Fiwire requirements
        /// </summary>
        /// <param name="plainText">The text to be encrypted</param>
        /// <param name="IV">The initial vector to use</param>
        /// <param name="key">The secret key to use</param>
        /// <returns>the encrypted string</returns>
        private static string EncryptString(string plainText, RijndaelManaged rijAlg)
        {
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

        /// <summary>
        /// Decrypt an ecnrypted string.
        /// </summary>
        /// <param name="cipherText">The output from EncryptString</param>
        /// <param name="key">The key originally used to encrypt the string</param>
        /// <param name="IV">The IV originally used to encrypt the string</param>
        /// <returns>The decrypted original string</returns>
        static string DecryptString(string cipherText, RijndaelManaged rijAlg)
        {           
            string plaintext = null;

            // Create a decryptor to perform the stream transform.
            var decryptor = rijAlg.CreateDecryptor();

            // Create the streams used for decryption.
            using var msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText));
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using (var srDecrypt = new StreamReader(csDecrypt))
            {
                // Read the decrypted bytes from the decrypting stream
                // and place them in a string.
                plaintext = srDecrypt.ReadToEnd();
            }

            return plaintext;
        }
    }
}
