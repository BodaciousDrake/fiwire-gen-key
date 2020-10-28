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
                    .WithParsed(opts =>
                    {
                        //get settings from appsettings.json
                        var builder = new ConfigurationBuilder()
                            .SetBasePath(Directory.GetCurrentDirectory());

                        var fileName = "appsettings.json";

                        //check to see if the user specified an alternate location for the appsettings
                        if (opts.AppSettingsPath != null)
                        {                            
                            builder.SetBasePath(Path.GetDirectoryName(opts.AppSettingsPath));

                            //if the user did not specify a file name, default to appsettings.json
                            //otherwise, use the name they specified
                            if (Path.HasExtension(opts.AppSettingsPath))
                                fileName = Path.GetFileName(opts.AppSettingsPath);
                        }

                        var built = builder
                            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                            .Build();

                        var appSettings = new FiwireSettings();
                        built.Bind("FiwireSettings", appSettings);

                        //check to see if the user requested a decrypt
                        if (!string.IsNullOrWhiteSpace(opts.ToDecrypt))
                        {
                            Console.WriteLine(DecryptString(
                                cipherText: opts.ToDecrypt,
                                key: appSettings.Key,
                                IV: appSettings.IV
                            ));
                        }
                        else
                        {
                            // print the encrypted string to the console
                            Console.WriteLine(EncryptString(
                                plainText: GetValueToEncrypt(appSettings.SharedSecret),
                                key: appSettings.Key,
                                IV: appSettings.IV
                            ));
                        }
                    })
                    .WithNotParsed(errors =>
                    {
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
        /// <param name="IV">The initial vector to use</param>
        /// <param name="key">The secret key to use</param>
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

        /// <summary>
        /// Test method used for decrypting the output from EncryptString.
        /// </summary>
        /// <param name="cipherText">The output from EncryptString</param>
        /// <param name="key">The key originally used to encrypt the string</param>
        /// <param name="IV">The IV originally used to encrypt the string</param>
        /// <returns>The decrypted original string</returns>
        static string DecryptString(string cipherText, string key, string IV)
        {           
            string plaintext = null;

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
