using CommandLine;

namespace CreateEncryptionKeyFiwire
{
    class CommandLineOptions
    {
        [Option('s',"settings", Required = false, HelpText = "The directory to look for appsettings.json. Defaults to current directory.")]
        public string AppSettingsPath { get; set; }

        [Option('d', "decrypt", Required = false, HelpText = "Use this to decrypt a previously encrypted string.")]
        public string ToDecrypt { get; set; }
    }
}
