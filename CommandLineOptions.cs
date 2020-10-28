using CommandLine;

namespace CreateEncryptionKeyFiwire
{
    class CommandLineOptions
    {
        [Option('s',"settings", Required = false, HelpText = "The path to the appsettings file. Defaults to current directory.")]
        public string AppSettingsPath { get; set; }

        [Option('d', "decrypt", Required = false, HelpText = "Use this to decrypt a previosly encrypted string.")]
        public string ToDecrypt { get; set; }
    }
}
