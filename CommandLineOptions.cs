using CommandLine;

namespace CreateEncryptionKeyFiwire
{
    /// <summary>
    /// This class is used by the CommandLine plugin to parse command line options
    /// and provide helpful instructions
    /// </summary>
    class CommandLineOptions
    {
        [Option('s', "shared", Required = true, HelpText = "The shared secret key")]
        public string SharedSecret { get; set; }

        [Option('i', "iv", Required = true, HelpText = "The IV value")]
        public string IVValue { get; set; }

        [Option('k', "key", Required = true, HelpText = "The private key")]
        public string KeyValue { get; set; }
    }
}
