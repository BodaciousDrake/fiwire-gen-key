using CommandLine;

namespace CreateEncryptionKeyFiwire
{
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
