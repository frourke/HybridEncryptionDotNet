using System.Security.Cryptography;
using System.Text;

namespace xPlatformEncrypt
{
    internal class Program
    {
        static int Main(string[] args)
        {
            var publicKeyPath = string.Empty;
            var inputFile = string.Empty;

            foreach(var arg in args){
                if (arg.StartsWith("publicKey="))
                {
                    publicKeyPath = arg.Substring(arg.IndexOf("=") + 1);
                }
                else if (arg.StartsWith("file="))
                {
                    inputFile = arg.Substring(arg.IndexOf("=") + 1);
                }
            }
            if (string.IsNullOrEmpty(publicKeyPath)) return ShowError("publicKey arguement not found. Please supply one and try again.");
            if (string.IsNullOrEmpty(inputFile)) return ShowError("inputFile arguement not found. Please supply one and try again.");

            // check required files exist
            if (File.Exists(inputFile) == false) return ShowError($"Input file not found: {inputFile}");
            if (File.Exists(publicKeyPath) == false) return ShowError($"RSA public key file not found: {publicKeyPath}");            

            Console.WriteLine($"Encrypting the contents of {inputFile}");

            // read file content
            var fileContent = File.ReadAllText(inputFile);

            // generate random AES key
            using Aes myAes = Aes.Create();
            myAes.GenerateKey();

            // encrypt file context with aes key
            var (ciphertext, nonce, tag) = AesEncryptData(fileContent, myAes.Key);
            
            // encrypt aes key with rsa private key
            var encryptedAesKey = EncryptAesKeyUsingRsaPublicKey(publicKeyPath, Convert.ToBase64String(myAes.Key));

            // build file payload
            var payload = $"{encryptedAesKey}|{Convert.ToBase64String(nonce)}|{Convert.ToBase64String(tag)}|{Convert.ToBase64String(ciphertext)}";

            // write encrypted payload to output file
            var outputFile = $"{inputFile}.aes";
            File.WriteAllText(outputFile, payload);
            Console.WriteLine($"Done. Encrypted file created: " + outputFile);
            return 0;
        }

        /// <summary>
        /// Encrypt the given data using AesGmc
        /// </summary>
        /// <param name="data">String data to be encrypted</param>
        /// <param name="key">AES key used to encrypt the data</param>
        /// <returns>Vaules required to decrypt the payload</returns>
        private static (byte[] ciphertext, byte[] nonce, byte[] tag) AesEncryptData(string data, byte[] key)
        {
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            RandomNumberGenerator.Fill(nonce);

            var tag = new byte[AesGcm.TagByteSizes.MaxSize];
            var plaintextBytes = Encoding.UTF8.GetBytes(data);
            var encryptedData = new byte[plaintextBytes.Length];

            using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
            aes.Encrypt(nonce, plaintextBytes, encryptedData, tag);

            return (encryptedData, nonce, tag);
        }

        /// <summary>
        /// Encrypt the given aesKey usign an RSA public key
        /// </summary>
        /// <param name="publicKeyPath">Path to RSA public key</param>
        /// <param name="aesKey">Base64 of AES key</param>
        /// <returns>Encrypted AES key</returns>
        private static string EncryptAesKeyUsingRsaPublicKey(string publicKeyPath, string aesKey)
        {
            var publicKey = File.ReadAllText(publicKeyPath);

            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKey.ToCharArray());            
            var encryptedBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(aesKey), RSAEncryptionPadding.OaepSHA256);

            var encrypted = Convert.ToBase64String(encryptedBytes);
            return encrypted;
        }

        static int ShowError(string message)
        {
            Console.WriteLine(message);
            return -1;
        }
    }
}