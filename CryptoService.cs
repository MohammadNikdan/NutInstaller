using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NutriculaInstaller
{
    internal static class CryptoService
    {
        // EXACT key required by the existing PHP/MQL protocol.
        private const string AesKey = "lj1@91!23867871jbhlk*&GS^madf^&!";

        public static string Encoder(string text)
        {
            if (text == null)
                throw new ArgumentNullException("text");

            byte[] plain = Encoding.UTF8.GetBytes(text);
            byte[] key = Encoding.UTF8.GetBytes(AesKey);

            if (key.Length != 32)
                throw new InvalidOperationException("AES key must be exactly 32 bytes.");

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.Zeros;
                aes.IV = new byte[16];

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    byte[] ciphertext = encryptor.TransformFinalBlock(plain, 0, plain.Length);
                    return ToUpperHex(ciphertext);
                }
            }
        }

        public static string BuildPostData(string email, string purchaseKey, string machineId, string rndNumber, string transferKey = null, string localIp = null)
        {
            string postData = "rnd_number=" + Encoder(rndNumber);
            postData += "&email=" + email;
            postData += "&purchase_key=" + purchaseKey;
            if (!string.IsNullOrEmpty(transferKey))
                postData += "&transfer_key=" + transferKey;
            postData += "&machine_id=" + Encoder(machineId);
            if (!string.IsNullOrEmpty(localIp))
                postData += "&local_ip=" + localIp;

            // IMPORTANT: The entire PostData is encrypted again using the same AES/ECB/zero-padding scheme.
            return Encoder(postData);
        }

        public static string ToUpperHex(byte[] data)
        {
            const string chars = "0123456789ABCDEF";
            char[] output = new char[data.Length * 2];
            for (int i = 0; i < data.Length; i++)
            {
                output[i * 2] = chars[data[i] >> 4];
                output[i * 2 + 1] = chars[data[i] & 0x0F];
            }
            return new string(output);
        }

        public static string Generate32DigitRandomNumber()
        {
            const int digitCount = 32;
            char[] result = new char[digitCount];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                byte[] buffer = new byte[1];
                for (int i = 0; i < result.Length; i++)
                {
                    // Rejection sampling avoids modulo bias.
                    do
                    {
                        rng.GetBytes(buffer);
                    }
                    while (buffer[0] >= 250);

                    result[i] = (char)('0' + (buffer[0] % 10));
                }
            }

            return new string(result);
        }
    }
}
