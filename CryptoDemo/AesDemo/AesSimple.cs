using System.Linq;
using System.Security.Cryptography;
using System.IO;
using System;

namespace CryptoDemo.AesDemo
{
    public class AesSimple
    {
        private const int BLOCKSIZE = 128; //bits
        private const int KEYSIZE = 256; //bits
        private const int IVLENGTH = 16; //bytes.
        public byte[] EncryptBytes(byte[] inputBytes, byte[] encryptionKey)
        {
            VerifyInputs(inputBytes, encryptionKey);
            
            byte[] encryptedBytes;
            using (var aes = Aes.Create())
            {
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;
                aes.KeySize = KEYSIZE;
                aes.BlockSize = BLOCKSIZE;
                aes.Key = encryptionKey;
                aes.GenerateIV(); //let AES generate an IV

                using (var outputMemoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(outputMemoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        //we write the IV to the output stream first.
                        outputMemoryStream.Write(aes.IV, 0, aes.IV.Length);

                        using (var inputMemoryStream = new MemoryStream(inputBytes))
                        {
                            int data;
                            while ((data = inputMemoryStream.ReadByte()) != -1)
                                cryptoStream.WriteByte((byte)data);
                        }
                    }
                    encryptedBytes = outputMemoryStream.ToArray();
                }
            }
            return encryptedBytes;
        }

        public byte[] DecryptBytes(byte[] encryptedBytes, byte[] encryptionKey)
        {
            VerifyInputs(encryptedBytes, encryptionKey);

            byte[] decryptedbytes = null;
            // read the IV from the front of the data.
            byte[] iv = encryptedBytes.Take(IVLENGTH).ToArray();
            // the rest of the data is the encrypted stuff
            byte[] inputstream = encryptedBytes.Skip(iv.Length).Take(encryptedBytes.Length - IVLENGTH).ToArray();

            using (var aes = Aes.Create())
            {
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;
                aes.KeySize = KEYSIZE;
                aes.BlockSize = BLOCKSIZE;
                aes.Key = encryptionKey;
                aes.IV = iv;

                using (var inputMemoryStream = new MemoryStream(inputstream))
                {
                    using (var outputMemorStream = new MemoryStream())
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(inputMemoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                        {
                            int data;
                            while ((data = cryptoStream.ReadByte()) != -1)
                                outputMemorStream.WriteByte((byte)data);
                        }
                        decryptedbytes = outputMemorStream.ToArray();
                    }
                }
            }

        return decryptedbytes;
        }

        private void VerifyInputs(byte[] data, byte[] encryptionKey)
        {
            if (data == null) throw new ArgumentException($"{nameof(data)} cannot be null");
            if (!data.Any()) throw new ArgumentException($"{nameof(data)} cannot be empty");
            if (encryptionKey.Length * 8 != KEYSIZE) throw new ArgumentException($"{nameof(encryptionKey)} must be {KEYSIZE} bits");
        }
    }
}
