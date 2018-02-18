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
                //The following settings are actually the default for AES
                //I'm hard coding them so you are aware of what they should
                //be, if you see someone using aes with different settings
                //there should be a very good reason.
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;
                aes.BlockSize = BLOCKSIZE;
                aes.GenerateIV(); //let AES generate an IV
                //
                aes.KeySize = KEYSIZE;
                aes.Key = encryptionKey;
                
                using (var outputMemoryStream = new MemoryStream())
                {
                    //write the IV to the beginning of the file.
                    outputMemoryStream.Write(aes.IV, 0, IVLENGTH);
                    using (var cryptoStream = new CryptoStream(outputMemoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(inputBytes, 0, inputBytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                    encryptedBytes = outputMemoryStream.ToArray();
                }
            }
            return encryptedBytes;
        }

        public byte[] DecryptBytes(byte[] encryptedBytes, byte[] encryptionKey)
        {
            VerifyInputs(encryptedBytes, encryptionKey);
            var iv = new byte[IVLENGTH];
            byte[] decryptedbytes = null;
            //pull the IV off the front of the file.
            Array.Copy(encryptedBytes, 0, iv, 0, IVLENGTH);

            using (var aes = Aes.Create())
            {
                //The following settings are actually the default for AES
                //I'm hard coding them so you are aware of what they should
                //be, if you see someone using aes with different settings
                //there should be a very good reason.
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;
                aes.BlockSize = BLOCKSIZE;
                //
                aes.KeySize = KEYSIZE;
                aes.Key = encryptionKey;
                aes.IV = iv;

                using (var outputMemorStream = new MemoryStream())
                {
                    using (var CryptoStream = new CryptoStream(outputMemorStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        CryptoStream.Write(encryptedBytes, IVLENGTH, (encryptedBytes.Length - IVLENGTH));
                        CryptoStream.FlushFinalBlock();
                    }
                    decryptedbytes = outputMemorStream.ToArray();
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
