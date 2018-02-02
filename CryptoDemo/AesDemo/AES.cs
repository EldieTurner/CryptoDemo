using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace CryptoDemo.AesDemo
{
    /// <summary>
    /// AES128 has 340,282,366,920,938,463,463,374,607,431,768,211,456
    /// possible keys
    /// </summary>
    [Obsolete("There isn't really any reason to use anything but AES256")]
    public class AES128 : AES
    {
        public AES128() : base()
            => base.KeySize = AesKeySize._128;
    }

    /// <summary>
    /// AES192 has 6,277,101,735,386,680,763,835,789,423,207,666,416,102,355,444,464,034,512,896
    /// possible keys
    /// </summary>
    [Obsolete("There isn't really any reason to use anything but AES256")]
    public class AES192 : AES
    {
        public AES192() : base()
            => base.KeySize = AesKeySize._192;
    }

    /// <summary>
    /// AES 256 has 115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,640,564,039,457,584,007,913,129,639,936
    /// possible keys
    /// </summary>
    public class AES256 : AES
    {
        public AES256() : base()
            => base.KeySize = AesKeySize._256;
    }

    public abstract class AES
    {
        private const int BLOCKSIZE = 128;
        private const int IVLENGTH = 16;
        protected enum AesKeySize
        {
            _128 = 128,
            _192 = 192,
            _256 = 256
        }
        protected AesKeySize KeySize { get; set; } //in bits.

        internal AES()
        {

        }
        public string EncryptString(string inputString, string encryptionKey)
            => EncryptString(inputString, Encoding.UTF8.GetBytes(encryptionKey));

        public string DecryptString(string inputString, string encryptionKey)
            => DecryptString(inputString, Encoding.UTF8.GetBytes(encryptionKey));


        public string EncryptString(string inputString, byte[] encryptionKey)
        {
            var inputstream = Encoding.UTF8.GetBytes(inputString);
            var outputStream = EncryptBytes(inputstream, encryptionKey);
            return Convert.ToBase64String(outputStream);
        }

        public string DecryptString(string encryptedString, byte[] encryptionKey)
        {
            var encryptedbytes = Convert.FromBase64String(encryptedString);
            var decryptedBytes = DecryptBytes(encryptedbytes, encryptionKey);
            return Encoding.UTF8.GetString(decryptedBytes, 0, decryptedBytes.Length);
        }

        private byte[] EncryptBytes(byte[] inputBytes, byte[] encryptionKey)
        {
            if (!inputBytes.Any())
                throw new ArgumentNullException(nameof(inputBytes));
            if ((encryptionKey.Length.ToBits()) != (int)KeySize)
                throw new ArgumentException($"{nameof(encryptionKey)} length must equal {(int)KeySize} bits");

            byte[] cipherTextBytes;
            try
            {
                using (var AES = Aes.Create())
                {
                    AES.Padding = PaddingMode.PKCS7;
                    AES.Mode = CipherMode.CBC;
                    AES.KeySize = (int)KeySize;
                    AES.BlockSize = BLOCKSIZE;
                    AES.Key = encryptionKey;
                    AES.GenerateIV();

                    using (var outputms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(outputms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            outputms.Write(AES.IV, 0, AES.IV.Length);

                            using (var inputms = new MemoryStream(inputBytes))
                            {
                                int data;
                                while ((data = inputms.ReadByte()) != -1)
                                    cs.WriteByte((byte)data);
                            }
                        }
                        cipherTextBytes = outputms.ToArray();
                    }
                }
            }
            catch
            {
                throw;
            }
            return cipherTextBytes;
        }

        private byte[] DecryptBytes(byte[] encryptedBytes, byte[] encryptionKey)
        {
            if (!encryptedBytes.Any())
                throw new ArgumentNullException(nameof(encryptedBytes));
            if ((encryptionKey.Length.ToBits()) != (int)KeySize)
                throw new ArgumentException($"{nameof(encryptionKey)} length must equal {(int)KeySize} bits");

            byte[] decryptedbytes = null;
            try
            {
                byte[] iv = encryptedBytes.Take(IVLENGTH).ToArray();
                byte[] inputstream = encryptedBytes.Skip(iv.Length).Take(encryptedBytes.Length - IVLENGTH).ToArray();

                using (var AES = Aes.Create())
                {
                    AES.Padding = PaddingMode.PKCS7;
                    AES.Mode = CipherMode.CBC;
                    AES.KeySize = (int)KeySize;
                    AES.BlockSize = BLOCKSIZE;
                    AES.Key = encryptionKey;
                    AES.IV = iv;

                    using (var inputms = new MemoryStream(inputstream))
                    {
                        using (var outputms = new MemoryStream())
                        {
                            using (CryptoStream cs = new CryptoStream(inputms, AES.CreateDecryptor(), CryptoStreamMode.Read))
                            {
                                int data;
                                while ((data = cs.ReadByte()) != -1)
                                    outputms.WriteByte((byte)data);
                            }
                            decryptedbytes = outputms.ToArray();
                        }
                    }
                }
            }
            catch
            {
                throw;
            }
            return decryptedbytes;
        }

        public void EncryptFile(string encryptionKey, string inputfile, string encryptedfile)
            => EncryptFile(Encoding.UTF8.GetBytes(encryptionKey), inputfile, encryptedfile);

        public void DecryptFile(string encryptionKey, string encryptedFile, string outputFile)
            => DecryptFile(Encoding.UTF8.GetBytes(encryptionKey), encryptedFile, outputFile);

        public void EncryptFile(byte[] encryptionKey, string inputfile, string encryptedfile)
        {
            if (!File.Exists(inputfile))
                throw new FileNotFoundException(inputfile);
            if ((encryptionKey.Length.ToBits()) != (int)KeySize)
                throw new ArgumentException($"{nameof(encryptionKey)} length must equal {(int)KeySize} bits");

            using (var AES = Aes.Create())
            {
                AES.Padding = PaddingMode.PKCS7;
                AES.Mode = CipherMode.CBC;
                AES.KeySize = (int)KeySize;
                AES.BlockSize = BLOCKSIZE;
                AES.Key = encryptionKey;
                AES.GenerateIV();
                using (var outputfs = new FileStream(encryptedfile, FileMode.Create))
                {
                    using (var cs = new CryptoStream(outputfs, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        outputfs.Write(AES.IV, 0, AES.IV.Length);

                        using (var inputfs = new FileStream(inputfile, FileMode.Open))
                        {
                            int data;
                            while ((data = inputfs.ReadByte()) != -1)
                                cs.WriteByte((byte)data);
                        }
                    }
                }
            }
        }

        public void DecryptFile(byte[] encryptionKey, string encryptedFile, string outputFile)
        {
            if (!File.Exists(encryptedFile))
                throw new FileNotFoundException(encryptedFile);
            if ((encryptionKey.Length.ToBits()) != (int)KeySize)
                throw new ArgumentException($"{nameof(encryptionKey)} length must equal {(int)KeySize} bits");

            using (var inputfs = new FileStream(encryptedFile, FileMode.Open))
            {
                var iv = new byte[IVLENGTH];
                inputfs.Read(iv, 0, IVLENGTH);
                inputfs.Position = iv.Length;

                using (var AES = Aes.Create())
                {
                    AES.Padding = PaddingMode.PKCS7;
                    AES.Mode = CipherMode.CBC;
                    AES.KeySize = (int)KeySize;
                    AES.BlockSize = BLOCKSIZE;
                    AES.Key = encryptionKey;
                    AES.IV = iv;
                    using (var outputfs = new FileStream(outputFile, FileMode.Create))
                    {
                        using (CryptoStream cs = new CryptoStream(inputfs, AES.CreateDecryptor(), CryptoStreamMode.Read))
                        {
                            int data;
                            while ((data = cs.ReadByte()) != -1)
                                outputfs.WriteByte((byte)data);
                        }
                    }
                }
            }
        }
    }

    public static class ExtensionMethods
    {
        public static int ToBits(this int bytes)
            => bytes * 8;
    }
}


