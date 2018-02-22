using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptoDemo.AesDemo;
using System.IO;
using UnitTestProject.Properties;

namespace UnitTestProject
{
    [TestClass]
    public class AesTests
    {
        private const string EncryptionKey = "passwordwith32bits12345678912345";

        [TestMethod]
        public void Aes_StringEncryption_Test()
        {
            //Arrange
            var data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            var aes = new AES256();
            //Act
            var encryptedString = aes.EncryptString(data, EncryptionKey);
            var result = aes.DecryptString(encryptedString, EncryptionKey);
            //Assert
            Assert.AreEqual(data, result);
        }

        [TestMethod]
        public void Aes_EncryptFile_Test()
        {
            //Arrange
            var tempPath = Path.GetTempPath();
            if (!Directory.Exists(tempPath)) Directory.CreateDirectory(tempPath);
            var path = $"{tempPath}Security.txt";
            var originalData = Resources.ResourceManager.GetString("Security");
            File.WriteAllText(path, originalData);

            var encryptedPath = $"{tempPath}Security.encrypt";
            var decryptPath = $"{tempPath}security2.txt";
            var aes = new AES256();

            //Act
            aes.EncryptFile(EncryptionKey, path, encryptedPath);
            aes.DecryptFile(EncryptionKey, encryptedPath, decryptPath);

            var inputFile = File.ReadAllText(path);
            var outputFile = File.ReadAllText(decryptPath);

            //Assert
            Assert.AreEqual(inputFile, outputFile);

            File.Delete(path);
            File.Delete(encryptedPath);
            File.Delete(decryptPath);
        }
    }
}
