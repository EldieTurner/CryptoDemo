using CryptoDemo.AesDemo;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace UnitTestProject
{
    [TestClass]
    public class AesTests
    {
        private readonly byte[] EncryptionKey = Encoding.UTF8.GetBytes("passwordpasswordpasswordpassword");

        [TestMethod]
        public void TestMethod1()
        {
            //Arrange
            var input = "This is some unencrypted text that we are going to encrypt then decrypt to make sure it comes out correct.";
                //Convert from string to byte array
            var byteInput = Encoding.UTF8.GetBytes(input);
            var aes = new AesSimple();
            //Act
            var encryptedString = aes.EncryptBytes(byteInput, EncryptionKey);
            var byteOutput = aes.DecryptBytes(encryptedString, EncryptionKey);
                //Convert from byte array to string
            var output = Encoding.UTF8.GetString(byteOutput, 0, byteOutput.Length);
            //Assert
            Assert.AreEqual(input, output);
        }
    }
}
