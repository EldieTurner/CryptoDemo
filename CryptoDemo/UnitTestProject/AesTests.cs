using CryptoDemo.AesDemo;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Text;

namespace UnitTestProject
{
    [TestClass]
    public class AesTests
    {
        private readonly byte[] EncryptionKey = Encoding.UTF8.GetBytes("passwordpasswordpasswordpassword");

        [TestMethod]
        public void HappyPath_Test()
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

        [TestMethod]
        public void NullData_Test()
        {
            //Arrange
            byte[] byteInput = null;
            var aes = new AesSimple();
            //Act 
            //Assert
            Assert.ThrowsException<ArgumentException>(() =>aes.EncryptBytes(byteInput, EncryptionKey), "data cannot be null");
        }

        [TestMethod]
        public void EmptyData_Test()
        {
            //Arrange
            byte[] byteInput = new Byte[0];
            var aes = new AesSimple();
            //Act 
            //Assert
            Assert.ThrowsException<ArgumentException>(() => aes.EncryptBytes(byteInput, EncryptionKey), "data cannot be empty");
        }

        [TestMethod]
        public void IncorrectKeySize_Test()
        {
            //Arrange
            var input = "This is some unencrypted text that we are going to encrypt then decrypt to make sure it comes out correct.";
            //Convert from string to byte array
            var byteInput = Encoding.UTF8.GetBytes(input);
            var shortkey = new byte[24];
            var aes = new AesSimple();
            //Act
            //Assert
            Assert.ThrowsException<ArgumentException>(() => aes.EncryptBytes(byteInput, shortkey), "encryptionKey must be 256 bits");
        }
    }
}
