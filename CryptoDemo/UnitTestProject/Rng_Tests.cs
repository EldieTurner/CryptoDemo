using Microsoft.VisualStudio.TestTools.UnitTesting;
using RngDemo;

namespace UnitTestProject
{
    [TestClass]
    public class Rng_Tests
    {
        [TestMethod]
        public void Rng_GetRandomBytes_Test()
        {
            //Arrange
            var byteLength = 16;
            var rng = new Rng();
            //Act
            var random1 = rng.GetRandomBytes(byteLength);
            var random2 = rng.GetRandomBytes(byteLength);
            //Assert
            Assert.AreNotEqual(random1, random2);
            Assert.AreEqual(random1.Length, byteLength);
            Assert.AreEqual(random2.Length, byteLength);
        }

        [TestMethod]
        public void Rng_GetRandomString_Test()
        {
            //Arrange
            var byteLength = 16;
            var rng = new Rng();
            //Act
            var random1 = rng.GetRandomString(byteLength);
            var random2 = rng.GetRandomString(byteLength);
            //Assert
            Assert.AreNotEqual(random1, random2);
        }
    }
}
