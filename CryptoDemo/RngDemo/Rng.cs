using System;
using System.Security.Cryptography;

namespace RngDemo
{
    public class Rng
    {
        private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        public string GetRandomString(int byteLength)
            => Convert.ToBase64String(GetRandomBytes(byteLength)).TrimEnd('=');

        public byte[] GetRandomBytes(int byteLength)
        {
            var salt = new byte[byteLength];
            _rng.GetBytes(salt);
            return salt;
        }
    }
}
