using System.Security.Cryptography;

namespace SolidPgp.Abstractions
{
    public interface IPgpPrivateKeyProvider
    {
        AsymmetricAlgorithm GetPrivateKey(byte[] keyId);
    }
}
