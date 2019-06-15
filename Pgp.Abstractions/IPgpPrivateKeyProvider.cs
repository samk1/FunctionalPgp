using System.Security.Cryptography;

namespace Pgp.Abstractions
{
    public interface IPgpPrivateKeyProvider
    {
        AsymmetricAlgorithm GetPrivateKey(byte[] keyId);
    }
}
