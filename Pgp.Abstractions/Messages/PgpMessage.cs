using System.IO;

namespace Pgp.Abstractions.Messages
{
    public abstract class PgpMessage
    {
        public Stream Plaintext { get; private set; }
    }
}