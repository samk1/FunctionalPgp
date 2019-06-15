using System.IO;

namespace SolidPgp.Abstractions.Messages
{
    public abstract class PgpMessage
    {
        public abstract Stream Plaintext { get; }
    }
}