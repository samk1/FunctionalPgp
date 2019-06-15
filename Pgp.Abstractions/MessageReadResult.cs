using System.IO;

namespace Pgp.Abstractions
{
    public abstract class MessageReadResult
    {
        public MemoryStream Message { get; private set; }

        public MessageVerificationResult MessageVerificationResult { get; private set; }
    }
}