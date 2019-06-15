namespace Pgp.Abstractions.Messages
{
    public abstract class PgpSignedMessage : PgpMessage
    {
        public PgpSignature Signature { get; private set; }
    }
}