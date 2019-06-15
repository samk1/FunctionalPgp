namespace SolidPgp.Abstractions.Messages
{
    public abstract class PgpSignedMessage : PgpMessage
    {
        public abstract PgpSignature Signature { get; }
    }
}