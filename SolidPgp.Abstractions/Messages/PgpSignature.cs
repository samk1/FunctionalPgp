namespace SolidPgp.Abstractions.Messages
{
    public abstract class PgpSignature
    {
        public abstract byte[] SigningKeyId { get; }

        public abstract VerificationResult Verify();
    }
}