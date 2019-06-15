namespace Pgp.Abstractions
{
    public abstract class MessageVerificationResult
    {
        public bool MessageSignatureIsValid { get; private set; }

        public MessageVerificationFailureReason MessageVerificationFailureReason { get; private set; }
    }

    public enum MessageVerificationFailureReason
    {
        InvalidSignature
    }
}