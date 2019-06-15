using System.IO;

namespace Pgp.Abstractions
{
    interface IPgpMessageReader
    {
        MessageReadResult ReadAndVerifyMessage(Stream message);

        Stream ReadMessage(Stream message);

        MessageVerificationResult VerifyMessage(Stream message);
    }
}