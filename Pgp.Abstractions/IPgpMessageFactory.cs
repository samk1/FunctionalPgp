using System.IO;
using Pgp.Abstractions.Messages;

namespace Pgp.Abstractions
{
    interface IPgpMessageFactory
    {
        PgpMessage FromStream(Stream stream);

        PgpMessage FromBytes(byte[] bytes);
    }
}