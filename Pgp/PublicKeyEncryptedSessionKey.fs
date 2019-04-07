module PublicKeyEncryptedSessionKey

open System.IO
open Constants
open Common

type PublicKeyEncryptedSessionKey = {
    PublicKeyEncryptedSessionKeyVersion : int;
    EncryptingKeyId : byte[];
    PublicKeyAlgorithm : PublicKeyAlgorithms.PublicKeyAlgorithm;
    EncryptedSessionKey : byte[];
}

let initial = {
    PublicKeyEncryptedSessionKeyVersion = 0;
    EncryptingKeyId = KeyId.initial;
    PublicKeyAlgorithm = PublicKeyAlgorithms.UnknownPublicKeyAlgorithm;
    EncryptedSessionKey = Array.empty<byte>
}

let read (input : Stream) (length : int) : PublicKeyEncryptedSessionKey =
    let versionNumber = (input.ReadByte())
    let keyId = KeyId.read input
    let publicKeyAlgorithm = PublicKeyAlgorithms.read input
    input.Seek((int64 (length - 10)), SeekOrigin.Current) |> ignore
    {
        initial with
            PublicKeyEncryptedSessionKeyVersion = versionNumber
            EncryptingKeyId = keyId
            PublicKeyAlgorithm = publicKeyAlgorithm
    }