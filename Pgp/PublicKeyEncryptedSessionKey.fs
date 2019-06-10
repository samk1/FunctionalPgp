namespace Pgp

open System.IO
open Pgp.Constants
open Common.KeyId

type internal PublicKeyEncryptedSessionKey = 
    {
        PublicKeyEncryptedSessionKeyVersion : int;
        EncryptingKeyId : byte[];
        PublicKeyAlgorithm : PublicKeyAlgorithm;
        EncryptedSessionKey : byte[];
    } with
    static member Initial = 
        { PublicKeyEncryptedSessionKeyVersion = 0;
          EncryptingKeyId = KeyId.initial;
          PublicKeyAlgorithm = UnknownPublicKeyAlgorithm;
          EncryptedSessionKey = Array.empty<byte> }

    static member Read (input : Stream) (length : int) : PublicKeyEncryptedSessionKey =
        let versionNumber = (input.ReadByte())
        let keyId = KeyId.read input
        let publicKeyAlgorithm = PublicKeyAlgorithm.UnknownPublicKeyAlgorithm
        input.Seek((int64 (length - 10)), SeekOrigin.Current) |> ignore
        { PublicKeyEncryptedSessionKey.Initial with
                PublicKeyEncryptedSessionKeyVersion = versionNumber
                EncryptingKeyId = keyId
                PublicKeyAlgorithm = publicKeyAlgorithm }