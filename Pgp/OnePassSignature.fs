namespace Pgp

open System.IO

open Common.KeyId
open Common.Boolean
open Constants.SignatureTypes
open Constants.HashAlgorithms
open Pgp.Constants

type internal OnePassSignature = 
    {
        VersionNumber : int
        SignatureType : SignatureType
        HashAlgorithm : HashAlgorithmType
        PublicKeyAlgorithm : PublicKeyAlgorithm
        SigningKeyId : byte[]
        IsNested : bool
    } with
    static member Initial =
        { VersionNumber = 0
          SignatureType = UnknownSignatureType
          HashAlgorithm = UnknownHashAlgorithm
          PublicKeyAlgorithm = UnknownPublicKeyAlgorithm
          SigningKeyId = KeyId.initial
          IsNested = false }

    static member Read (input : Stream) (length : int) : OnePassSignature =
        let versionNumber = input.ReadByte();
        let signatureType = SignatureType.Read input
        let hashAlgorithm = HashAlgorithmType.Read input
        let publicKeyAlgorithm = PublicKeyAlgorithm.UnknownPublicKeyAlgorithm
        let signingKeyId = KeyId.read input
        let isNested = Boolean.read input
        { VersionNumber = versionNumber
          SignatureType = signatureType
          HashAlgorithm = hashAlgorithm
          PublicKeyAlgorithm = publicKeyAlgorithm
          SigningKeyId = signingKeyId
          IsNested = isNested }

