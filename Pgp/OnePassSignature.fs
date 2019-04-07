module OnePassSignature

open System.IO

open Constants
open Common
open Constants.SignatureTypes
open Constants.HashAlgorithms
open Constants.PublicKeyAlgorithms

type OnePassSignature = {
    VersionNumber : int
    SignatureType : SignatureType
    HashAlgorithm : HashAlgorithmType
    PublicKeyAlgorithm : PublicKeyAlgorithm
    SigningKeyId : byte[]
    IsNested : bool
}

let initial = {
    VersionNumber = 0
    SignatureType = UnknownSignatureType
    HashAlgorithm = UnknownHashAlgorithm
    PublicKeyAlgorithm = UnknownPublicKeyAlgorithm
    SigningKeyId = KeyId.initial
    IsNested = false
}

let read (input : Stream) (length : int) : OnePassSignature =
    let versionNumber = input.ReadByte();
    let signatureType = SignatureTypes.read input
    let hashAlgorithm = HashAlgorithmType.read input
    let publicKeyAlgorithm = PublicKeyAlgorithms.read input
    let signingKeyId = KeyId.read input
    let isNested = Boolean.read input
    {
        VersionNumber = versionNumber
        SignatureType = signatureType
        HashAlgorithm = hashAlgorithm
        PublicKeyAlgorithm = publicKeyAlgorithm
        SigningKeyId = signingKeyId
        IsNested = isNested
    }

