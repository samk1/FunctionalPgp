namespace Constants.SignatureTypes

open System.IO

type internal SignatureType = 
    | UnknownSignatureType
    | SignatureOfABinaryDocument
    | SignatureOfACanonicalTextDocument
    | StandaloneSignature
    | GenericCertificationOfAUserIdAndPublicKeyPacket
    | PersonaCertificationOfAUserIdAndPublicKeyPacket
    | CasualCertificationOfAUserIdAndPublicKeyPacket
    | PositiveCertificationOfAUserIdAndPublicKeyPacket
    | SubkeyBindingSignature
    | PrimaryKeyBindingSignature
    | SignatureDirectlyOnAKey
    | KeyRevocationSignature
    | SubkeyRevocationSignature
    | CertificationRevocationSignature
    | TimestampSignature
    | ThirdPartyConfirmationSignature
with
    static member Read (input : Stream) : SignatureType =
        match (input.ReadByte()) with
        | 0x00 -> SignatureOfABinaryDocument
        | 0x01 -> SignatureOfACanonicalTextDocument
        | 0x02 -> StandaloneSignature
        | 0x10 -> GenericCertificationOfAUserIdAndPublicKeyPacket
        | 0x12 -> PersonaCertificationOfAUserIdAndPublicKeyPacket
        | 0x13 -> CasualCertificationOfAUserIdAndPublicKeyPacket
        | 0x18 -> SubkeyBindingSignature
        | 0x19 -> PrimaryKeyBindingSignature
        | 0x1F -> SignatureDirectlyOnAKey
        | 0x20 -> KeyRevocationSignature
        | 0x28 -> SubkeyRevocationSignature
        | 0x40 -> TimestampSignature
        | 0x50 -> ThirdPartyConfirmationSignature
        | _ -> UnknownSignatureType