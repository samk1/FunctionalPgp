namespace Pgp.Constants

type internal PacketType = 
    | ReservedPacket
    | PublicKeyEncryptedSessionKeyPacket
    | SignaturePacket
    | SymettricKeyEncryptedSessionKeyPacket
    | OnePassSignaturePacket
    | SecretKeyPacket
    | PublicKeyPacket
    | SecretSubkeyPacket
    | CompressedDataPacket
    | SymmetricallyEncryptedDataPacket
    | MarkerPacket
    | LiteralDataPacket
    | TrustPacket
    | UserIdPacket
    | PublicSubkeyPacket
    | UserAttributePacket
    | SymmetricallyEncryptedAndIntegrityProtectedDataPacket
    | ModificationDetectionCodePacket
    | PrivateOrExperimental60Packet
    | PrivateOrExperimental61Packet
    | PrivateOrExperimental62Packet
    | PrivateOrExperimental63Packet
    | UnknownPacketType of int
    with 
    static member Read (tag: int) : PacketType = 
        match tag with
        | 0 -> ReservedPacket
        | 1 -> PublicKeyEncryptedSessionKeyPacket
        | 2 -> SignaturePacket
        | 3 -> SymettricKeyEncryptedSessionKeyPacket
        | 4 -> OnePassSignaturePacket
        | 5 -> SecretKeyPacket
        | 6 -> PublicKeyPacket
        | 7 -> SecretSubkeyPacket
        | 8 -> CompressedDataPacket
        | 9 -> SymmetricallyEncryptedDataPacket
        | 10 -> MarkerPacket
        | 11 -> LiteralDataPacket
        | 12 -> TrustPacket
        | 13 -> UserIdPacket
        | 14 -> PublicSubkeyPacket
        | 17 -> UserAttributePacket
        | 18 -> SymmetricallyEncryptedAndIntegrityProtectedDataPacket
        | 19 -> ModificationDetectionCodePacket
        | 60 -> PrivateOrExperimental60Packet
        | 61 -> PrivateOrExperimental61Packet
        | 62 -> PrivateOrExperimental62Packet
        | 63 -> PrivateOrExperimental63Packet
        | other -> UnknownPacketType other

module internal PacketType =
    let ofInt n =
        match n with
        | 0 -> ReservedPacket
        | 1 -> PublicKeyEncryptedSessionKeyPacket
        | 2 -> SignaturePacket
        | 3 -> SymettricKeyEncryptedSessionKeyPacket
        | 4 -> OnePassSignaturePacket
        | 5 -> SecretKeyPacket
        | 6 -> PublicKeyPacket
        | 7 -> SecretSubkeyPacket
        | 8 -> CompressedDataPacket
        | 9 -> SymmetricallyEncryptedDataPacket
        | 10 -> MarkerPacket
        | 11 -> LiteralDataPacket
        | 12 -> TrustPacket
        | 13 -> UserIdPacket
        | 14 -> PublicSubkeyPacket
        | 17 -> UserAttributePacket
        | 18 -> SymmetricallyEncryptedAndIntegrityProtectedDataPacket
        | 19 -> ModificationDetectionCodePacket
        | 60 -> PrivateOrExperimental60Packet
        | 61 -> PrivateOrExperimental61Packet
        | 62 -> PrivateOrExperimental62Packet
        | 63 -> PrivateOrExperimental63Packet
        | other -> UnknownPacketType other    