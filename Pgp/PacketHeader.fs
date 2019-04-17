namespace Pgp

open System.IO

exception internal UnknownPacketTagException

exception internal UnknownLengthTypeException

exception internal UnsupportedLengthTypeException    

type internal PacketHeaderFormat = NewFormat | OldFormat

type internal PacketTag = 
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
    with 
    static member Read (tag: int) : PacketTag = 
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
        | _ -> raise UnknownPacketTagException

type internal LengthType = 
    | OneOctetLength of int
    | TwoOctetLength of int
    | FiveOctetLength of int
    | PartialBodyLength of int
    with
    static member Read (octet : int) : LengthType =
        if octet < 192 then OneOctetLength octet
        elif octet < 223 then TwoOctetLength octet
        elif octet < 255 then PartialBodyLength octet
        elif octet = 255 then FiveOctetLength octet
        else raise UnknownLengthTypeException

    static member ReadTwoOctet (firstOctet : int) (input: Stream) =
        let secondOctet = input.ReadByte()
        ((firstOctet - 192) <<< 8) + secondOctet + 192

    static member ReadFiveOctet (input: Stream) =
        let (secondOctet, thirdOctet, fourthOctet, fifthOctet) = 
            (input.ReadByte(), 
             input.ReadByte(), 
             input.ReadByte(), 
             input.ReadByte())
        (secondOctet <<< 24) ||| (thirdOctet <<< 16) ||| (fourthOctet <<< 8) ||| fifthOctet

type internal OldLengthType = 
    | OldOneOctetLength
    | OldTwoOctetLength
    | FourOctetLength
    | IndeterminateLength
    with
    static member Read (lengthType : int) =
        match lengthType with
        | 0 -> OldOneOctetLength
        | 1 -> OldTwoOctetLength
        | 2 -> FourOctetLength
        | 3 -> IndeterminateLength
        | _ -> raise UnknownLengthTypeException

    static member ReadTwoOctet (input : Stream) = 
        let (firstOctet, secondOctet) = (input.ReadByte(), input.ReadByte())
        (firstOctet <<< 8) ||| secondOctet

    static member ReadFourOctet (input : Stream) = 
        let (firstOctet, secondOctet, thirdOctet, fourthOctet) = 
            (input.ReadByte(), 
             input.ReadByte(), 
             input.ReadByte(), 
             input.ReadByte())
        (firstOctet <<< 24) ||| (secondOctet <<< 16) ||| (thirdOctet <<< 8) ||| fourthOctet

type internal PacketHeader = 
    { 
        PacketTag : PacketTag; 
        Length : int 
    } with
    static member Read (input : Stream) =
        let packetTag = input.ReadByte()
        let packetHeaderFormat = PacketHeader.ReadHeaderFormat packetTag
        match packetHeaderFormat with
        | OldFormat -> PacketHeader.ReadOldFormat input packetTag
        | NewFormat -> PacketHeader.ReadNewFormat input packetTag

    static member ReadHeaderFormat (packetTag : int) =
        match (0b01000000 &&& packetTag) with
        | 0 -> OldFormat
        | _ -> NewFormat

    static member ReadNewFormat (input : Stream) (packetTag : int) =
        let (tag, lengthType) = (PacketTag.Read (packetTag &&& 0b00111111), LengthType.Read (input.ReadByte()))
        match lengthType with
        | OneOctetLength octet -> { PacketTag = tag; Length = octet }
        | TwoOctetLength octet -> { PacketTag = tag; Length = LengthType.ReadTwoOctet octet input }
        | FiveOctetLength _ -> { PacketTag = tag; Length = LengthType.ReadFiveOctet input }
        | PartialBodyLength _ -> raise UnsupportedLengthTypeException

    static member ReadOldFormat (input : Stream) (packetTag : int) =
        let (tag, lengthType) = 
            (PacketTag.Read ((0b00111100 &&& packetTag) >>> 2), 
             OldLengthType.Read (0b00000011 &&& packetTag))
        match lengthType with
        | OldOneOctetLength -> { PacketTag = tag; Length = input.ReadByte() }
        | OldTwoOctetLength -> { PacketTag = tag; Length = OldLengthType.ReadTwoOctet input}
        | FourOctetLength -> { PacketTag = tag; Length = OldLengthType.ReadFourOctet input}
        | IndeterminateLength -> raise UnsupportedLengthTypeException
