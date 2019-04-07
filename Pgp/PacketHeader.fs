module PacketHeader

open System.IO

type PacketHeaderFormat = NewFormat | OldFormat

type PacketTag = ReservedPacket
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

exception UnknownPacketTag

let readPacketTag (tag: int) : PacketTag = 
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
        | _ -> raise UnknownPacketTag

type LengthType = OneOctetLength of int
                | TwoOctetLength of int
                | FiveOctetLength of int
                | PartialBodyLength of int

type OldLengthType = OldOneOctetLength
                    | OldTwoOctetLength
                    | FourOctetLength
                    | IndeterminateLength


exception UnknownLengthType

let readNewFormatLengthType (octet: int) : LengthType =
    if octet < 192 then OneOctetLength octet
    elif octet < 223 then TwoOctetLength octet
    elif octet < 255 then PartialBodyLength octet
    elif octet = 255 then FiveOctetLength octet
    else raise UnknownLengthType

type PacketHeader = { PacketTag : PacketTag; Length : int }

exception UnsupportedLengthType    

let readTwoOctetLength (firstOctet: int, input: Stream) : int =
    let secondOctet = input.ReadByte()
    ((firstOctet - 192) <<< 8) + secondOctet + 192

let readFiveOctetLength (input : Stream) : int =
    let (secondOctet, thirdOctet, fourthOctet, fifthOctet) = (input.ReadByte(), input.ReadByte(), input.ReadByte(), input.ReadByte())
    (secondOctet <<< 24) ||| (thirdOctet <<< 16) ||| (fourthOctet <<< 8) ||| fifthOctet

let readPacketHeaderFormat (packetTag : int) =
    match (0b01000000 &&& packetTag) with
        | 0 -> OldFormat
        | _ -> NewFormat

let readNewFormatPacketHeader (input : Stream, packetTag : int) =
    let (tag, lengthType) = (readPacketTag (packetTag &&& 0b00111111), readNewFormatLengthType (input.ReadByte()))
    match lengthType with
        | OneOctetLength octet -> { PacketTag = tag; Length = octet }
        | TwoOctetLength octet -> { PacketTag = tag; Length = readTwoOctetLength (octet, input) }
        | FiveOctetLength _ -> { PacketTag = tag; Length = readFiveOctetLength input }
        | PartialBodyLength _ -> raise UnsupportedLengthType


let readOldFormatLengthType (lengthType : int) =
    match lengthType with
        | 0 -> OldOneOctetLength
        | 1 -> OldTwoOctetLength
        | 2 -> FourOctetLength
        | 3 -> IndeterminateLength
        | _ -> raise UnknownLengthType

let readOldTwoOctetLength (input : Stream) = 
    let (firstOctet, secondOctet) = (input.ReadByte(), input.ReadByte())
    (firstOctet <<< 8) ||| secondOctet

let readOldFourOctetLength (input : Stream) =
    let (firstOctet, secondOctet, thirdOctet, fourthOctet) = (input.ReadByte(), input.ReadByte(), input.ReadByte(), input.ReadByte())
    (firstOctet <<< 24) ||| (secondOctet <<< 16) ||| (thirdOctet <<< 8) ||| fourthOctet

let readOldFormatPacketHeader (input : Stream, packetTag : int) =
    let (tag, lengthType) = (readPacketTag ((0b00111100 &&& packetTag) >>> 2), readOldFormatLengthType (0b00000011 &&& packetTag))
    match lengthType with
        | OldOneOctetLength -> { PacketTag = tag; Length = input.ReadByte() }
        | OldTwoOctetLength -> { PacketTag = tag; Length = readOldTwoOctetLength input}
        | FourOctetLength -> { PacketTag = tag; Length = readOldFourOctetLength input}
        | IndeterminateLength -> raise UnsupportedLengthType


let readPacketHeader (input : Stream) =
    let packetTag = input.ReadByte()
    let packetHeaderFormat = readPacketHeaderFormat packetTag
    match packetHeaderFormat with
        | OldFormat -> readOldFormatPacketHeader (input, packetTag)
        | NewFormat -> readNewFormatPacketHeader (input, packetTag)