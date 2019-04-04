// Learn more about F# at http://fsharp.org

open System
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
                | SymetricallyEncryptedDataPacket
                | MarkerPacket
                | LiteralDataPacket
                | TrustPacket
                | UserIdPacket
                | PublicSubkeyPacket
                | UserAttributePacket
                | SymetricallyEncryptedAndIntegrityProtectedDataPacket
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
        | 9 -> SymetricallyEncryptedDataPacket
        | 10 -> MarkerPacket
        | 11 -> LiteralDataPacket
        | 12 -> TrustPacket
        | 13 -> UserIdPacket
        | 14 -> PublicSubkeyPacket
        | 17 -> UserAttributePacket
        | 18 -> SymetricallyEncryptedAndIntegrityProtectedDataPacket
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

type Packet = { PacketHeader : PacketHeader; PacketData : byte[] }

exception CouldNotReadFullPacket

type HashAlgorithm = UnknownHashAlgorithm
                    | Md5
                    | Sha1
                    | RipeMd160
                    | Reserved4
                    | Reserved5
                    | Reserved6
                    | Reserved7
                    | Sha256
                    | Sha384
                    | Sha512
                    | Sha224
                    | PrivateOrExperimentalHashAlgorithm

type PublicKeyAlgorithm = UnknownPublicKeyAlgorithm
                        | RsaEncryptOrSign
                        | RsaEncryptOnly
                        | RsaSignOnly
                        | ElgamalEncryptOnly
                        | Dsa
                        | ReservedEllipticCurve
                        | ReservedEcdsa
                        | ReservedFormerlyElgamalEncryptOrSign
                        | ReservedDiffieHellman
                        | PrivateOrExperimentalPublicKeyAlgorithm

type SignatureType = UnknownSignatureType
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

type OnePassSignature = {
    Version : int
    SignatureType : SignatureType
    HashAlgorithm : HashAlgorithm
    PublicKeyAlgorithm : PublicKeyAlgorithm
    SigningKeyId : byte[]
    IsNested : bool
}

type DecryptionState = {
    Input : Stream
    OnePassSignature : OnePassSignature
}

let readSignatureType (input : Stream) : SignatureType =
    match input.ReadByte() with
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

let readHashAlgorithm (input : Stream) : HashAlgorithm =
    let id = input.ReadByte()
    match id with
        | 1 -> Md5
        | 2 -> Sha1
        | 3 -> RipeMd160
        | 4 -> Reserved4
        | 5 -> Reserved5
        | 6 -> Reserved6
        | 7 -> Reserved7
        | 8 -> Sha256
        | 9 -> Sha384
        | 10 -> Sha512
        | 11 -> Sha224
        | _ when id >= 100 && id <= 110 -> PrivateOrExperimentalHashAlgorithm
        | _ -> UnknownHashAlgorithm

let readPublicKeyAlgorithm (input : Stream) : PublicKeyAlgorithm =
    let id = input.ReadByte()
    match id with
        | 1 -> RsaEncryptOrSign
        | 2 -> RsaEncryptOnly
        | 3 -> RsaSignOnly
        | 16 -> ElgamalEncryptOnly
        | 17 -> Dsa
        | 18 -> ReservedEllipticCurve
        | 19 -> ReservedEcdsa
        | 20 -> ReservedFormerlyElgamalEncryptOrSign
        | 21 -> ReservedDiffieHellman
        | _ when id >= 100 && id <= 110 -> PrivateOrExperimentalPublicKeyAlgorithm
        | _ -> UnknownPublicKeyAlgorithm

exception CouldNotReadKeyId

let readKeyId (input : Stream) : byte[] =
    let keyId = Array.zeroCreate 8
    let read = input.Read(keyId, 0, 8)
    match read with
        | 8 -> keyId
        | _ -> raise CouldNotReadKeyId

let readBool (input : Stream) : bool =
    match input.ReadByte() with
    | 0 -> false
    | _ -> true

let readOnePassSignature (input : Stream, signatureLength : int) : OnePassSignature =
    let versionNumber = input.ReadByte();
    let signatureType = readSignatureType input
    let hashAlgorithm = readHashAlgorithm input;
    let publicKeyAlgorithm = readPublicKeyAlgorithm input;
    let signingKeyId = readKeyId input;
    let isNested = readBool input

    {
        Version = versionNumber;
        SignatureType = signatureType
        HashAlgorithm = hashAlgorithm;
        PublicKeyAlgorithm = publicKeyAlgorithm;
        SigningKeyId = signingKeyId;
        IsNested = isNested
    }

let reader (state : DecryptionState, packetHeader : PacketHeader) : DecryptionState =
    printfn "%A" packetHeader
    match packetHeader.PacketTag with
        | OnePassSignaturePacket -> { state with OnePassSignature = readOnePassSignature (state.Input, packetHeader.Length) }
        | _ -> state.Input.Seek(int64 packetHeader.Length, SeekOrigin.Current) |> ignore; state

[<EntryPoint>]
let main argv =
    let file = File.OpenRead(@"C:\Users\samk\encrypted.bin")
    let message = seq {
        while file.Position <> file.Length do
            yield readPacketHeader file
    }

    let initialState = {
        Input = file
        OnePassSignature = {
            Version = 0
            SignatureType = UnknownSignatureType
            HashAlgorithm = UnknownHashAlgorithm
            PublicKeyAlgorithm = UnknownPublicKeyAlgorithm
            SigningKeyId = Array.zeroCreate 8
            IsNested = false
        }
    }

    let finalState = Seq.fold (fun state packetHeader -> reader (state, packetHeader)) initialState message
    printfn "%A" finalState
    0