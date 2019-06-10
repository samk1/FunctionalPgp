namespace Pgp

open System.IO
open Pgp.Constants
open Pgp.Common
open System.Runtime.InteropServices

exception internal UnknownPacketTagException

exception internal UnknownLengthTypeException

exception internal UnsupportedLengthTypeException    

type internal PacketHeaderFormat = NewFormat | OldFormat

type internal NewLengthType = 
    | OneOctetLength of int
    | TwoOctetLength of int
    | FiveOctetLength of int
    | PartialBodyLength of int
    with
    static member Read (octet : int) : NewLengthType =
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

type internal PacketTagError =
    | PacketTagReadError of BinaryReadError
    | UnknownPacketTagError of int
    | UnknownHeaderFormat

type internal PacketTag = { PacketType: PacketType; PacketHeaderFormat: PacketHeaderFormat option}

module internal PacketTag =
    let initial = { PacketType = UnknownPacketType 0; PacketHeaderFormat = None }

    let validatePacketType (packetTag, errorOption) =
        match errorOption with
        | None ->
            let { PacketType = packetType } = packetTag
            match packetType with
            | UnknownPacketType n -> (packetTag, Some (UnknownPacketTagError n))
            | _ -> (packetTag, None)
        | Some error -> (packetTag, Some error)

    let validateHeaderFormat (packetTag, errorOption) =
        match errorOption with
        | None ->
            let { PacketHeaderFormat = headerFormat } = packetTag
            match headerFormat with
            | Some _ -> (packetTag, None)
            | None -> (packetTag, Some UnknownHeaderFormat)
        | Some error -> (packetTag, Some error)

    let validatePacketTag packetTag =
        (packetTag, None) |> validatePacketType |> validateHeaderFormat    

    let parseHeaderFormat (tag, header) =
        match (0b01000000 &&& tag) with
        | 0 -> tag, { header with PacketHeaderFormat = Some OldFormat }
        | _ -> tag, { header with PacketHeaderFormat = Some NewFormat }

    let parsePacketType (tag, header) =
        let { PacketHeaderFormat = headerFormat } = header
        match headerFormat with    
        | Some NewFormat -> tag, { header with PacketType = PacketType.ofInt (tag &&& 0b00111111) }
        | Some OldFormat -> tag, { header with PacketType = PacketType.ofInt ((tag &&& 0b00111100) >>> 2) }
        | None -> tag, header

    let parsePacketTag tag =
        let (_, packetTag) =
            (tag, initial) |> parseHeaderFormat |> parsePacketType
        packetTag        

    let parser =
        Parser.unit (initial, None)
        |> BinaryParsers.uint8Reader (fun _ n -> parsePacketTag n) PacketTagReadError
        |> Parser.map (ParseResult.mapResult validatePacketTag)

type internal NewLengthType2 =
    | OneOctetLength
    | TwoOctetLength
    | FiveOctetLength
    | PartialBodyLength

type internal  NewPacketLengthOctets =
    { Octets: int list
      LengthType: NewLengthType2 option; }

type internal NewPacketLengthOctetsError =
    | FirstOctetReadFailed of BinaryReadError
    | SecondOctetReadFailed of BinaryReadError
    | ThirdOctetReadFailed of BinaryReadError
    | FourthOctetReadFailed of BinaryReadError
    | FifthOctetReadFailed of BinaryReadError
    | UnknownLengthType

module internal NewPacketLength =
    let initial =
        { Octets = []; LengthType = None; }

    let parseLengthType octet =    
        if octet < 192 then Some OneOctetLength
        elif octet < 223 then Some TwoOctetLength
        elif octet < 255 then Some PartialBodyLength
        elif octet = 255 then Some FiveOctetLength
        else None

    let appendOctetReader errorType =
        BinaryParsers.uint8Reader
            (fun lengthOctets octet ->
                { lengthOctets with Octets = (octet :: lengthOctets.Octets) })
            errorType

    let twoOctetLengthParser lengthOctets =
        Parser.unit (lengthOctets, None)
        |> appendOctetReader SecondOctetReadFailed

    let fiveOctetLengthParser lengthOctets =
        Parser.unit (lengthOctets, None)
        |> appendOctetReader SecondOctetReadFailed
        |> appendOctetReader ThirdOctetReadFailed
        |> appendOctetReader FourthOctetReadFailed
        |> appendOctetReader FifthOctetReadFailed

    let selectLengthOctetsParser lengthOctets =
        let { LengthType = lengthType } = lengthOctets
        match lengthType with
        | Some TwoOctetLength -> twoOctetLengthParser lengthOctets
        | Some FiveOctetLength -> fiveOctetLengthParser lengthOctets
        | Some _ -> Parser.unit (lengthOctets, None)
        | None -> Parser.unit (lengthOctets, Some UnknownLengthType)

    let makeLengthOctetsParser =
        let selectLengthOctetsParser lengthOctets =
            let { LengthType = lengthType } = lengthOctets
            match lengthType with
            | Some TwoOctetLength -> twoOctetLengthParser lengthOctets
            | Some FiveOctetLength -> fiveOctetLengthParser lengthOctets
            | Some _ -> Parser.unit (lengthOctets, None)
            | None -> Parser.unit (lengthOctets, Some UnknownLengthType)

        let lengthOctetsParser state =
            (ParseResult.bindf (fun lengthOctets ->
                let (result, _) = Parser.run (selectLengthOctetsParser lengthOctets) state
                result)),
            state
        Parser lengthOctetsParser

    let parser =
        Parser.unit (initial, None)
        |> BinaryParsers.uint8Reader 
            (fun lengthOctets octet -> 
                { lengthOctets with Octets = [ octet ]; LengthType = parseLengthType octet })
            FirstOctetReadFailed
        |> Parser.apply makeLengthOctetsParser        

type internal PacketLength = PacketLength of int option

module internal PacketLength =
    let initial =
        PacketLength None

type internal PacketHeader = 
    { 
        PacketTag : PacketType; 
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
        let (tag, lengthType) = (PacketType.Read (packetTag &&& 0b00111111), NewLengthType.Read (input.ReadByte()))
        match lengthType with
        | NewLengthType.OneOctetLength octet -> { PacketTag = tag; Length = octet }
        | NewLengthType.TwoOctetLength octet -> { PacketTag = tag; Length = NewLengthType.ReadTwoOctet octet input }
        | NewLengthType.FiveOctetLength _ -> { PacketTag = tag; Length = NewLengthType.ReadFiveOctet input }
        | NewLengthType.PartialBodyLength _ -> raise UnsupportedLengthTypeException

    static member ReadOldFormat (input : Stream) (packetTag : int) =
        let (tag, lengthType) = 
            (PacketType.Read ((0b00111100 &&& packetTag) >>> 2), 
             OldLengthType.Read (0b00000011 &&& packetTag))
        match lengthType with
        | OldOneOctetLength -> { PacketTag = tag; Length = input.ReadByte() }
        | OldTwoOctetLength -> { PacketTag = tag; Length = OldLengthType.ReadTwoOctet input}
        | FourOctetLength -> { PacketTag = tag; Length = OldLengthType.ReadFourOctet input}
        | IndeterminateLength -> raise UnsupportedLengthTypeException
