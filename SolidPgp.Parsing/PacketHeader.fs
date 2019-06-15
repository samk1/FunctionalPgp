namespace SolidPgp.Parsing

open System.IO
open SolidPgp.Parsing.Constants
open SolidPgp.Parsing.Common
open System.Runtime.InteropServices
open System

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
    | InvalidOldLengthType
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

type internal PacketTag = 
    { PacketType: PacketType option
      PacketHeaderFormat: PacketHeaderFormat option
      PacketTagOctet: int option }

module internal PacketTag =
    let initial = { PacketType = None; PacketHeaderFormat = None; PacketTagOctet = None; }

    let validatePacketType (packetTag, errorOption) =
        match errorOption with
        | None ->
            let { PacketType = packetType } = packetTag
            match packetType with
            | Some (UnknownPacketType n) -> (packetTag, Some (UnknownPacketTagError n))
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
        | Some NewFormat -> tag, { header with PacketType = Some (PacketType.ofInt (tag &&& 0b00111111)) }
        | Some OldFormat -> tag, { header with PacketType = Some (PacketType.ofInt ((tag &&& 0b00111100) >>> 2)) }
        | None -> tag, header

    let parsePacketTagOctet octet =
        let (_, packetTag) =
            (octet, initial) |> parseHeaderFormat |> parsePacketType
        { packetTag with PacketTagOctet = Some octet }

    let parser =
        Parser.unit (initial, None)
        |> BinaryParsers.uint8Reader (fun _ n -> parsePacketTagOctet n) PacketTagReadError
        |> Parser.map (ParseResult.mapResult validatePacketTag)

type internal OldPacketLengthOctetsError =
    | InvalidPacketTag
    | FirstOctetReadFailed of BinaryReadError
    | SecondOctetReadFailed of BinaryReadError
    | ThirdOctetReadFailed of BinaryReadError
    | FourthOctetReadFailed of BinaryReadError
    | UnknownLengthType

type internal OldPacketLengthOctets = { OldFormatOctets: int list; OldFormatLengthType: OldLengthType option }

module internal OldPacketLengthOctets = 
    let initial = { OldFormatOctets = []; OldFormatLengthType = None }

    let parseOldLengthType octet =
        match (octet &&& 0b00000011) with
        | 0 -> OldOneOctetLength
        | 1 -> OldTwoOctetLength
        | 2 -> FourOctetLength
        | 3 -> IndeterminateLength
        | _ -> InvalidOldLengthType

    let appendOctetReader errorType =
        BinaryParsers.uint8Reader
            (fun lengthOctets octet ->
                { lengthOctets with OldFormatOctets = (octet :: lengthOctets.OldFormatOctets) })
            errorType

    let initLengthOctetsParser lengthOctets =
        Parser.unit (lengthOctets, None)    

    let oneOctetLengthParser =
        initLengthOctetsParser 
        >> appendOctetReader FirstOctetReadFailed

    let twoOctetLengthParser =
        oneOctetLengthParser 
        >> appendOctetReader SecondOctetReadFailed

    let fourOctetLengthParser =
        twoOctetLengthParser
        >> appendOctetReader ThirdOctetReadFailed
        >> appendOctetReader FourthOctetReadFailed

    let lengthOctetsParser packetTag =
        let { PacketTagOctet = octetOption } = packetTag
        let lengthType = Option.map parseOldLengthType octetOption

        let selector lengthOctets = 
            let { OldFormatLengthType = lengthTypeOption } = lengthOctets
            match lengthTypeOption with
            | Some OldOneOctetLength -> oneOctetLengthParser lengthOctets
            | Some OldTwoOctetLength -> twoOctetLengthParser lengthOctets
            | Some FourOctetLength -> fourOctetLengthParser lengthOctets
            | Some _ -> Parser.unit (lengthOctets, None)
            | None -> Parser.unit (lengthOctets, Some UnknownLengthType)

        { initial with OldFormatLengthType = lengthType }
        |> selector

type internal NewLengthType2 =
    | OneOctetLength
    | TwoOctetLength
    | FiveOctetLength
    | PartialBodyLength

type internal  NewPacketLengthOctets =
    { NewFormatOctets: int list
      NewFormatLengthType: NewLengthType2 option; }

type internal NewPacketLengthOctetsError =
    | FirstOctetReadFailed of BinaryReadError
    | SecondOctetReadFailed of BinaryReadError
    | ThirdOctetReadFailed of BinaryReadError
    | FourthOctetReadFailed of BinaryReadError
    | FifthOctetReadFailed of BinaryReadError
    | UnknownLengthType

module internal NewPacketLength =
    let initial =
        { NewFormatOctets = []; NewFormatLengthType = None; }

    let parseLengthType octet =    
        if octet < 192 then Some OneOctetLength
        elif octet < 223 then Some TwoOctetLength
        elif octet < 255 then Some PartialBodyLength
        elif octet = 255 then Some FiveOctetLength
        else None

    let appendOctetReader errorType =
        BinaryParsers.uint8Reader
            (fun lengthOctets octet ->
                { lengthOctets with NewFormatOctets = (octet :: lengthOctets.NewFormatOctets) })
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

    let makeLengthOctetsParser =
        let selectLengthOctetsParser lengthOctets =
            let { NewFormatLengthType = lengthType } = lengthOctets
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
                { lengthOctets with NewFormatOctets = [ octet ]; NewFormatLengthType = parseLengthType octet })
            FirstOctetReadFailed
        |> Parser.apply makeLengthOctetsParser        

type internal PacketLength = PacketLength of int option

type internal OldFormatPacketLengthErrorType =
    | InvalidSingleOctetLength
    | InvalidTwoOctetLength
    | InvalidFourOctetLength
    | UnspecifiedLengthType

type internal NewFormatPacketLengthErrorType =
    | InvalidSingleOctetLength
    | InvalidTwoOctetLength
    | InvalidFiveOctetLength
    | UnspecifiedLengthType

type internal PacketLengthError =
    | OldFormatPacketLengthError of OldFormatPacketLengthErrorType
    | NewFormatPacketLengthError of NewFormatPacketLengthErrorType
    | NoLengthOctetsType
    | PacketTagParsingFailed of PacketTagError

module internal PacketLength =
    let initial =
        PacketLength None

    let computeOldFormatLength oldLengthOctets =
        let { OldFormatLengthType = lengthType; OldFormatOctets = octets } = oldLengthOctets
        let lengthComputationResult =
            match lengthType with
            | Some OldOneOctetLength ->
                match octets with
                | [ length ] -> (Some length, None)
                | _ -> (None, Some OldFormatPacketLengthErrorType.InvalidSingleOctetLength)
            | Some OldTwoOctetLength ->
                match octets with
                | [ length1; length2 ] -> (Some (length1 <<< 8 ||| length2), None)
                | _ -> (None, Some OldFormatPacketLengthErrorType.InvalidTwoOctetLength)
            | Some FourOctetLength ->
                match octets with
                | [ length1; length2; length3; length4 ] ->
                    (Some ((length1 <<< 24) ||| (length2 <<< 16) ||| (length3 <<< 8) ||| length4), None)
                | _ -> (None, Some InvalidFourOctetLength)                    
            | Some IndeterminateLength -> (None, None)
            | _ -> (None, Some OldFormatPacketLengthErrorType.UnspecifiedLengthType)
        let (length, error) = lengthComputationResult
        ParseResult.unit (PacketLength length, Option.map OldFormatPacketLengthError error)     

    let mapOldLengthOctetsParser parser =
        Parser.map (ParseResult.bindf computeOldFormatLength) parser

    let computeNewFormatLength newLengthOctets =
        let { NewFormatLengthType = lengthType; NewFormatOctets = octets} = newLengthOctets
        let lengthComputationResult =
            match lengthType with
            | Some OneOctetLength ->
                match octets with
                | [ length ] -> (Some length, None)
                | _ -> (None, Some NewFormatPacketLengthErrorType.InvalidSingleOctetLength)
            | Some TwoOctetLength ->
                match octets with
                | [ length1; length2 ] -> (Some (((length1 - 192) <<< 8) + length2 + 192)), None
                | _ -> None, Some NewFormatPacketLengthErrorType.InvalidTwoOctetLength
            | Some FiveOctetLength ->
                match octets with
                | [ length1; length2; length3; length4 ] ->
                    (Some ((length1 <<< 24) ||| (length2 <<< 16) ||| (length3 <<< 8) ||| length4), None)
                | _ -> None, Some NewFormatPacketLengthErrorType.InvalidFiveOctetLength
            | Some PartialBodyLength -> (None, None)
            | None -> (None, Some NewFormatPacketLengthErrorType.UnspecifiedLengthType)
        let (length, error) = lengthComputationResult
        ParseResult.unit (PacketLength length, Option.map NewFormatPacketLengthError error)

    let mapNewLengthOctetsParser parser =
        Parser.map (ParseResult.bindf computeNewFormatLength) parser

    let mapLengthParser packetTag =
        let { PacketHeaderFormat = headerFormat } = packetTag
        match headerFormat with
        | Some OldFormat -> 
            mapOldLengthOctetsParser
                (OldPacketLengthOctets.lengthOctetsParser packetTag)
        | Some NewFormat -> mapNewLengthOctetsParser NewPacketLength.parser
        | None -> Parser.unit (initial, Some NoLengthOctetsType)


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

type internal PacketHeaderError =
    | PacketTagReadError of PacketTagError
    | PacketLengthReadError of PacketLengthError

type internal PacketHeader2 = { PacketType: PacketType option; PacketLength: PacketLength }

module internal PacketHeader =
    let initial = { PacketType = None; PacketLength = PacketLength.initial }

    let mapPacketTag packetHeader packetTag  = 
        let { PacketTag.PacketType = packetTagOption } = packetTag
        { packetHeader with PacketHeader2.PacketType = packetTagOption }

    let mapPacketLength packetHeader packetLength  =
        { packetHeader with PacketLength = packetLength }

    let makePacketHeader (packetLengthResult, packetTagResult) packetHeader =
        let mapPacketTagResult packetTag packetHeader = 
            ParseResult.map2 
                (mapPacketTag packetHeader)
                (fun err -> (initial, PacketTagReadError err))
                packetTag

        let mapPacketLengthResult packetLength packetHeader =
            ParseResult.map2
                (mapPacketLength packetHeader)
                (fun err -> (initial, PacketLengthReadError err))
                packetLength
        ParseResult.success packetHeader
        |> ParseResult.bindf (mapPacketLengthResult packetLengthResult)
        |> ParseResult.bindf (mapPacketTagResult packetTagResult)
        
    let parser =
        let packetHeaderParser state =
            let (packetTagResult, state) = Parser.run PacketTag.parser state
            let lengthParser = 
                    (ParseResult.bind 
                        PacketLength.mapLengthParser
                        (fun (_, error) -> 
                            Parser.unit (PacketLength.initial, error |> (PacketTagParsingFailed >> Some)))
                        packetTagResult)
            let (packetLengthResult, state) = Parser.run lengthParser state
            (makePacketHeader (packetLengthResult, packetTagResult) initial), state
        Parser packetHeaderParser


