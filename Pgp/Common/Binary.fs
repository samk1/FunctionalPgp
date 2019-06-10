namespace Pgp.Common

open System
open System.IO
open System.Diagnostics

type internal BinaryReadError = PrematureEndOfStream

module internal Binary =
    let tryReadInt state f onSuccess onError =
        try
            let result = (onSuccess (f state.BinaryReader))
            result
        with
        | :? System.IO.EndOfStreamException -> 
            onError PrematureEndOfStream

    let readByte state =
        tryReadInt state (fun br -> int (br.ReadByte ()))

    let readUint16FromBinaryReader (br: BinaryReader) =
        let b1 = br.ReadByte ()
        let b2 = br.ReadByte ()
        int (BitConverter.ToUInt16 ([| b2; b1 |], 0))

    let readUint16 state =
        tryReadInt state readUint16FromBinaryReader

    let readUint32FromBinaryReader (br: BinaryReader) =
        let b1 = br.ReadByte ()
        let b2 = br.ReadByte ()
        let b3 = br.ReadByte ()
        let b4 = br.ReadByte ()
        int64 (BitConverter.ToUInt32 ([| b4; b3; b2; b1 |], 0))

    let readUint32 state =
        tryReadInt state readUint32FromBinaryReader

    let readBytes state count onSuccess onError =
        try
            let result = onSuccess (state.BinaryReader.ReadBytes (count))
            result
        with
        | :? System.IO.EndOfStreamException -> 
            onError PrematureEndOfStream

module internal BinaryParsers =
    let byteArrayParser =
        let parseBytes state =
            (fun count -> (Binary.readBytes state count
                ParseResult.success (fun err -> ParseResult.failure ((Array.zeroCreate<byte> 0), err)))), 
            state
        Parser parseBytes

    let uint32Parser =
        let parser state =
            (Binary.readUint32 state
                ParseResult.success
                (fun err -> ParseResult.failure (0L, err))), state
        Parser parser

    let uint32Reader withInt64 withError =
        Parser.foldpr withInt64 withError uint32Parser    

    let uint16Parser =
        let parser state =
            (Binary.readUint16 state
                ParseResult.success
                (fun err -> ParseResult.failure (0, err))), state
        Parser parser

    let uint16Reader withInt withError =
        Parser.foldpr withInt withError uint16Parser

    let uint8Parser =
        let parser state =
            (Binary.readByte state
                ParseResult.success
                (fun err -> ParseResult.failure (0, err))), state
        Parser parser

    let uint8Reader withInt withError =
        Parser.foldpr withInt withError uint8Parser           
