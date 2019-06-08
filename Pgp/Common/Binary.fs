namespace Pgp.Common

open System
open System.IO

type internal BinaryReadError = PrematureEndOfStream

module internal Binary =
    let tryReadInt state f onSuccess onError =
        try
            let result = f state.BinaryReader
            printfn "read %A" result
            (onSuccess result)
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

    let readUint32 state =
        tryReadInt state (fun br -> int64 (br.ReadUInt32 ()))    

    let uint16Parser =
        let parser state =
            (readUint16 state
                ParseResult.success
                (fun err -> ParseResult.failure (0, err))), state
        Parser parser

    let uint16Read withInt withError =
        Parser.makeReader uint16Parser withInt withError

    let uint32Parser =
        let parser state =
            (readUint32 state
                ParseResult.success
                (fun err -> ParseResult.failure (0L, err))), state
        Parser parser

    let uint32Read withInt64 withError =
        Parser.makeReader uint32Parser withInt64 withError              

    let readBytes state count onSuccess onError =
        try
            onSuccess (state.BinaryReader.ReadBytes (count))
        with
        | :? System.IO.EndOfStreamException -> 
            printf "read failed"
            onError PrematureEndOfStream

    let makeByteArrayParser count =
        let parser state =
            (readBytes state count
                ParseResult.success
                (fun err -> ParseResult.failure ((Array.zeroCreate<byte> 0), err))), state
        Parser parser

    let makeByteArrayRead withByteArray withError count =
        Parser.makeReader (makeByteArrayParser count) withByteArray withError