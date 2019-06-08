namespace Pgp.Common

open Pgp
open System.IO

type internal MPInteger = { Length: int; Bytes : byte[] }

type internal InvalidMPIntegerLengthInfo =
    {
        Position: int64
        InvalidLength: int
    }

type internal MPIntegerReadError =
    InvalidMPIntegerLength
    | MPIntegerReadError of BinaryReadError

type internal MPIntegerParseResult = ParseResult<MPInteger, MPIntegerReadError>

module internal MPInteger =
    let initial = { Length = 0; Bytes = null }
    
    let mpiSize mpi = 
        (mpi.Length + 7) / 8

    let validMpiSize mpiResult =
        match mpiResult with
        | ParseResult (mpi, None) ->
            if (mpiSize mpi > 0) then
                ParseResult.success mpi
            else
                ParseResult.failure (mpi, InvalidMPIntegerLength)
        | ParseResult (mpi, Some err) -> ParseResult.failure (mpi, err)     

    let setMpiBytes mpiResult byteResult =
        match mpiResult with
        | ParseResult (mpi, None) ->
            match byteResult with
            | ParseResult (bytes, None) -> ParseResult.success ({ mpi with Bytes = bytes})
            | ParseResult (_, Some err) -> ParseResult.failure (mpi, (MPIntegerReadError err))
        | ParseResult (mpi, Some err) -> ParseResult.failure (mpi, err)

    let mpiLengthParser = 
        Parser.unit (initial, None)
        |> Binary.uint16Read 
            (fun mpi n -> { mpi with Length = n })
            (fun _ (_, err) -> MPIntegerReadError err)

    let makeMpiBytesParser =
        let parser mpiResult =
            let mpiParser = 
                match validMpiSize mpiResult with
                    | ParseResult (mpi, None) -> mpi |> mpiSize |> Binary.makeByteArrayParser
                    | ParseResult (_, Some _) -> Parser.unit (Array.zeroCreate 0, None)
            Parser.map (setMpiBytes mpiResult) mpiParser
        Parser.bind parser

    let parser =
        mpiLengthParser |> makeMpiBytesParser

    let read withMpi withMpiError =
        Parser.fold 
            (ParseResult.foldResult withMpi)
            (ParseResult.foldError (fun _ (_, mpiError) -> withMpiError mpiError))
            parser