namespace Pgp.Common

open Pgp
open System.IO
open System.Runtime.ExceptionServices

type internal MPInteger = { Length: int; Bytes : byte[] }

type internal InvalidMPIntegerLengthInfo =
    {
        Position: int64
        InvalidLength: int
    }

type internal MPIntegerErrorType =
    InvalidMPIntegerLength
    | MPIntegerLengthReadError of BinaryReadError
    | MPIntegerBytesReadError of BinaryReadError

type internal MPIntegerError = MPIntegerError of MPIntegerErrorType

type internal MPIntegerParseResult = ParseResult<MPInteger, MPIntegerError>

module internal MPInteger =
    let initial = { Length = 0; Bytes = null }
    
    let mpiSize mpi = 
        (mpi.Length + 7) / 8

    let bytesParser mpiParser =
        Parser.apply
            (Parser.map
                (fun f -> 
                    ParseResult.mapf
                        (fun mpi bytes -> { mpi with Bytes = bytes })
                        (MPIntegerBytesReadError >> MPIntegerError)
                        (ParseResult.bindf (mpiSize >> f)))
                BinaryParsers.byteArrayParser)
            mpiParser

    let parser =
        Parser.unit (initial, None)
        |> BinaryParsers.uint16Reader 
            (fun mpi n -> { mpi with Length = n }) 
            (MPIntegerLengthReadError >> MPIntegerError)
        |> Parser.validate 
            (fun mpi -> mpi.Length > 0) 
            (MPIntegerError InvalidMPIntegerLength)
        |> bytesParser

    let read withMpi withMpiError =
        Parser.foldpr withMpi withMpiError parser
            