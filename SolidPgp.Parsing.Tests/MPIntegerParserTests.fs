namespace SolidPgp.Parsing.Tests

open Fuchu
open System.IO
open SolidPgp.Parsing.Common

module internal MPIntegerTests =
    let testMpi1Byte = [| 0uy; 1uy; 88uy; |];
    let testMpi2Bytes = [| 0uy; 16uy; 88uy; 88uy;|]

    let makeStream (b: byte[]) =
        new MemoryStream (b)

    let makeState (b : byte[]) =
        ParseState.initStream (makeStream b)

    let mpiParseTestCase expectedBytes expectedLength mpiData () =
        let state = makeState mpiData
        match state with
        | Some state -> 
            let (result, _) = Parser.run MPInteger.parser state
            match result with
            | ParseResult (_, Some err) -> failwith (sprintf "parse failed: %A" err)
            | ParseResult (mpi, None) -> 
                printfn "parsed MPInteger: %A" mpi
                let { Length = length; Bytes = bytes} = mpi
                Assert.Equal("bytes not read correctly", expectedBytes, bytes)
                Assert.Equal("Length not read correctly", expectedLength, length)
        | None -> failwith "read failed"

    let tests = testList "MPInteger parsing tests" [
        testCase "parse 1 byte MPInteger" (mpiParseTestCase [| 88uy |] 1 testMpi1Byte)
        testCase "parse 2 byte MPInteger" (mpiParseTestCase [| 88uy; 88uy |] 16 testMpi2Bytes)
    ]