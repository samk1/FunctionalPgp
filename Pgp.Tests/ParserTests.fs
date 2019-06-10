namespace Pgp.Tests

open Fuchu
open System.IO
open Pgp.Common

type TestType = TestType of (int * string)

module internal ParserTests =
    let adder =
        BinaryParsers.uint16Reader ( + ) id

    let testParser =
        Parser.unit (0, None)
        |> adder
        |> BinaryParsers.uint32Reader (fun a b -> (int a) + (int b))  id
        |> adder

    let testCompoundParser =
        Parser.unit (TestType (0, ""), None)
        |> Parser.foldpr (fun (TestType (a, s)) b -> TestType ((a - b), s + "a")) id testParser
        |> Parser.dump
        |> Parser.foldpr (fun (TestType (a, s)) b -> TestType ((a - b), s + "b")) id testParser
        |> Parser.foldpr (fun (TestType (a, s)) b -> TestType ((a - b), s + "c")) id testParser

    let testData = [| 0uy; 1uy; 0uy; 0uy; 0uy; 1uy; 0uy; 1uy; |]

    let testCompoundData = Array.concat [testData; testData; testData]

    let testStream () = new MemoryStream (testData)

    let testCompoundStream () = new MemoryStream (testCompoundData)

    let tests = testList "Parser tests" [
        testCase "run composed parser" <| fun _ ->
            let state = ParseState.initStream (testStream ())
            match state with
            | Some state ->
                let (result, _) = Parser.run testParser state
                printfn "parse result: %A" result
            | None -> printfn "read failed"

        testCase "run compound parser" <| fun _ ->
            let state = ParseState.initStream (testCompoundStream ())
            match state with
            | Some state ->
                let (result, _) = Parser.run testCompoundParser state
                printfn "compound parse result: %A" result
            | None -> printfn "read failed"
    ]
