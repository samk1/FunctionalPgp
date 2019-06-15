namespace SolidPgp.Parsing.Tests

open SolidPgp.Parsing.Common
open Fuchu
open System.IO

module internal PacketHeaderTests =
    let makeState (data: byte[]) =
        match ParseState.initStream (new MemoryStream (data)) with
        | Some state -> state
        | None -> failwith "test data not readable"

    let testPacketHeaderCase packetHeaderCase () =
        let testData, testName, expectedLength, actualTag = packetHeaderCase
        let state = makeState testData
        let (result, state) = Parser.run SolidPgp.Parsing.PacketHeader.parser state
        printfn "%s" testName
        printfn "%A" result

        match result with
        | ParseResult (header, None) ->
            let { SolidPgp.Parsing.PacketHeader2.PacketLength = packetLength} = header
            let (SolidPgp.Parsing.PacketLength lengthOption) = packetLength
            match lengthOption with
            | Some length -> Assert.Equal("length does not match", expectedLength, int64 length)
            | None -> printfn "no packet length"
        | _ -> failtest "packet header parsing failed"      

    let makePacketHeaderTestCase packetHeaderCase =
        let testData, testName, actualLength, actualTag = packetHeaderCase
        testCase testName (testPacketHeaderCase packetHeaderCase)

    let tests = 
        testList 
            "Packet header test cases" 
            (List.map makePacketHeaderTestCase PacketHeaderTestCases.cases)