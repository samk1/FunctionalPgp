namespace SolidPgp.Parsing.Tests

open Fuchu
open System.IO
open SolidPgp.Parsing.Common
open SolidPgp.Parsing.KeyMaterial

module internal PublicKeyPacketData =
    let testPublicKeyPacket = 
        [| 
            153uy; 1uy; 13uy; 4uy; 92uy; 254uy; 5uy; 242uy; 2uy; 8uy; 0uy; 175uy; 58uy; 132uy; 208uy; 9uy
            8uy; 196uy; 59uy; 184uy; 161uy; 224uy; 44uy; 112uy; 138uy; 34uy; 156uy; 146uy; 115uy; 41uy; 156uy; 255uy
            193uy; 116uy; 69uy; 234uy; 247uy; 151uy; 195uy; 31uy; 31uy; 141uy; 37uy; 139uy; 69uy; 187uy; 87uy; 109uy
            102uy; 206uy; 167uy; 98uy; 48uy; 40uy; 194uy; 148uy; 66uy; 48uy; 251uy; 198uy; 101uy; 72uy; 41uy; 122uy
            17uy; 81uy; 54uy; 245uy; 203uy; 148uy; 246uy; 135uy; 95uy; 224uy; 194uy; 216uy; 22uy; 124uy; 39uy; 9uy
            127uy; 154uy; 222uy; 115uy; 48uy; 163uy; 186uy; 56uy; 211uy; 132uy; 87uy; 134uy; 120uy; 124uy; 178uy; 234uy
            250uy; 243uy; 18uy; 203uy; 209uy; 222uy; 83uy; 126uy; 250uy; 126uy; 104uy; 255uy; 97uy; 233uy; 129uy; 24uy
            169uy; 7uy; 100uy; 87uy; 78uy; 127uy; 105uy; 161uy; 201uy; 68uy; 223uy; 40uy; 230uy; 182uy; 180uy; 123uy
            64uy; 167uy; 140uy; 225uy; 148uy; 254uy; 35uy; 151uy; 179uy; 224uy; 15uy; 176uy; 100uy; 57uy; 117uy; 249uy
            69uy; 144uy; 125uy; 15uy; 77uy; 123uy; 132uy; 245uy; 152uy; 106uy; 74uy; 218uy; 172uy; 151uy; 240uy; 254uy
            217uy; 232uy; 101uy; 142uy; 156uy; 37uy; 179uy; 253uy; 84uy; 214uy; 33uy; 149uy; 234uy; 46uy; 97uy; 240uy
            86uy; 140uy; 11uy; 54uy; 189uy; 62uy; 3uy; 63uy; 224uy; 218uy; 33uy; 207uy; 155uy; 95uy; 157uy; 246uy
            13uy; 2uy; 113uy; 151uy; 82uy; 73uy; 161uy; 98uy; 69uy; 237uy; 66uy; 222uy; 101uy; 227uy; 211uy; 127uy
            236uy; 75uy; 199uy; 212uy; 150uy; 226uy; 213uy; 57uy; 0uy; 126uy; 66uy; 80uy; 40uy; 49uy; 5uy; 219uy
            132uy; 182uy; 48uy; 192uy; 16uy; 4uy; 244uy; 147uy; 154uy; 206uy; 48uy; 160uy; 114uy; 244uy; 198uy; 10uy
            234uy; 196uy; 159uy; 233uy; 253uy; 242uy; 5uy; 87uy; 35uy; 160uy; 7uy; 144uy; 172uy; 208uy; 37uy; 234uy
            245uy; 218uy; 15uy; 223uy; 168uy; 233uy; 142uy; 168uy; 102uy; 221uy; 77uy; 0uy; 17uy; 1uy; 0uy; 1uy 
        |]

module internal PublicKeyPacketTests =
    let makeState (data: byte[]) =
        match ParseState.initStream (new MemoryStream (data)) with
        | Some state -> state
        | None -> failwith "test data not readable"

    let parsePublicKeyPacket (data: byte[]) =
        let state = makeState data
        let (result, state) = Parser.run SolidPgp.Parsing.PacketHeader.parser state
        printfn "packet header: %A" result

        let (result, _) = Parser.run PublicKey.parser state
        match result with
        | ParseResult (publicKey, None) ->
            printfn "parsed public key: %A" publicKey
        | ParseResult (_, Some error) ->
            failwith (sprintf "parse failed: %A" error)

    let tests = testList "Public key packet parsing tests" [
        testCase "parse public key packet" 
            (fun () -> parsePublicKeyPacket PublicKeyPacketData.testPublicKeyPacket)        
    ]