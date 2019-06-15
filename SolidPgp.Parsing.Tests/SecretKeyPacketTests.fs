namespace SolidPgp.Parsing.Tests
open Fuchu
open System.IO
open SolidPgp.Parsing.KeyMaterial
    
module SecretKeyPacketTests =
    let secretKeyPacketStream () 
        = new MemoryStream(TestData.SecretKeyPacket)

    let tests = testList "Secret key packet tests" [
        testCase "Read secret key packet" <| fun _ ->
            let input = secretKeyPacketStream ()
            let packetHeader = SolidPgp.Parsing.PacketHeader.Read input
            printfn "%A" packetHeader
            let secretKey = SecretKeyFactory.fromStream input "open sesame" SolidPgp.Parsing.SymmetricEncryption.decrypt
            printfn "Secret key: %A" secretKey
            ()        
    ]