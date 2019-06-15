namespace Pgp.Parsing.Tests
open Fuchu
open System.IO
open Pgp.Parsing.KeyMaterial
    
module SecretKeyPacketTests =
    let secretKeyPacketStream () 
        = new MemoryStream(TestData.SecretKeyPacket)

    let tests = testList "Secret key packet tests" [
        testCase "Read secret key packet" <| fun _ ->
            let input = secretKeyPacketStream ()
            let packetHeader = Pgp.Parsing.PacketHeader.Read input
            printfn "%A" packetHeader
            let secretKey = SecretKeyFactory.fromStream input "open sesame" Pgp.Parsing.SymmetricEncryption.decrypt
            printfn "Secret key: %A" secretKey
            ()        
    ]