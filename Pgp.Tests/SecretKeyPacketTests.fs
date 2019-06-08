namespace Pgp.Tests
open Fuchu
open System.IO
open Pgp.KeyMaterial.SecretKey
    
module SecretKeyPacketTests =
    let secretKeyPacketStream () 
        = new MemoryStream(TestData.SecretKeyPacket)

    let tests = testList "Secret key packet tests" [
        testCase "Read secret key packet" <| fun _ ->
            let input = secretKeyPacketStream ()
            let packetHeader = Pgp.PacketHeader.Read input
            printfn "%A" packetHeader
            let secretKey = SecretKeyFactory.fromStream input "open sesame" Pgp.SymmetricEncryption.decrypt
            printfn "Secret key: %A" secretKey
            ()        
    ]