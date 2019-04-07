module SecretKeyRing

open System.IO
open PacketHeader
open System
open KeyMaterial.SecretKey

type SecretKeyRingState = {
    Input : Stream
    Passphrase : string
    SecretKey : SecretKey
}

let initialState = {
    Input = Stream.Null
    Passphrase = null
    SecretKey = SecretKey.initial
}

let handler 
    state 
    { PacketTag = packetTag; Length = length }  
    (
    ) : SecretKeyRingState =
    printfn "%A" { PacketTag = packetTag; Length = length }
    let packetHandler = match packetTag with
        | SecretKeyPacket -> 
            fun state length -> { 
                state with SecretKey = SecretKey.read state.Input "test123" SymmetricEncryption.decrypt }
        | _ -> 
            fun state length -> state.Input.Seek(int64 length, SeekOrigin.Current) |> ignore; state
    packetHandler state length