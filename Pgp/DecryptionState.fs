module DecryptionState

open System.IO
open PacketHeader
open OnePassSignature
open PublicKeyEncryptedSessionKey


type DecryptionState = {
    Input : Stream
    OnePassSignature : OnePassSignature
    PublicKeyEncryptedSessionKey : PublicKeyEncryptedSessionKey
}




let initialDecryptionState = {
    Input = Stream.Null
    OnePassSignature = OnePassSignature.initial
    PublicKeyEncryptedSessionKey = PublicKeyEncryptedSessionKey.initial
}

type PacketHandler = PacketTag of (DecryptionState -> int -> DecryptionState)

let handler 
    state 
    { PacketTag = packetTag; Length = length }  
    (
        onePassSignaturePacketHandler, 
        publicKeyEncryptedSessionKeyPacketHandler
    ) : DecryptionState =
    printfn "%A" { PacketTag = packetTag; Length = length }
    let packetHandler = match packetTag with
        | OnePassSignaturePacket -> onePassSignaturePacketHandler
        | PublicKeyEncryptedSessionKeyPacket -> publicKeyEncryptedSessionKeyPacketHandler
        | _ -> fun state length -> state.Input.Seek(int64 length, SeekOrigin.Current) |> ignore; state
    packetHandler state length