namespace Pgp.Parsing

open System.IO
open Pgp.Parsing


type internal DecryptionState = 
    {
        Input : Stream
        OnePassSignature : OnePassSignature
        PublicKeyEncryptedSessionKey : PublicKeyEncryptedSessionKey
    } with
    static member Initial = 
        { Input = Stream.Null
          OnePassSignature = OnePassSignature.Initial
          PublicKeyEncryptedSessionKey = PublicKeyEncryptedSessionKey.Initial }

type internal PacketHandler = PacketTag of (DecryptionState -> int -> DecryptionState)

module internal Decryption =
    let handler 
        state 
        { PacketTag = packetTag; Length = length }  
        (
            onePassSignaturePacketHandler, 
            publicKeyEncryptedSessionKeyPacketHandler
        ) : DecryptionState =
        printfn "%A" { PacketTag = packetTag; Length = length }
        let packetHandler = 
            match packetTag with
            | OnePassSignaturePacket -> onePassSignaturePacketHandler
            | PublicKeyEncryptedSessionKeyPacket -> publicKeyEncryptedSessionKeyPacketHandler
            | _ -> fun state length -> state.Input.Seek(int64 length, SeekOrigin.Current) |> ignore; state
        packetHandler state length