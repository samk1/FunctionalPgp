namespace Pgp.Messages

open System.IO
open KeyMaterial.SecretKey
open Pgp

type private SecretKeyRingState = 
    { Input : Stream
      Passphrase : string
      SecretKey : SecretKey }

type SecretKeyRingReader(file : Stream) =
    static let initialState = {
        Input = Stream.Null
        Passphrase = null
        SecretKey = SecretKey.initial
    }
    
    static let handler 
        state 
        { PacketTag = packetTag; Length = length } : SecretKeyRingState =
        printfn "%A" { PacketTag = packetTag; Length = length }
        let packetHandler = 
            match packetTag with
            | SecretKeyPacket -> 
                fun state _ -> 
                    { state with SecretKey = SecretKey.Read state.Input "test123" SymmetricEncryption.decrypt }
            | _ -> 
                fun state length -> state.Input.Seek(int64 length, SeekOrigin.Current) |> ignore; state
        packetHandler state length
    member this.Read =
        //Message.read<SecretKeyRingState> file handler { initialState with Input = file } |> ignore;
        ()