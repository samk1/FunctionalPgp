module public Message

open System.IO
open PacketHeader
open SecretKeyRing
open KeyMaterial.SecretKey

type private PacketHandler<'TState> = 'TState -> PacketHeader -> 'TState

let private read<'TState> (input : Stream) (handler : PacketHandler<'TState>) (initialState : 'TState) =
    let message = seq {
        while input.Position <> input.Length do
            yield readPacketHeader input
    }

    Seq.fold handler initialState message

type SecretKeyRing(file: Stream) =
    static let initialState = {
        Input = Stream.Null
        Passphrase = null
        SecretKey = SecretKey.initial
    }
    static member private handler 
        state 
        { PacketTag = packetTag; Length = length } : SecretKeyRingState =
        printfn "%A" { PacketTag = packetTag; Length = length }
        let packetHandler = 
            match packetTag with
                | SecretKeyPacket -> 
                    fun state length -> { 
                        state with SecretKey = SecretKey.read state.Input "test123" SymmetricEncryption.decrypt }
                | _ -> 
                    fun state length -> state.Input.Seek(int64 length, SeekOrigin.Current) |> ignore; state
        packetHandler state length
    member this.read : unit = 
        let initialState: SecretKeyRingState = { initialState with Input = file }
        let finalState = read<SecretKeyRingState> file SecretKeyRing.handler initialState
        ()