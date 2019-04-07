// Learn more about F# at http://fsharp.org

open System
open System.IO

open PacketHeader
open DecryptionState
open SecretKeyRing

type PacketHandler<'TState> = 'TState -> PacketHeader -> 'TState


let readMessage<'TState> (input : Stream) (handler : PacketHandler<'TState>) (initialState : 'TState) =
    let message = seq {
        while input.Position <> input.Length do
            yield readPacketHeader input
    }

    Seq.fold handler initialState message

let decryptionHandler = 
    fun state header -> (DecryptionState.handler state header (
                            (fun state length -> 
                                { state with OnePassSignature = 
                                                OnePassSignature.read state.Input length }), 
                            (fun state length -> 
                                { state with PublicKeyEncryptedSessionKey = 
                                                PublicKeyEncryptedSessionKey.read state.Input length })))

let secretKeyRingHandler =
    fun state header -> (SecretKeyRing.handler state header (
                            ))

[<EntryPoint>]
let main argv =
    let file = File.OpenRead(@"C:\Users\samk\mykey.key")
    let initialKeyRingState = { SecretKeyRing.initialState with Input = file }
    let finalKeyRingState = readMessage file secretKeyRingHandler initialKeyRingState
    printfn "%A" finalKeyRingState

    let file = File.OpenRead(@"C:\Users\samk\encrypted.bin")
    let initialState = { initialDecryptionState with Input = file }
    let finalState = readMessage file decryptionHandler initialState

    printfn "%A" finalState
    0