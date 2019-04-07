module Common.KeyId

open System.IO

exception CouldNotReadKeyId

let read (input : Stream) : byte[] =
    let keyId = Array.zeroCreate 8
    let read = input.Read(keyId, 0, 8)
    match read with
        | 8 -> keyId
        | _ -> raise CouldNotReadKeyId

let initial = Array.zeroCreate<byte> 8