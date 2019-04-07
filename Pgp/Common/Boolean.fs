module Common.Boolean

open System.IO

let read (input : Stream) : bool =
    match (input.ReadByte()) with
    | 0 -> false
    | _ -> true
