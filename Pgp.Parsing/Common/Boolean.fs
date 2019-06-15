namespace Common.Boolean

open System.IO

module internal Boolean =
    let read (input : Stream) : bool =
        match (input.ReadByte()) with
        | 0 -> false
        | _ -> true
