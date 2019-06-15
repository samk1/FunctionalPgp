namespace Pgp.Parsing.Common

open System.IO

type internal ReadError =
    StreamIsNull
    | StreamIsNotReadable
    | PrematureEndOfStream

type internal ParseState = { BinaryReader: BinaryReader; Stream: Stream }

module internal ParseState =
    let init =
        { BinaryReader = null; Stream = null }

    let ensureStream (stream: Stream) =
        match Option.ofObj stream with
        | Some stream -> 
            if stream.CanRead then
                None
            else
                Some StreamIsNotReadable
        | None -> Some StreamIsNull        

    let initStream (stream: Stream) =
        let state = init
        match ensureStream stream with
        | Some _ -> None
        | None -> Some { state with BinaryReader = new BinaryReader (stream); Stream = stream }
