namespace Common.PgpDateTime

open System.IO

type internal PgpDateTime = 
    { 
        Epoch : uint32 
    } with
    static member Read (input : Stream) : PgpDateTime =
        let reader = new BinaryReader (input)
        { Epoch = reader.ReadUInt32 () }

    static member Initial : PgpDateTime =
        { Epoch = uint32 0 }
