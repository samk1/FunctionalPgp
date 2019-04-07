module Common.PgpDateTime

open System.IO

type PgpDateTime = {
    Epoch : uint32
}   with
    static member read (input : Stream) : PgpDateTime =
        let reader = new BinaryReader (input)
        {
            Epoch = reader.ReadUInt32 ()
        }
    static member initial : PgpDateTime =
        {
            Epoch = uint32 0
        }
