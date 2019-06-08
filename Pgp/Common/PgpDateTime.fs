namespace Pgp.Common

open System.IO

type internal PgpDateTimeError = PgpDateTimeReadError of BinaryReadError

type internal PgpDateTime = PgpDateTime of int64

module internal PgpDateTime =
    let initial = PgpDateTime 0L

    let parser =
        Parser.unit (initial, None)
        |> Binary.uint32Read
            (fun _ n -> PgpDateTime n)
            (fun _ (_, err) -> PgpDateTimeReadError err)