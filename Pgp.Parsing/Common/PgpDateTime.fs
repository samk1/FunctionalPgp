namespace Pgp.Parsing.Common

open System.IO

type internal PgpDateTimeError = PgpDateTimeReadError of BinaryReadError

type internal PgpDateTime = PgpDateTime of int64

module internal PgpDateTime =
    let initial = PgpDateTime 0L

    let parser =
        Parser.unit (initial, None)
        |> BinaryParsers.uint32Reader
            (fun _ n -> PgpDateTime n)
            PgpDateTimeReadError

    let reader withPgpDateTime withError =
        Parser.foldpr withPgpDateTime withError parser