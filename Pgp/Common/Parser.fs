namespace Pgp.Common

open System.IO

type internal Parser<'T> = 
    Parser of (ParseState -> 'T * ParseState)

module internal Parser =
    let run (Parser parse) parseState =
        parse parseState

    let map f (Parser parse) =
        let duringParse parseState =
            let src, parseState = parse parseState
            let dest = f src
            dest, parseState
        Parser duringParse

    let unit (x, e) =
        let unitParser parseState =
            match e with
            | Some e -> ParseResult.failure (x, e), parseState
            | None -> ParseResult.success x, parseState
        Parser unitParser        

    let bind f parser =
        let bindParser parseState =
            let src, parseState = run parser parseState
            let destParser = f src
            let dest, parseState = run destParser parseState
            dest, parseState
        Parser bindParser

    let apply parserF parserX =
        let applyParser parseState =
            let f, parseState = run parserF parseState
            let x, parseState = run parserX parseState
            let y = f x
            y, parseState
        Parser applyParser

    let fold fresult ferror parser =
        let folder state =
            map
                (ParseResult.bind (fresult state) (ferror state))
                parser
        bind folder

    let makeReader parser withResult withError =
        fold
            (ParseResult.foldResult withResult)
            (ParseResult.foldError withError)
            parser