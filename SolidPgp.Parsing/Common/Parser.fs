namespace SolidPgp.Parsing.Common

open System.IO
open System.Threading

type internal Parser<'T> = 
    Parser of (ParseState -> 'T * ParseState)

module internal Parser =
    let run (Parser parse) parseState =
        parse parseState

    let map f parser =
        let duringParse parseState =
            let src, parseState = run parser parseState
            let dest = f src
            dest, parseState
        Parser duringParse

    let unit (x, e) =
        let unitParser parseState =
            match e with
            | Some e -> ParseResult.failure (x, e), parseState
            | None -> ParseResult.success x, parseState
        Parser unitParser

    let unitf (f: 'a -> 'b) =
        let unitfParser parseState =
            (f, parseState)
        Parser unitfParser

    let bind f parsera =
        let bindParser parseState =
            let resulta, parseState = run parsera parseState
            let parserb = f resulta
            let resultb, parseState = run parserb parseState
            resultb, parseState
        Parser bindParser

    let bindpr fpr parsera =
        let binder pr =
            match pr with
            | ParseResult (resulta, _) -> fpr resulta
        bind binder parsera

    let apply parserF parserX =
        let applyParser parseState =
            let f, parseState = run parserF parseState
            let x, parseState = run parserX parseState
            let y = f x
            y, parseState
        Parser applyParser

    let foldpr fresult ferror parserb parsera =
        let folder state =
            let (resulta, state) = run parsera state
            let resultf = ParseResult.fold fresult ferror resulta
            (resultf, state)
        let parserf = Parser folder
        apply parserf parserb

    let makeReader withResult withError parser =
        foldpr withResult withError parser

    let validate validatorf error parser =
        let validator result =
            if (validatorf result) then (result, None)
            else (result, Some error)
        map (ParseResult.mapResult validator) parser

    let tap f parser =
        let tapParser = unitf (fun r -> f r; r)
        apply tapParser parser

    let dump parser =
        tap (fun result -> printfn("tap: %A") result) parser