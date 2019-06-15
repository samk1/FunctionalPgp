namespace SolidPgp.Parsing.Common

type ParseResult<'result, 'error> = ParseResult of ('result * 'error option)

module ParseResult =
    let unit (x, e) =
        match e with
        | Some err -> ParseResult (x, Some err)
        | None -> ParseResult (x, None)

    let failure (x, e) =
        ParseResult (x, Some e)

    let success x =
        ParseResult (x, None)

    let bindResult f pr =
        match pr with
        | ParseResult (result, None) -> f result
        | ParseResult (_, Some _) -> pr

    let bind fresult ferror pr =
        match pr with
        | ParseResult (result, None) -> fresult result
        | ParseResult (result, Some error) -> ferror (result, error)  

    let map fresult ferror pr =
        match pr with
        | ParseResult (result, None) -> ParseResult(fresult result, None)
        | ParseResult (result, Some error) -> ParseResult(fresult result, Some (ferror error))

    let map2 onSuccess onError (ParseResult (result, errorOption)) =
        match errorOption with
        | None -> success (onSuccess result)
        | Some error -> failure (onError error)

    let mapResult f (ParseResult (result, error)) =
        match error with
        | None -> ParseResult (f result)
        | Some err -> failure (result, err)


    let fold fresult ferror (ParseResult (resulta, errora)) (ParseResult (resultb, errorb)) =
        match errora, errorb with
        | None, None -> success (fresult resulta resultb)
        | _, Some errb -> failure (resulta, ferror errb)
        | Some erra, _ -> failure (resulta, erra)

    let mapf fresult ferror f =
        let foldResultA parseResultA =
            let (ParseResult (resultA, errorAOption)) = parseResultA
            match errorAOption with
            | None ->
                let (ParseResult (resultB, errorBOption)) = f parseResultA
                match errorBOption with
                | None -> success (fresult resultA resultB)
                | Some errorB -> failure (resultA, ferror errorB)
            | Some errorA -> failure (resultA, errorA)
        foldResultA

    let bindf f =
        let bindA (ParseResult (resultA, _)) =
            f resultA
        bindA


    let apply fpr xpr =
            let (ParseResult (f, _)) = fpr
            let (ParseResult (x, error)) = xpr
            ParseResult (f x, error)

    let foldResult f pr resulta =
        map (fun resultb -> f resultb resulta) id pr

    let foldError f pr (resulta, errora) =
        map id (fun errorb -> (f errorb (resulta, errora))) pr