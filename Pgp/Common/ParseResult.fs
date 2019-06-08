namespace Pgp.Common

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

    let apply fpr xpr =
            let (ParseResult (f, _)) = fpr
            let (ParseResult (x, error)) = xpr
            ParseResult (f x, error)

    let foldResult f pr resulta =
        map (fun resultb -> f resultb resulta) id pr

    let foldError f pr (resulta, errora) =
        map id (fun errorb -> (f errorb (resulta, errora))) pr

    let fold fresult ferror pr (ParseResult (resulta, erroraoption)) =
        match erroraoption with
        | Some errora -> foldError ferror pr (resulta, errora)
        | None -> foldResult fresult pr resulta