namespace SolidPgp.Parsing.Tests

open Fuchu
open System.IO
open SolidPgp.Parsing.Common
open SolidPgp.Parsing.KeyMaterial

module RsaPublicKeyParametersTests =
    let rsaParametersStream ()
        = new MemoryStream(TestData.RsaPublicParameters)

    let tests = testList "RSA public key parameters tests" [
        testCase "Read RSA public key parameters" <| fun _ ->
            let state = ParseState.initStream (rsaParametersStream ())
            match state with
            | Some state -> 
                let (result, _) = Parser.run RsaPublicParameters.parser state
                printfn "%A" result
            | None -> printf "read failed"
    ]    