namespace Pgp.Tests

open Fuchu
open System.IO
open Pgp.KeyMaterial.PublicKey
open Pgp.Common

module RsaPublicKeyParametersTests =
    let rsaParametersStream ()
        = new MemoryStream(TestData.RsaPublicParameters)

    let tests = testList "RSA public key parameters tests" [
        testCase "Read RSA public key parameters" <| fun _ ->
            let state = ParseState.initStream (rsaParametersStream ())
            match state with
            | Some state -> 
                let (result, _) = Parser.run RsaPublicParameters.parser state
                printf "%A" result
            | None -> printf "read failed"            
    ]    