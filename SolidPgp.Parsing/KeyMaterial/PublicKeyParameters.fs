namespace SolidPgp.Parsing.KeyMaterial

open SolidPgp.Parsing.Common
open SolidPgp.Parsing.Constants

type internal PublicKeyParametersErrorType =
    | RsaParametersReadError of RsaPublicParametersError
    | DsaParametersReadError of DsaPublicParametersError
    | ElgamalParametersReadError of ElgamalPublicParametersError
    | UnknownAlgorithmType of PublicKeyAlgorithm

type internal PublicKeyParametersError = PublicKeyParametersError of PublicKeyParametersErrorType

type internal PublicKeyParameters =
    | Rsa of RsaPublicParameters
    | Dsa of DsaPublicParameters
    | Elgamal of ElgamalPublicParameters
    | Unknown

module internal PublicKeyParameters =
    let initial = Unknown

    let useParamParser paramType errorType reader =
        Parser.unit (initial, None)
        |> reader (fun _ parms -> paramType parms) (errorType >> PublicKeyParametersError)

    let useRsaParser =
        useParamParser Rsa RsaParametersReadError RsaPublicParameters.read

    let useDsaParser =
        useParamParser Dsa DsaParametersReadError DsaPublicParameters.read

    let useElgamalParser =
        useParamParser Elgamal ElgamalParametersReadError ElgamalPublicParameters.read    

    let useUnknownAlgorithmTypeParser alg =
        Parser.unit (initial, Some (PublicKeyParametersError (UnknownAlgorithmType alg)))

    let parser =
        let makeParser algorithm =
            match algorithm with
            | RsaEncryptOnly | RsaEncryptOrSign | RsaSignOnly -> useRsaParser
            | DsaSignOnly -> useDsaParser
            | ElgamalEncryptOnly -> useElgamalParser
            | other -> useUnknownAlgorithmTypeParser other

        let publicKeyParser state =
            (fun alg -> 
                let (result, _) = Parser.run (makeParser alg) state
                result), 
            state
        Parser publicKeyParser