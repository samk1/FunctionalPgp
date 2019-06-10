namespace Pgp.KeyMaterial.PublicKey

open Constants.PublicKeyAlgorithms
open Pgp.Common

type internal RsaPublicParameters = { ExponentE: MPInteger; ModulusN: MPInteger }

type internal RsaPublicParametersError =
    | RsaModulusNReadError of MPIntegerError
    | RsExponentEReadError of MPIntegerError

module internal RsaPublicParameters =
    let initial =
        { ExponentE = MPInteger.initial; ModulusN = MPInteger.initial }

    let parser =
        Parser.unit (initial, None)
        |> MPInteger.read (fun rsa mpi -> { rsa with ModulusN = mpi }) RsaModulusNReadError
        |> MPInteger.read (fun rsa mpi -> { rsa with ExponentE = mpi }) RsExponentEReadError

    let read withRsa withRsaError =
        Parser.foldpr withRsa withRsaError parser

type internal DsaPublicParameters = 
    { PrimeP : MPInteger 
      GroupOrderQ : MPInteger 
      GroupGeneratorG : MPInteger 
      PublicKeyY : MPInteger }

type internal DsaPublicParametersError =
    | DsaPrimePReadError of MPIntegerError
    | DsaGroupOrderQReadError of MPIntegerError
    | DsaGroupGeneratorGReadError of MPIntegerError
    | DsaPublicKeyYReadError of MPIntegerError

module internal DsaPublicParameters =
    let initial =
        { PrimeP = MPInteger.initial
          GroupOrderQ = MPInteger.initial
          GroupGeneratorG = MPInteger.initial
          PublicKeyY = MPInteger.initial }

    let parser =
        Parser.unit (initial, None)
        |> MPInteger.read (fun dsa mpi -> { dsa with PrimeP = mpi }) DsaPrimePReadError
        |> MPInteger.read (fun dsa mpi -> { dsa with GroupOrderQ = mpi }) DsaGroupOrderQReadError
        |> MPInteger.read (fun dsa mpi -> { dsa with GroupGeneratorG = mpi }) DsaGroupGeneratorGReadError
        |> MPInteger.read (fun dsa mpi -> { dsa with PublicKeyY = mpi }) DsaPublicKeyYReadError

    let read withDsa withDsaError =
        Parser.foldpr withDsa withDsaError parser

type internal ElgamalPublicParameters = { PrimeP : MPInteger; GroupGeneratorG : MPInteger }

type internal ElgamalPublicParametersError =
    | ElgamalPrimePReadError of MPIntegerError
    | ElgamalGroupGeneratorGReadError of MPIntegerError

module internal ElgamalPublicParameters = 
    let initial =
        { PrimeP = MPInteger.initial; GroupGeneratorG = MPInteger.initial }

    let parser =
        Parser.unit (initial, None)
        |> MPInteger.read (fun elgamal mpi -> { elgamal with PrimeP = mpi }) ElgamalPrimePReadError
        |> MPInteger.read (fun elgamal mpi -> { elgamal with GroupGeneratorG = mpi }) ElgamalGroupGeneratorGReadError

    let read withElgamal withElgamalError =
        Parser.foldpr withElgamal withElgamalError parser

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

type internal PublicKey = 
    { VersionNumber : int
      CreationTime : PgpDateTime
      PublicKeyAlgorithm : PublicKeyAlgorithm
      KeyParameters : PublicKeyParameters }

type internal PublicKeyErrorType =
    | PublicKeyVersionReadError of BinaryReadError
    | PublicKeyCreationTimeReadError of PgpDateTimeError
    | PublicKeyAlgorithmReadError of BinaryReadError
    | PublicKeyParametersReadError of PublicKeyParametersError

type internal PublicKeyError = PublicKeyError of PublicKeyErrorType

module internal PublicKey =
    let initial =
        { VersionNumber = 0
          CreationTime = PgpDateTime.initial
          PublicKeyAlgorithm = UnknownPublicKeyAlgorithm
          KeyParameters = Unknown }

    let parametersParser pkeyParser =
        Parser.apply 
            (Parser.map
                (fun f -> 
                    ParseResult.mapf
                        (fun pkey keyParams -> { pkey with KeyParameters = keyParams })
                        (PublicKeyParametersReadError >> PublicKeyError)
                        (ParseResult.bindf ((fun pkey -> pkey.PublicKeyAlgorithm) >> f)))
                PublicKeyParameters.parser)
            pkeyParser            

    let parser =
        Parser.unit (initial, None)
        |> BinaryParsers.uint8Reader 
            (fun pkey n -> { pkey with VersionNumber = n })
            (PublicKeyVersionReadError >> PublicKeyError)
        |> PgpDateTime.reader
            (fun pkey datetime -> { pkey with CreationTime = datetime })
            (PublicKeyCreationTimeReadError >> PublicKeyError)
        |> BinaryParsers.uint8Reader
            (fun pkey n -> { pkey with PublicKeyAlgorithm = PublicKeyAlgorithm.ofInt n })        
            (PublicKeyAlgorithmReadError >> PublicKeyError)
        |> parametersParser        
