namespace SolidPgp.Parsing.KeyMaterial

open SolidPgp.Parsing.Constants
open SolidPgp.Parsing.Common

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
