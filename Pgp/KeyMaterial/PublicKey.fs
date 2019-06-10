namespace Pgp.KeyMaterial.PublicKey

open Constants.PublicKeyAlgorithms
open Pgp.Common
open System.IO
open System.Security.Cryptography.X509Certificates

exception NotImplementedPublicKeyAlgorithmException of string

module internal Errors = 
    let internal errorPos (input: Stream) (msg: string): string =
        sprintf "position: %A %s" input.Position msg

    let  unimplementedPublicKeyAlgorithm (input: Stream) (tag: PublicKeyAlgorithm) =
        let message = (errorPos input (sprintf "Unsupported public key algorithm: %A" tag))
        printfn "%s" message
        raise (NotImplementedPublicKeyAlgorithmException message)

type internal RsaPublicParameters = { PublicExponent: MPInteger; PublicModulus: MPInteger }

type internal DsaParameters = 
    { 
        p : MPInteger 
        q : MPInteger 
        g : MPInteger 
        y : MPInteger
    } with
    static member Initial =
        { p = MPInteger.initial
          q = MPInteger.initial
          g = MPInteger.initial
          y = MPInteger.initial }

type internal ElgamalParameters = 
    { 
        p : MPInteger
        e : MPInteger 
    } with
    static member Read (input : Stream) : ElgamalParameters =
        { p = MPInteger.initial
          e = MPInteger.initial }

type internal RsaParametersError =
    InvalidRsaPublicModulus of MPIntegerError
    | InvalidRsaPublicExponent of MPIntegerError

type internal DsaParametersReadError =
    | InvalidDsaPrimeP of MPIntegerError

module internal RsaPublicParameters =
    let initial =
        { PublicExponent = MPInteger.initial; PublicModulus = MPInteger.initial }

    let parser =
        Parser.unit (initial, None)
        |> MPInteger.read (fun rsa mpi -> { rsa with PublicExponent = mpi }) InvalidRsaPublicExponent
        |> MPInteger.read (fun rsa mpi -> { rsa with PublicModulus = mpi }) InvalidRsaPublicModulus

    let read withRsa withRsaError =
        Parser.foldpr withRsa withRsaError parser

type internal PublicKeyParametersErrorType =
    RsaParametersReadError of RsaParametersError

type internal PublicKeyParametersError = PublicKeyParametersError of PublicKeyParametersErrorType

type internal PublicKeyParameters =
    Rsa of RsaPublicParameters
    | Unknown

module internal PublicKeyParameters =
    let initial = Unknown

    let useRsaParser =
        Parser.unit (initial, None)
        |> RsaPublicParameters.read
            (fun _ rsa -> Rsa rsa)
            (RsaParametersReadError >> PublicKeyParametersError)

    let parser =
        let makeParser algorithm =
            match algorithm with
            | RsaEncryptOnly | RsaEncryptOrSign | RsaSignOnly -> useRsaParser

        let publicKeyParser state =
            (fun alg -> 
                let (result, _) = Parser.run (makeParser alg) state
                result), 
            state
        Parser publicKeyParser

type internal PublicKey = 
    { 
        VersionNumber : int
        CreationTime : PgpDateTime
        PublicKeyAlgorithm : PublicKeyAlgorithm
        KeyParameters : PublicKeyParameters 
    } with
    static member Read (input : Stream) : PublicKey =
        let versionNumber = input.ReadByte()
        let creationTime = PgpDateTime.initial
        let publicKeyAlgorithm = PublicKeyAlgorithm.UnknownPublicKeyAlgorithm
        let keyParameters = 
            match publicKeyAlgorithm with
            | _ -> Errors.unimplementedPublicKeyAlgorithm input publicKeyAlgorithm
        { VersionNumber = versionNumber
          CreationTime = creationTime
          PublicKeyAlgorithm = publicKeyAlgorithm
          KeyParameters = keyParameters }
    static member Initial : PublicKey =
        { VersionNumber = 0
          CreationTime = PgpDateTime.initial
          PublicKeyAlgorithm = UnknownPublicKeyAlgorithm
          KeyParameters = Unknown }

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
