namespace Pgp.KeyMaterial.PublicKey

open Constants.PublicKeyAlgorithms
open Pgp.Common
open System.IO

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

type internal RsaParametersReadError =
    InvalidRsaPublicModulus of MPIntegerReadError
    | InvalidRsaPublicExponent of MPIntegerReadError

type internal DsaParametersReadError =
    | InvalidDsaPrimeP of MPIntegerReadError

module internal RsaPublicParameters =
    let initial =
        { PublicExponent = MPInteger.initial; PublicModulus = MPInteger.initial }

    let parser =
        Parser.unit (initial, None)
        |> MPInteger.read (fun rsa mpi -> { rsa with PublicExponent = mpi }) InvalidRsaPublicExponent
        |> MPInteger.read (fun rsa mpi -> { rsa with PublicModulus = mpi }) InvalidRsaPublicModulus

    let read withRsa withRsaError =
        Parser.fold
            (ParseResult.foldResult withRsa)
            (ParseResult.foldError withRsaError)
            parser

type internal PublicKey = 
    { 
        VersionNumber : int
        CreationTime : PgpDateTime
        PublicKeyAlgorithm : PublicKeyAlgorithm
        KeyParameters : RsaPublicParameters 
    } with
    static member Read (input : Stream) : PublicKey =
        let versionNumber = input.ReadByte()
        let creationTime = PgpDateTime.initial
        let publicKeyAlgorithm = PublicKeyAlgorithm.Read input
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
          KeyParameters = RsaPublicParameters.initial }
