namespace KeyMaterial.PublicKey

open Constants.PublicKeyAlgorithms
open Common.MPInteger
open Common.PgpDateTime
open System.IO

exception NotImplementedPublicKeyAlgorithm

type internal RsaParameters = 
    { 
        n : MPInteger
        e : MPInteger 
    } with
    static member Read (input : Stream) : RsaParameters =
        { n = MPInteger.Read input
          e = MPInteger.Read input }

type internal DsaParameters = 
    { 
        p : MPInteger 
        q : MPInteger 
        g : MPInteger 
        y : MPInteger
    } with
    static member Read (input : Stream) : DsaParameters =
        { p = MPInteger.Read input
          q = MPInteger.Read input
          g = MPInteger.Read input
          y = MPInteger.Read input }

type internal ElgamalParameters = 
    { 
        p : MPInteger
        e : MPInteger 
    } with
    static member Read (input : Stream) : ElgamalParameters =
        { p = MPInteger.Read input
          e = MPInteger.Read input }

type internal PublicKeyParameters = 
    | Rsa of RsaParameters
    | Dsa of DsaParameters
    | Initial
                
type internal PublicKey = 
    { 
        VersionNumber : int
        CreationTime : PgpDateTime
        PublicKeyAlgorithm : PublicKeyAlgorithm
        KeyParameters : PublicKeyParameters 
    } with
    static member Read (input : Stream) : PublicKey =
        let versionNumber = input.ReadByte()
        let creationTime = PgpDateTime.Read input
        let publicKeyAlgorithm = PublicKeyAlgorithm.Read input
        let keyParameters = 
            match publicKeyAlgorithm with
            | RsaEncryptOrSign | RsaEncryptOnly | RsaSignOnly -> Rsa(RsaParameters.Read input)
            | DsaSignOnly -> Dsa(DsaParameters.Read input)
            | _ -> raise NotImplementedPublicKeyAlgorithm
        { VersionNumber = versionNumber
          CreationTime = creationTime
          PublicKeyAlgorithm = publicKeyAlgorithm
          KeyParameters = keyParameters }
    static member Initial : PublicKey =
        { VersionNumber = 0
          CreationTime = PgpDateTime.Initial
          PublicKeyAlgorithm = UnknownPublicKeyAlgorithm
          KeyParameters = Initial }
