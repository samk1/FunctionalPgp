module KeyMaterial.PublicKey

open System
open Constants.PublicKeyAlgorithms
open Common.MPInteger
open Common.PgpDateTime
open System.IO



exception NotImplementedPublicKeyAlgorithm

type RsaParameters = { n : MPInteger; e : MPInteger } with
    static member read (input : Stream) : RsaParameters =
        { 
            n = MPInteger.read input; 
            e = MPInteger.read input 
        }

type DsaParameters = { p : MPInteger; q : MPInteger; g : MPInteger; y : MPInteger} with
    static member read (input : Stream) : DsaParameters =
        { 
            p = MPInteger.read input; 
            q = MPInteger.read input;
            g = MPInteger.read input;
            y = MPInteger.read input;
        }

type ElgamalParameters = { p : MPInteger; e : MPInteger } with
    static member read (input : Stream) : ElgamalParameters =
        {
            p = MPInteger.read input;
            e = MPInteger.read input;
        }

type PublicKeyParameters = Rsa of RsaParameters
                            | Dsa of DsaParameters
                            | Initial
                
type PublicKey = {
    VersionNumber : int
    CreationTime : PgpDateTime
    PublicKeyAlgorithm : PublicKeyAlgorithm
    KeyParameters : PublicKeyParameters
} with
    static member read (input : Stream) : PublicKey =
        let versionNumber = input.ReadByte()
        let creationTime = PgpDateTime.read input
        let publicKeyAlgorithm = Constants.PublicKeyAlgorithms.read input
        let keyParameters = match publicKeyAlgorithm with
            | RsaEncryptOrSign | RsaEncryptOnly | RsaSignOnly -> 
                Rsa(RsaParameters.read input)
            | DsaSignOnly -> 
                Dsa(DsaParameters.read input)
            | _ -> raise NotImplementedPublicKeyAlgorithm
        {
            VersionNumber = versionNumber;
            CreationTime = creationTime;
            PublicKeyAlgorithm = publicKeyAlgorithm;
            KeyParameters = keyParameters
        }
    static member initial : PublicKey =
        {
            VersionNumber = 0
            CreationTime = PgpDateTime.initial
            PublicKeyAlgorithm = UnknownPublicKeyAlgorithm
            KeyParameters = Initial
        }
