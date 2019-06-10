namespace Pgp.Constants

open System.IO

type internal PublicKeyAlgorithm = 
    | UnknownPublicKeyAlgorithm
    | RsaEncryptOrSign
    | RsaEncryptOnly
    | RsaSignOnly
    | ElgamalEncryptOnly
    | DsaSignOnly
    | ReservedEllipticCurve
    | ReservedEcdsa
    | ReservedFormerlyElgamalEncryptOrSign
    | ReservedDiffieHellman
    | PrivateOrExperimentalPublicKeyAlgorithm

module internal PublicKeyAlgorithm =
    let ofInt n : PublicKeyAlgorithm =
        match n with
        | 1 -> RsaEncryptOrSign
        | 2 -> RsaEncryptOnly
        | 3 -> RsaSignOnly
        | 16 -> ElgamalEncryptOnly
        | 17 -> DsaSignOnly
        | 18 -> ReservedEllipticCurve
        | 19 -> ReservedEcdsa
        | 20 -> ReservedFormerlyElgamalEncryptOrSign
        | 21 -> ReservedDiffieHellman
        | octet when octet >= 100 && octet <= 110 -> PrivateOrExperimentalPublicKeyAlgorithm
        | _ -> UnknownPublicKeyAlgorithm
