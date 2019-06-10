namespace Pgp.KeyMaterial.SecretKey

open Constants.SymmetricKeyAlgorithms
open Constants.PublicKeyAlgorithms
open Pgp.Common
open Common.StringToKeySpecifiers
open Pgp.KeyMaterial.PublicKey
open KeyMaterial.StringToKey
open System.IO

exception internal UnableToReadKeyParametersException

exception internal UnknownStringToKeyUsageConventionException

type internal RsaSecretParameters = 
    {
        d : MPInteger
        p : MPInteger
        q : MPInteger
        u : MPInteger
    } with
    static member Read (input : Stream) : RsaSecretParameters = 
        { d = MPInteger.initial
          p = MPInteger.initial
          q = MPInteger.initial
          u = MPInteger.initial }

type internal DsaSecretParameters = 
    {
        x : MPInteger
    } with
    static member Read (input : Stream) : DsaSecretParameters = 
        { x = MPInteger.initial}

type internal ElgamalSecretParameters = 
    {
        x : MPInteger
    } with
    static member Read (input : Stream) : ElgamalSecretParameters = 
        { x = MPInteger.initial}

type internal SecretKeyParameters = 
    | Rsa of RsaSecretParameters
    | Dsa of DsaSecretParameters
    | Elgamal of ElgamalSecretParameters
    with 
    static member read (algorithmType : PublicKeyAlgorithm) (input : Stream) =
        match algorithmType with
        | DsaSignOnly -> Dsa(DsaSecretParameters.Read input)
        | RsaEncryptOnly | RsaSignOnly | RsaEncryptOrSign -> Rsa(RsaSecretParameters.Read input)
        | ElgamalEncryptOnly -> Elgamal(ElgamalSecretParameters.Read input)
        | _ -> raise UnableToReadKeyParametersException
    
module internal SecretKeyElementReaders =
    let readTwoOctetChecksum (input : Stream) : byte[] =
        let checksum = Array.zeroCreate 2
        input.Read(checksum, 0, 2) |> ignore
        checksum

    let readSha1Hash (input : Stream) : byte[] =
        let hash = Array.zeroCreate 20
        input.Read(hash, 0, 20) |> ignore
        hash

    let readIv (algorithmType : SymmetricKeyAlgorithmType) (input : Stream) : byte[] =
        let blockSize = SymmetricKeyAlgorithmType.BlockSize algorithmType
        let iv = Array.zeroCreate blockSize
        input.Read(iv, 0, blockSize) |> ignore
        iv

type internal UnknownStringToKeyUsageConventionInfo =
    {
        Position: int64
        StringToKeyUsageConvention: int        
    }

type internal SecretKeyReadError =
    UnknownStringToKeyUsageConvention of UnknownStringToKeyUsageConventionInfo

type internal SecretKey = 
    {
        PublicKey : PublicKey
        StringToKeyUsageConvention : int
        StringToKeySymmetricKeyAlgorithm : SymmetricKeyAlgorithmType
        StringToKeySpecifier : Option<StringToKeySpecifier>
        StringToKeyIV : Option<byte[]>
        SecretKeyData : Option<SecretKeyParameters>
        ChecksumData : byte[]
    }

type internal SecretKeyReadResult =
    Success of SecretKey
    | Failure of SecretKeyReadError

module internal SecretKeyReadErrors =
    let unknownStringToKeyUsageConvention (stream: Stream) stringToKeyUsageConvention =
        Failure (UnknownStringToKeyUsageConvention {
            Position = stream.Position
            StringToKeyUsageConvention = stringToKeyUsageConvention
        })

module internal SecretKeyFactory =
    let fromStream (input : Stream) passPhrase decrypt =
        let publicKey = PublicKey.initial
        let stringToKeyUsageConvention = input.ReadByte()
        match stringToKeyUsageConvention with
        | 0 -> 
            Success {
                PublicKey = publicKey
                StringToKeyUsageConvention = stringToKeyUsageConvention
                StringToKeySymmetricKeyAlgorithm = Plaintext
                StringToKeySpecifier = None
                StringToKeyIV = None
                SecretKeyData = Some(SecretKeyParameters.read publicKey.PublicKeyAlgorithm input)
                ChecksumData = (SecretKeyElementReaders.readTwoOctetChecksum input) 
            }
        | 254 ->
            let symmetricKeyAlgorithm = SymmetricKeyAlgorithmType.Read input
            let stringToKeySpecifier = StringToKeySpecifier.read input
            let key = StringToKeyAlgorithms.computeStringToKey passPhrase stringToKeySpecifier symmetricKeyAlgorithm
            let iv = SecretKeyElementReaders.readIv symmetricKeyAlgorithm input
            let decryptedInput = decrypt symmetricKeyAlgorithm key input
            let keyParameters = SecretKeyParameters.read publicKey.PublicKeyAlgorithm decryptedInput
            Success { 
                PublicKey = publicKey
                StringToKeyUsageConvention = stringToKeyUsageConvention
                StringToKeySymmetricKeyAlgorithm = symmetricKeyAlgorithm
                StringToKeySpecifier = Some(stringToKeySpecifier)
                StringToKeyIV = Some(iv)
                SecretKeyData = Some(keyParameters)
                ChecksumData = (SecretKeyElementReaders.readSha1Hash input) 
            }
        | 255 ->
            let symmetricKeyAlgorithm = SymmetricKeyAlgorithmType.Read input
            let stringToKeySpecifier = StringToKeySpecifier.read input
            let key = StringToKeyAlgorithms.computeStringToKey passPhrase stringToKeySpecifier symmetricKeyAlgorithm
            let iv = SecretKeyElementReaders.readIv symmetricKeyAlgorithm input
            let decryptedInput = decrypt symmetricKeyAlgorithm key input
            let keyParameters = SecretKeyParameters.read publicKey.PublicKeyAlgorithm decryptedInput
            Success { 
                PublicKey = publicKey
                StringToKeyUsageConvention = stringToKeyUsageConvention
                StringToKeySymmetricKeyAlgorithm = symmetricKeyAlgorithm
                StringToKeySpecifier = Some(stringToKeySpecifier)
                StringToKeyIV = Some(iv)
                SecretKeyData = Some(keyParameters)
                ChecksumData = (SecretKeyElementReaders.readTwoOctetChecksum input) 
            }       
        | _ -> SecretKeyReadErrors.unknownStringToKeyUsageConvention input stringToKeyUsageConvention
    let initial () =
        { PublicKey = PublicKey.initial
          StringToKeyUsageConvention = 0
          StringToKeySymmetricKeyAlgorithm = UnknownSymmetricKeyAlgorithm
          StringToKeySpecifier = None
          StringToKeyIV = None
          SecretKeyData = None
          ChecksumData = Array.empty }