module KeyMaterial.SecretKey

open PublicKey
open Constants.SymmetricKeyAlgorithms
open Constants.PublicKeyAlgorithms
open Common.StringToKeySpecifiers
open StringToKey
open Common.MPInteger
open System.IO
open System

type RsaSecretParameters = {
    d : MPInteger
    p : MPInteger
    q : MPInteger
    u : MPInteger
} with
    static member read (input : Stream) : RsaSecretParameters = {
        d = MPInteger.read input;
        p = MPInteger.read input;
        q = MPInteger.read input;
        u = MPInteger.read input}

type DsaSecretParameters = {
    x : MPInteger
} with
    static member read (input : Stream) : DsaSecretParameters = {
        x = MPInteger.read input}

type ElgamalSecretParameters = {
    x : MPInteger
} with
    static member read (input : Stream) : ElgamalSecretParameters = {
        x = MPInteger.read input}

exception UnableToReadKeyParameters

type SecretKeyParameters = Rsa of RsaSecretParameters
                            | Dsa of DsaSecretParameters
                            | Elgamal of ElgamalSecretParameters
 with 
     static member read (algorithmType : PublicKeyAlgorithm) (input : Stream) =
        match algorithmType with
            | DsaSignOnly -> Dsa(DsaSecretParameters.read input)
            | RsaEncryptOnly | RsaSignOnly | RsaEncryptOrSign -> Rsa(RsaSecretParameters.read input)
            | ElgamalEncryptOnly -> Elgamal(ElgamalSecretParameters.read input)
            | _ -> raise UnableToReadKeyParameters
    
let readTwoOctetChecksum (input : Stream) : byte[] =
    let checksum = Array.zeroCreate 2
    input.Read(checksum, 0, 2) |> ignore
    checksum

let readSha1Hash (input : Stream) : byte[] =
    let hash = Array.zeroCreate 20
    input.Read(hash, 0, 20) |> ignore
    hash

let readIv (algorithmType : SymmetricKeyAlgorithmType) (input : Stream) : byte[] =
    let blockSize = SymmetricKeyAlgorithmType.blockSize algorithmType
    let iv = Array.zeroCreate blockSize
    input.Read(iv, 0, blockSize) |> ignore
    iv

exception UnknownStringToKeyUsageConvention

type SecretKey = {
    PublicKey : PublicKey
    StringToKeyUsageConvention : int
    StringToKeySymmetricKeyAlgorithm : SymmetricKeyAlgorithmType
    StringToKeySpecifier : Option<StringToKeySpecifier>
    StringToKeyIV : Option<byte[]>
    SecretKeyData : Option<SecretKeyParameters>
    ChecksumData : byte[]
} with
    static member read 
        (input : Stream) 
        (passPhrase : string) 
        (decrypt : SymmetricKeyAlgorithmType -> byte[] -> byte[] -> Stream -> Stream) : SecretKey =
        let publicKey = PublicKey.read input
        let stringToKeyUsageConvention = input.ReadByte()
        match stringToKeyUsageConvention with
            | 0 -> 
                {
                    PublicKey = publicKey
                    StringToKeyUsageConvention = stringToKeyUsageConvention
                    StringToKeySymmetricKeyAlgorithm = Plaintext
                    StringToKeySpecifier = None
                    StringToKeyIV = None
                    SecretKeyData = Some(SecretKeyParameters.read publicKey.PublicKeyAlgorithm input)
                    ChecksumData = (readTwoOctetChecksum input) 
                }
            | 254 ->
                let symmetricKeyAlgorithm = SymmetricKeyAlgorithmType.read input
                let stringToKeySpecifier = StringToKeySpecifier.read input
                let key = stringToKey passPhrase stringToKeySpecifier symmetricKeyAlgorithm
                let iv = readIv symmetricKeyAlgorithm input
                let decryptedInput = decrypt symmetricKeyAlgorithm key iv input
                let keyParameters = SecretKeyParameters.read publicKey.PublicKeyAlgorithm decryptedInput
                {
                    PublicKey = publicKey
                    StringToKeyUsageConvention = stringToKeyUsageConvention
                    StringToKeySymmetricKeyAlgorithm = symmetricKeyAlgorithm
                    StringToKeySpecifier = Some(stringToKeySpecifier)
                    StringToKeyIV = Some(iv)
                    SecretKeyData = Some(keyParameters)
                    ChecksumData = (readSha1Hash input)
                }
            | _ -> raise UnknownStringToKeyUsageConvention
    static member initial : SecretKey = 
        {
            PublicKey = PublicKey.initial
            StringToKeyUsageConvention = 0
            StringToKeySymmetricKeyAlgorithm = UnknownSymmetricKeyAlgorithm
            StringToKeySpecifier = None
            StringToKeyIV = None
            SecretKeyData = None
            ChecksumData = Array.empty
        }


