namespace Pgp

open System.IO
open System.Security.Cryptography

open Constants.SymmetricKeyAlgorithms
open CypherFeedbackMode

exception internal EncryptionNotImplemented

exception internal SymmetricAlgorithmNotImplemented

module internal SymmetricEncryption = 
    let createAes (keySize : int) : SymmetricAlgorithm =
        let aes = RijndaelManaged.Create()
        aes.KeySize <- keySize
        upcast aes

    let createAlgorithm (algorithmType : SymmetricKeyAlgorithmType)  : SymmetricAlgorithm =
        match algorithmType with
        | Aes128 -> createAes 128
        | Aes192 -> createAes 192
        | Aes256 -> createAes 256
        | _ -> raise EncryptionNotImplemented

    let initAlgorithm (algorithmType : SymmetricKeyAlgorithmType) (key : byte[]) : SymmetricAlgorithm =
        let algorithm = createAlgorithm algorithmType
        algorithm.Key <- key
        algorithm.Mode <- CipherMode.ECB
        algorithm.FeedbackSize <- algorithm.BlockSize
        algorithm.Padding <- PaddingMode.None
        algorithm

    let readBlock(input: Stream) (transform: ICryptoTransform) (length: int): byte[] =
        let cypherBlock = Array.zeroCreate length
        input.Read(cypherBlock, 0, length) |> ignore
        let plainBlock = Array.zeroCreate length
        transform.TransformBlock(cypherBlock, 0, length, plainBlock, 0) |> ignore
        plainBlock

    let initCfbStream (input: Stream) (mode: CryptoStreamMode) (algorithm: SymmetricAlgorithm) : Stream =
        let transform = new OpenPgpCfbBlockCipher (algorithm, mode)
        upcast new CryptoStream(input, transform, mode)

    let decrypt (algorithmType : SymmetricKeyAlgorithmType) (key : byte[]) (input : Stream) : Stream =
        match algorithmType with
        | Plaintext -> input
        | algorithmType -> initAlgorithm algorithmType key |> initCfbStream input CryptoStreamMode.Read

    let encrypt (algorithmType: SymmetricKeyAlgorithmType) (key : byte[]) (input: Stream) : Stream =
        match algorithmType with
        | Plaintext -> input
        | algorithmType -> initAlgorithm algorithmType key |> initCfbStream input CryptoStreamMode.Write

