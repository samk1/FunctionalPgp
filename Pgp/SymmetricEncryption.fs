namespace Pgp

open System.IO
open System.Security.Cryptography

open Constants.SymmetricKeyAlgorithms

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

    let initAlgorithm (algorithmType : SymmetricKeyAlgorithmType) (key : byte[]) (iv : byte[]) : SymmetricAlgorithm =
        let algorithm = createAlgorithm algorithmType
        algorithm.IV <- iv
        algorithm.Key <- key
        algorithm.Mode <- CipherMode.CFB
        algorithm.FeedbackSize <- algorithm.BlockSize
        algorithm.Padding <- PaddingMode.None
        algorithm

    let readBlock(input: Stream) (transform: ICryptoTransform) (length: int): byte[] =
        let cypherBlock = Array.zeroCreate length
        input.Read(cypherBlock, 0, length) |> ignore
        let plainBlock = Array.zeroCreate length
        transform.TransformBlock(cypherBlock, 0, length, plainBlock, 0) |> ignore
        plainBlock

    let initCfbStream (algorithm: SymmetricAlgorithm) (input: Stream) : Stream =
        let transform = algorithm.CreateDecryptor()

        let blockSize = transform.InputBlockSize
        let feedBackSize = algorithm.FeedbackSize / 8

        let firstPlainBlock = readBlock input transform blockSize

        let secondPlainBlock = readBlock input transform blockSize

        let thirdPlainBlock = readBlock input transform blockSize
    
        let fourthPlainBlock = readBlock input transform blockSize

        upcast new CryptoStream(input, transform, CryptoStreamMode.Read)


    let decrypt (algorithmType : SymmetricKeyAlgorithmType) (key : byte[]) (iv : byte[]) (input : Stream) : Stream =
        match algorithmType with
        | Plaintext -> input
        | algorithmType -> 
            let algorithm = initAlgorithm algorithmType key iv
            initCfbStream algorithm input