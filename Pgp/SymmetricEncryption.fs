module SymmetricEncryption

open System.IO
open System.Security.Cryptography

open Common.MPInteger
open Constants.SymmetricKeyAlgorithms

exception EncryptionNotImplemented

exception SymmetricAlgorithmNotImplemented

let createAes (keySize : int) : SymmetricAlgorithm =
    let aes = Aes.Create()
    aes.KeySize <- keySize
    upcast aes

let initAlgorithm (algorithm : SymmetricAlgorithm) (key : byte[]) (iv : byte[]) : SymmetricAlgorithm =
    algorithm.IV <- iv
    algorithm.Key <- key
    algorithm.Mode <- CipherMode.CFB
    algorithm.FeedbackSize <- 2
    algorithm

let createAlgorithm (algorithmType : SymmetricKeyAlgorithmType)  : SymmetricAlgorithm =
    match algorithmType with
        | Aes128 -> createAes 128
        | Aes192 -> createAes 192
        | Aes256 -> createAes 256
        | _ -> raise EncryptionNotImplemented

let decrypt (algorithmType : SymmetricKeyAlgorithmType) (key : byte[]) (iv : byte[]) (input : Stream) : Stream =
    match algorithmType with
        | Plaintext -> input
        | algorithmType -> upcast new CryptoStream (
                                            input, 
                                            (initAlgorithm (createAlgorithm algorithmType) key iv).CreateDecryptor(), 
                                            CryptoStreamMode.Read)