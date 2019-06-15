namespace Constants.SymmetricKeyAlgorithms

open System.IO

exception internal UnknownKeyLengthException

exception internal UnknownBlockSizeException

type internal SymmetricKeyAlgorithmType = 
    | UnknownSymmetricKeyAlgorithm
    | Plaintext
    | Idea
    | TripleDes
    | Cast5
    | Blowfish
    | Reserved5
    | Reserved6
    | Aes128
    | Aes192
    | Aes256
    | Twofish
    | PrivateOrExperimentalSymmetricKeyAlgorithm 
with
    static member Read (input : Stream) : SymmetricKeyAlgorithmType =
        match input.ReadByte () with
        | 0 -> Plaintext
        | 1 -> Idea
        | 2 -> TripleDes
        | 3 -> Cast5
        | 4 -> Blowfish
        | 5 -> Reserved5
        | 6 -> Reserved6
        | 7 -> Aes128
        | 8 -> Aes192
        | 9 -> Aes256
        | 10 -> Twofish
        | id when id >= 100 && id <= 110 -> PrivateOrExperimentalSymmetricKeyAlgorithm
        | _ -> UnknownSymmetricKeyAlgorithm
    static member KeyLength (algorithm : SymmetricKeyAlgorithmType) : int =
        match algorithm with
        | Aes128 -> 128
        | _ -> raise UnknownKeyLengthException
    static member BlockSize (algorithm : SymmetricKeyAlgorithmType) : int =
        match algorithm with
        | Aes128 | Aes192 | Aes256 -> 16
        | Blowfish | Twofish | TripleDes -> 8
        | _ -> raise UnknownBlockSizeException
            
