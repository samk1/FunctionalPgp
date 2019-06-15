namespace Common.StringToKeySpecifiers

open Constants
open Constants.HashAlgorithms
open System.IO

type internal SimpleStringToKey = { HashAlgorithm : HashAlgorithmType }

type internal SaltedStringToKey = 
    { HashAlgorithm : HashAlgorithmType
      SaltValue : byte[] }

type internal IteratedAndSaltedStringToKey = 
    { HashAlgorithm : HashAlgorithmType
      SaltValue : byte[]
      OctetCount : int }

module internal StringToKeySpecifiers =
    let readBytes (input : Stream) (count : int) : byte[] =
        let bytes = Array.zeroCreate count
        input.Read(bytes, 0, count) |> ignore
        bytes

    let readSaltValue (input : Stream) : byte[] =
        readBytes input 8

    let readOctetCount (input : Stream) : int =
        let expBias = 6
        let c = input.ReadByte()
        (16 + (c &&& 15)) <<< ((c >>> 4) + expBias)

type internal StringToKeySpecifier = 
    | UnknownStringToKeySpecifier
    | SimpleStringToKey of SimpleStringToKey
    | SaltedStringToKey of SaltedStringToKey
    | IteratedAndSaltedStringToKey of IteratedAndSaltedStringToKey
    with 
    static member read (input : Stream) : StringToKeySpecifier =
        match (input.ReadByte()) with
        | 0 -> SimpleStringToKey 
                { HashAlgorithm = HashAlgorithmType.Read input }
        | 1 -> SaltedStringToKey 
                { HashAlgorithm = HashAlgorithmType.Read input;
                  SaltValue = StringToKeySpecifiers.readSaltValue input }
        | 3 -> IteratedAndSaltedStringToKey 
                { HashAlgorithm = HashAlgorithmType.Read input; 
                  SaltValue = StringToKeySpecifiers.readSaltValue input; 
                  OctetCount = StringToKeySpecifiers.readOctetCount input }
        | _ -> UnknownStringToKeySpecifier

