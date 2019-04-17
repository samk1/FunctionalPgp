namespace Constants.HashAlgorithms

open System.IO
open System.Security.Cryptography

exception NotImplementedHashAlgorithmException

type internal CryptoHashAlgorithm = System.Security.Cryptography.HashAlgorithm

type internal HashAlgorithmType = 
    | UnknownHashAlgorithm
    | Md5
    | Sha1
    | RipeMd160
    | Reserved4
    | Reserved5
    | Reserved6
    | Reserved7
    | Sha256
    | Sha384
    | Sha512
    | Sha224
    | PrivateOrExperimentalHashAlgorithm
with
    static member Read (input : Stream) : HashAlgorithmType =
        match (input.ReadByte()) with
        | 1 -> Md5
        | 2 -> Sha1
        | 3 -> RipeMd160
        | 4 -> Reserved4
        | 5 -> Reserved5
        | 6 -> Reserved6
        | 7 -> Reserved7
        | 8 -> Sha256
        | 9 -> Sha384
        | 10 -> Sha512
        | 11 -> Sha224
        | id when id >= 100 && id <= 110 -> PrivateOrExperimentalHashAlgorithm
        | _ -> UnknownHashAlgorithm

type internal HashAlgorithm (algorithmType : HashAlgorithmType) =
    let context = HashAlgorithm.Create algorithmType

    static let md5Length = (HashAlgorithm.Create Md5).HashSize
    static let sha1Length = (HashAlgorithm.Create Sha1).HashSize
    static let sha256Length = (HashAlgorithm.Create Sha256).HashSize
    static let sha384Length = (HashAlgorithm.Create Sha384).HashSize
    static let sha512Length = (HashAlgorithm.Create Sha512).HashSize

    static member HashLength (algorithmType : HashAlgorithmType) : int =
        match algorithmType with
            | Md5 -> md5Length
            | Sha1 -> sha1Length
            | Sha256 -> sha256Length
            | Sha384 -> sha384Length
            | Sha512 -> sha512Length
            | _ -> raise NotImplementedHashAlgorithmException

    static member Create (algorithmType : HashAlgorithmType) : CryptoHashAlgorithm =
        match algorithmType with
            | Md5 -> upcast MD5.Create()
            | Sha1 -> upcast SHA1.Create()
            | Sha256 -> upcast SHA256.Create()
            | Sha384 -> upcast SHA384.Create()
            | Sha512 -> upcast SHA512.Create()
            | _ -> raise NotImplementedHashAlgorithmException

    member this.Load (bytes : byte[]) : HashAlgorithm =
        context.TransformBlock (bytes, 0, bytes.Length, null, 0) |> ignore
        this

    member _this.Unload () : byte[] =
        context.TransformFinalBlock (Array.empty, 0, 0) |> ignore
        context.Hash

    member _this.Hash (buffer : byte[]) : byte[] =
        context.TransformFinalBlock (buffer, 0, buffer.Length) |> ignore
        context.Hash




