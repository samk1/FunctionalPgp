namespace CypherFeedbackMode

open System.Security.Cryptography
open System.Diagnostics



module Cfb =
    let dumpBuf (buf: byte[]) (name: string) : unit =
        Trace.WriteLine(sprintf "%s: %A" name buf)

    let dump args name : unit =
        Trace.Write(sprintf "%s: " name)
        List.map (sprintf " %A " >> Trace.Write) args |> ignore

    let createTransform (cipher: SymmetricAlgorithm)  (mode: CryptoStreamMode) (blockSize: int) =
        match mode with
        | CryptoStreamMode.Write -> 
            let encryptor = cipher.CreateEncryptor()
            fun inBuf outBuf -> encryptor.TransformBlock(inBuf, 0, blockSize, outBuf, 0) |> ignore
        | CryptoStreamMode.Read -> 
            let decryptor = cipher.CreateDecryptor()
            fun inBuf outBuf -> decryptor.TransformBlock(inBuf, 0, blockSize, outBuf, 0) |> ignore
        | _ -> invalidOp "Invalid CryptoStreamMode"
    

type OpenPgpCfbBlockCipher(cipher: SymmetricAlgorithm, mode: CryptoStreamMode) =
    let blockSize = cipher.BlockSize / 8
    let fr = Array.zeroCreate blockSize
    let fre = Array.zeroCreate blockSize

    let transform = Cfb.createTransform cipher mode blockSize

    let mutable count = 0

    member this.EncryptBlock (inBuf: byte[]) (inOff: int) (outBuf: byte[]) (outOff: int) = 
        if count > blockSize then
            
            outBuf.[outOff] <- inBuf.[inOff] ^^^ fre.[blockSize - 2]
            fr.[blockSize - 2] <- outBuf.[outOff]

            outBuf.[outOff + 1] <- inBuf.[inOff + 1] ^^^ fre.[blockSize - 1]
            fr.[blockSize - 1] <- outBuf.[outOff + 1]

            transform fr fre

            for i = 2 to (blockSize - 1) do
                outBuf.[outOff + i] <- inBuf.[inOff + i] ^^^ fre.[i - 2]
                fre.[i - 2] <- outBuf.[outOff + i]
            ()
        else if count = blockSize then
            transform fr fre

            outBuf.[outOff] <- inBuf.[inOff] ^^^ fre.[0]
            outBuf.[outOff + 1] <- inBuf.[inOff + 1] ^^^ fre.[1]

            for i = 2 to (blockSize - 1) do
                fr.[i - 2] <- fr.[i]

            fr.[blockSize - 2] <- outBuf.[outOff]
            fr.[blockSize - 1] <- outBuf.[outOff + 1]

            transform fr fre

            for i = 0 to (blockSize - 3) do
                fr.[i] <- fre.[i] ^^^ inBuf.[inOff + 2 + i]
                outBuf.[i + 2] <- fr.[i]
            ()
        else if count = 0 then
            transform fr fre

            for i = 0 to (blockSize - 1) do
                fr.[i] <- fre.[i] ^^^ inBuf.[inOff + i]
                outBuf.[outOff + i] <- fr.[i]
            ()
        count <- count + blockSize


    interface ICryptoTransform with
        member this.CanReuseTransform: bool = 
            false
        member this.CanTransformMultipleBlocks: bool = 
            true
        member this.Dispose(): unit = 
            ()
        member this.InputBlockSize: int = 
            cipher.BlockSize
        member this.OutputBlockSize: int = 
            cipher.BlockSize
        member this.TransformFinalBlock(inputBuffer: byte [], inputOffset: int, inputCount: int): byte [] = 
            raise (System.NotImplementedException())
        member this.TransformBlock (inputBuffer: byte[], inputOffset: int, inputCount: int, outputBuffer: byte[], outputOffset: int) =
            raise (System.NotImplementedException())