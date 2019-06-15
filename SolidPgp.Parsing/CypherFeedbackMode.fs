namespace CypherFeedbackMode

open System.Security.Cryptography
open System.Diagnostics
open System

type internal OpenPgpCfbBlockCipher(cipher: SymmetricAlgorithm, mode: CryptoStreamMode) =
    let blockSize = cipher.BlockSize / 8
    let fr = Array.zeroCreate blockSize
    let fre = Array.zeroCreate blockSize

    let encryptor = cipher.CreateEncryptor()
    let encryptFr () = 
        encryptor.TransformBlock(fr, 0, blockSize, fre, 0) |> ignore

    let mutable count = 0

    let encryptBlock (inBuf: byte[]) (inOff: int) (outBuf: byte[]) (outOff: int) = 
        if count > blockSize then
            outBuf.[outOff] <- inBuf.[inOff] ^^^ fre.[blockSize - 2]
            fr.[blockSize - 2] <- outBuf.[outOff]

            outBuf.[outOff + 1] <- inBuf.[inOff + 1] ^^^ fre.[blockSize - 1]
            fr.[blockSize - 1] <- outBuf.[outOff + 1]

            encryptFr ()

            for i = 2 to (blockSize - 1) do
                outBuf.[outOff + i] <- inBuf.[inOff + i] ^^^ fre.[i - 2]
                fre.[i - 2] <- outBuf.[outOff + i]
            ()
        else if count = blockSize then
            encryptFr ()

            outBuf.[outOff] <- inBuf.[inOff] ^^^ fre.[0]
            outBuf.[outOff + 1] <- inBuf.[inOff + 1] ^^^ fre.[1]

            for i = 2 to (blockSize - 1) do
                fr.[i - 2] <- fr.[i]

            fr.[blockSize - 2] <- outBuf.[outOff]
            fr.[blockSize - 1] <- outBuf.[outOff + 1]

            encryptFr ()

            for i = 0 to (blockSize - 3) do
                fr.[i] <- fre.[i] ^^^ inBuf.[inOff + 2 + i]
                outBuf.[i + 2] <- fr.[i]
            count <- count + blockSize
        else if count = 0 then
            encryptFr ()

            for i = 0 to (blockSize - 1) do
                fr.[i] <- fre.[i] ^^^ inBuf.[inOff + i]
                outBuf.[outOff + i] <- fr.[i]
            count <- blockSize

    let decryptBlock (inBuf: byte[]) (inOff: int) (outBuf: byte[]) (outOff: int) = 
        if count > blockSize then
            fr.[blockSize - 2] <- inBuf.[inOff]
            outBuf.[outOff] <- inBuf.[inOff] ^^^ fre.[blockSize - 2]

            fr.[blockSize - 1] <- inBuf.[inOff + 1]
            outBuf.[outOff + 1] <- inBuf.[inOff + 1] ^^^ fre.[blockSize - 1]

            encryptFr ()

            for i = 2 to (blockSize - 1) do
                fr.[i - 2] <- inBuf.[inOff + i]
                outBuf.[outOff + i] <- inBuf.[inOff + i] ^^^ fre.[i - 2]
            ()
        else if count = blockSize then
            encryptFr ()

            outBuf.[outOff] <- inBuf.[inOff] ^^^ fre.[0]
            outBuf.[outOff + 1] <- inBuf.[inOff + 1] ^^^ fre.[1]

            for i = 2 to (blockSize - 1) do
                fr.[i - 2] <- fr.[i]

            fr.[blockSize - 2] <- inBuf.[inOff]
            fr.[blockSize - 1] <- inBuf.[inOff + 1]

            encryptFr ()

            for i = 2 to (blockSize - 1) do
                fr.[i - 2] <- inBuf.[inOff + i]
                outBuf.[outOff + i] <- inBuf.[inOff + i] ^^^ fre.[i - 2]
            count <- blockSize + count            
        else if count = 0 then
            encryptFr ()

            for i = 0 to (blockSize - 1) do
                fr.[i] <- inBuf.[inOff + i]
                outBuf.[i] <- inBuf.[inOff + i] ^^^ fre.[i]
            count <- blockSize

    let transform =
        match mode with
        | CryptoStreamMode.Read -> decryptBlock
        | CryptoStreamMode.Write -> encryptBlock
        | _ -> raise (InvalidOperationException ())

    interface ICryptoTransform with
        member this.CanReuseTransform: bool = 
            false
        member this.CanTransformMultipleBlocks: bool = 
            false
        member this.Dispose(): unit = 
            ()
        member this.InputBlockSize: int = 
            blockSize
        member this.OutputBlockSize: int = 
            blockSize
        member this.TransformBlock (inputBuffer: byte[], inputOffset: int, inputCount: int, outputBuffer: byte[], outputOffset: int) =
            transform inputBuffer inputOffset outputBuffer outputOffset
            inputCount
        member this.TransformFinalBlock(inputBuffer: byte [], inputOffset: int, inputCount: int): byte [] = 
            let finalBlock = Array.zeroCreate blockSize
            transform inputBuffer inputOffset finalBlock 0
            
            let outputBuffer = Array.zeroCreate inputCount
            Array.blit finalBlock 0 outputBuffer 0 inputCount
            Array.fill finalBlock 0 blockSize 0uy
            outputBuffer