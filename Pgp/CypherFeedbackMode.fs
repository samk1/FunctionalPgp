namespace CypherFeedbackMode

open System.Security.Cryptography
open System.Diagnostics

type CfbState = 
    { 
      Transform: byte[] -> byte[] -> unit
      Fre: byte[]
      Fr: byte[] 
      Count: int
      BlockSize: int}

type TransformParams =  
    { InputBuffer: byte[]
      InputOffset: int
      OutputBuffer: byte[]
      OutputOffset: int }

module Cfb =
    let dumpState (state : CfbState) : unit =
        Trace.WriteLine(sprintf "state: %A" state)

    let dumpBuf (buf: byte[]) (name: string) : unit =
        Trace.WriteLine(sprintf "%s: %A" name buf)

    let dump args name : unit =
        Trace.Write(sprintf "%s: " name)
        List.map (fun arg -> Trace.Write(sprintf " %A " arg)) args |> ignore
        Trace.WriteLine("")
        ()

    let transformParams (inBuf: byte[], inOff: int, outBuf: byte[], outOff: int) : TransformParams =
        { InputBuffer = inBuf
          InputOffset = inOff
          OutputBuffer = outBuf
          OutputOffset = outOff }

    let xor (arg1: byte) (arg2: byte) : byte =
        arg1 ^^^ arg2

    let transformFr ({Transform = transform; Fre = fre; Fr = fr}: CfbState ): unit =
        transform fr fre

    let encryptFirstBlock (state: CfbState) (encParams: TransformParams): CfbState =
        let { OutputOffset = outOff; OutputBuffer = outBuf; InputOffset = inOff; InputBuffer = inBuf } = encParams
        let { Fr = fr; Fre = fre; BlockSize = bs; Transform = transform; Count = count } = state
        transform fr fre

        for i = 0 to (bs - 1) do
            fr.[i] <- fre.[i] ^^^ inBuf.[inOff + i]
            outBuf.[outOff + i] <- fr.[i]

        { state with Count = count + bs; }

    let encryptSecondBlock (state: CfbState) (encParams: TransformParams): CfbState =
        let { OutputOffset = outOff; OutputBuffer = outBuf; InputOffset = inOff; InputBuffer = inBuf } = encParams
        let { Fr = fr; Fre = fre; BlockSize = bs; Transform = transform; Count = count } = state

        transform fr fre

        outBuf.[outOff] <- inBuf.[inOff] ^^^ fre.[0]
        outBuf.[outOff + 1] <- inBuf.[inOff + 1] ^^^ fre.[1]

        for i = 2 to (bs - 1) do
            fr.[i - 2] <- fr.[i]

        fr.[bs - 2] <- outBuf.[outOff]
        fr.[bs - 1] <- outBuf.[outOff + 1]

        transform fr fre

        for i = 0 to (bs - 3) do
            fr.[i] <- fre.[i] ^^^ inBuf.[inOff + 2 + i]
            outBuf.[i + 2] <- fr.[i]

        { state with Count = count + bs; Fr = fr }



type CfbBlockCypher(cypher: SymmetricAlgorithm, mode: CryptoStreamMode) =
    let blockSize = cypher.BlockSize / 8
    let fr = Array.zeroCreate blockSize
    let fre = Array.zeroCreate blockSize

    let transform = 
        match mode with
        | CryptoStreamMode.Write -> 
            let encryptor = cypher.CreateEncryptor()
            fun inBuf outBuf -> encryptor.TransformBlock(inBuf, 0, blockSize, outBuf, 0) |> ignore
        | CryptoStreamMode.Read -> 
            let decryptor = cypher.CreateDecryptor()
            fun inBuf outBuf -> decryptor.TransformBlock(inBuf, 0, blockSize, outBuf, 0) |> ignore
        | _ -> invalidOp "Invalid CryptoStreamMode"

    let mutable count = 0

    let encryptByte (data: byte) (blockOffset: int) : byte =
        fre.[blockOffset] ^^^ data


    let encryptSecondBlock (inputBuffer: byte[]) (inputOffset: int) (outputBuffer: byte[]) (outputOffset: int) =
        transform fr fre

        outputBuffer.[outputOffset] <- encryptByte inputBuffer.[inputOffset] 0
        outputBuffer.[outputOffset + 1] <- encryptByte inputBuffer.[inputOffset + 1] 1

        Array.blit fr 2 fr 0 (blockSize - 2)
        Array.blit outputBuffer outputOffset fr (blockSize - 2) 2

        transform fr fre

        for n = 2 to blockSize - 1 do
            let enc = encryptByte inputBuffer.[inputOffset + n] (n - 2)
            fr.[n - 2] <- enc
            outputBuffer.[outputOffset + n] <- enc

        count <- count + blockSize
        ()

    member private this.iv with get () = Array.zeroCreate blockSize
    member private this.fr with get () = Array.zeroCreate blockSize
    member private this.fre with get () = Array.zeroCreate blockSize
    member private this.Decryptor with get () = cypher.CreateDecryptor()
    member private this.Encryptor with get () = cypher.CreateEncryptor()

    member private this.encryptBlockInternal (inputBuffer: byte[]) (inputOffset: int) (outputBuffer: byte[]) (outputOffset: int) =
        let enc1 = encryptByte inputBuffer.[inputOffset] (cypher.BlockSize - 2)
        outputBuffer.[outputOffset] <- enc1
        this.fr.[cypher.BlockSize - 2] <- enc1

        let enc2 = encryptByte inputBuffer.[inputOffset + 1] (cypher.BlockSize - 1)
        outputBuffer.[outputOffset + 1] <- enc2
        this.fr.[cypher.BlockSize - 1] <- enc2

        this.Encryptor.TransformBlock(this.fr, 0, cypher.BlockSize, this.fre, 0) |> ignore

        for n = 2 to cypher.BlockSize do
            let enc = encryptByte inputBuffer.[inputOffset + n] (n - 2)
            outputBuffer.[outputOffset + n] <- enc
            this.fr.[n - 2] <- enc

        ()

    member this.encryptBlock (inBuf: byte[]) (inOff: int) (outBuf: byte[]) (outOff: int) = 
        if count = 0 then
            transform fr fre

            for i = 0 to (blockSize - 1) do
                fr.[i] <- fre.[i] ^^^ inBuf.[inOff + i]
                outBuf.[outOff + i] <- fr.[i]

            count <- blockSize

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
        else if count > blockSize then
            ()


    interface ICryptoTransform with
        member this.CanReuseTransform: bool = 
            false
        member this.CanTransformMultipleBlocks: bool = 
            true
        member this.Dispose(): unit = 
            ()
        member this.InputBlockSize: int = 
            cypher.BlockSize
        member this.OutputBlockSize: int = 
            cypher.BlockSize
        member this.TransformFinalBlock(inputBuffer: byte [], inputOffset: int, inputCount: int): byte [] = 
            raise (System.NotImplementedException())
        member this.TransformBlock (inputBuffer: byte[], inputOffset: int, inputCount: int, outputBuffer: byte[], outputOffset: int) =
            0