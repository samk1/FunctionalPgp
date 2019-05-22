namespace Pgp.Tests


open Fuchu
open System.Security.Cryptography
open System.Diagnostics
open System
open CypherFeedbackMode

module OpenPgpCfbTests =
    let initCfbBlockCypher () =
        let key = Array.zeroCreate 16
        

        let aes = new AesManaged()
        aes.Key <- key
        aes.Mode <- CipherMode.ECB

        new CfbBlockCypher(aes, CryptoStreamMode.Write)

    let ``Encrypt first block in OpenPGP CFB Mode`` () =
        let inputBuffer = Array.create 16 0x88uy
        let outputBuffer = Array.zeroCreate 16
        let cfb = initCfbBlockCypher ()

        cfb.EncryptBlock inputBuffer 0 outputBuffer 0

        let expected = [| 0xeeuy; 0x61uy; 0xc3uy; 0x5cuy; 0x67uy; 0x02uy; 0xa4uy; 0xb3uy; 0x00uy; 0xc4uy; 0x72uy; 0xd1uy; 0x42uy; 0xbcuy; 0xa3uy; 0xa6uy; |]
        Assert.Equal<byte[]>("", expected, outputBuffer)

    let ``Encrypt second block in OpenPGP CFB Mode`` () =
        let inputBuffer = Array.create 16 0x88uy
        let outputBuffer = Array.zeroCreate 16
        let cfb = initCfbBlockCypher ()

        cfb.EncryptBlock inputBuffer 0 outputBuffer 0
        cfb.EncryptBlock inputBuffer 0 outputBuffer 0

        let expected = [| 0xd5uy; 0x78uy; 0xf1uy; 0xa6uy; 0x41uy; 0xb1uy; 0x06uy; 0x97uy; 0xdduy; 0x41uy; 0x42uy; 0x03uy; 0x35uy; 0x97uy; 0x13uy; 0xf7uy; |]
        Assert.Equal<byte[]>("", expected, outputBuffer)

    let ``AES should encrypt using ECB mode as expected`` () =
        let key = Array.zeroCreate 16
        let inputBuffer = Array.zeroCreate 16
        let outputBuffer = Array.zeroCreate 16
        
        let aes = new AesManaged()
        aes.Key <- key
        aes.Mode <- CipherMode.ECB
        
        aes.CreateEncryptor().TransformBlock (inputBuffer, 0, 16, outputBuffer, 0) |> ignore
        Trace.WriteLine(sprintf "outputBuffer: %A" outputBuffer)

    let ``Stress test CFB`` () =
        let random32MB = Array.zeroCreate (1024 * 1024 * 32)
        let rng = RandomNumberGenerator.Create()
        rng.GetBytes(random32MB)    

        let mutable count = 0L
        let mutable ticks : int64 = 0L
        let test (inputBuffer: byte[]) (offset: int) = 
            let outputBuffer = Array.zeroCreate 16
            let cfb = initCfbBlockCypher ()

            let watch = Stopwatch.StartNew ()

            cfb.EncryptBlock inputBuffer offset outputBuffer 0
            cfb.EncryptBlock inputBuffer (offset + 16) outputBuffer 0
            watch.Stop()
            count <- count + 1L
            ticks <- ticks + watch.ElapsedTicks
            ()

        for n = 0 to ((1024 * 1024) - 1) do
            test random32MB (n * 32)

        let nsPerTick = (float (1000L*1000L*1000L)) / (float Stopwatch.Frequency)
        let avgTicks = (float ticks) / (float count)

        let avgNs = avgTicks * nsPerTick
        ()