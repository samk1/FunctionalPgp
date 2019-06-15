namespace SolidPgp.Parsing.Tests


open Fuchu
open System.Security.Cryptography
open System.Diagnostics
open System
open CypherFeedbackMode
open System.IO

module SymmetricEncryptionTests =
    let initCfbBlockCypher mode: ICryptoTransform =
        let key = Array.zeroCreate 16

        let aes = new AesManaged()
        aes.Key <- key
        aes.Mode <- CipherMode.ECB

        upcast new OpenPgpCfbBlockCipher(aes, mode)

    let ``Encrypt first block in OpenPGP CFB Mode`` () =
        let inputBuffer = Array.create 16 0x88uy
        let outputBuffer = Array.zeroCreate 16
        let cfb = initCfbBlockCypher CryptoStreamMode.Write

        cfb.TransformBlock(inputBuffer, 0, 16, outputBuffer, 0) |> ignore

        let expected = [| 0xeeuy; 0x61uy; 0xc3uy; 0x5cuy; 0x67uy; 0x02uy; 0xa4uy; 0xb3uy; 0x00uy; 0xc4uy; 0x72uy; 0xd1uy; 0x42uy; 0xbcuy; 0xa3uy; 0xa6uy; |]
        Assert.Equal<byte[]>("", expected, outputBuffer)

    let ``Encrypt second block in OpenPGP CFB Mode`` () =
        let inputBuffer = Array.create 16 0x88uy
        let outputBuffer = Array.zeroCreate 16
        let cfb = initCfbBlockCypher CryptoStreamMode.Write

        cfb.TransformBlock(inputBuffer, 0, 16, outputBuffer, 0) |> ignore
        cfb.TransformBlock(inputBuffer, 0, 16, outputBuffer, 0) |> ignore

        let expected = [| 0xd5uy; 0x78uy; 0xf1uy; 0xa6uy; 0x41uy; 0xb1uy; 0x06uy; 0x97uy; 0xdduy; 0x41uy; 0x42uy; 0x03uy; 0x35uy; 0x97uy; 0x13uy; 0xf7uy; |]
        Assert.Equal<byte[]>("", expected, outputBuffer)

    let ``Encrypt third block in OpenPGP CFB Mode`` () =
        let inputBuffer = Array.create 16 0x88uy
        let outputBuffer = Array.zeroCreate 16
        let cfb = initCfbBlockCypher CryptoStreamMode.Write

        cfb.TransformBlock(inputBuffer, 0, 16, outputBuffer, 0) |> ignore
        cfb.TransformBlock(inputBuffer, 0, 16, outputBuffer, 0) |> ignore
        cfb.TransformBlock(inputBuffer, 0, 16, outputBuffer, 0) |> ignore

        let expected = [| 0xc6uy; 0x5auy; 0xb8uy; 0xbauy; 0xefuy; 0x87uy; 0x3fuy; 0x66uy; 0xa4uy; 0xc1uy; 0xa0uy; 0x29uy; 0x43uy; 0xd2uy; 0x5cuy; 0xa3uy |]
        Assert.Equal<byte[]>("", expected, outputBuffer)

    let ``Decrypt first block in OpenPGP CFB Mode`` () =
        let inputBuffer = [| 0xeeuy; 0x61uy; 0xc3uy; 0x5cuy; 0x67uy; 0x02uy; 0xa4uy; 0xb3uy; 0x00uy; 0xc4uy; 0x72uy; 0xd1uy; 0x42uy; 0xbcuy; 0xa3uy; 0xa6uy; |]
        let outputBuffer = Array.zeroCreate 16
        let cfb = initCfbBlockCypher CryptoStreamMode.Read

        cfb.TransformBlock(inputBuffer, 0, 16, outputBuffer, 0) |> ignore

        let expected = Array.create 16 0x88uy
        Assert.Equal<byte[]>("", expected, outputBuffer)

    let ``Decrypt second block in OpenPGP CFB Mode`` () =
        let inputBuffer1 = [| 0xeeuy; 0x61uy; 0xc3uy; 0x5cuy; 0x67uy; 0x02uy; 0xa4uy; 0xb3uy; 0x00uy; 0xc4uy; 0x72uy; 0xd1uy; 0x42uy; 0xbcuy; 0xa3uy; 0xa6uy; |]
        let inputBuffer2 = [| 0x2auy; 0x87uy; 0x01uy; 0x61uy; 0xb8uy; 0xcauy; 0xc4uy; 0x2fuy; 0xcfuy; 0xf3uy; 0x45uy; 0x56uy; 0x31uy; 0xcfuy; 0xe1uy; 0x3fuy |]
        let outputBuffer = Array.zeroCreate 16
        let cfb = initCfbBlockCypher CryptoStreamMode.Read

        cfb.TransformBlock(inputBuffer1, 0, 16, outputBuffer, 0) |> ignore
        cfb.TransformBlock(inputBuffer2, 0, 16, outputBuffer, 0) |> ignore

        let expected = Array.create 16 0x77uy
        Assert.Equal<byte[]>("", expected, outputBuffer)

    let ``Decrypt third block in OpenPGP CFB Mode`` () =
        let inputBuffer1 = [| 0xeeuy; 0x61uy; 0xc3uy; 0x5cuy; 0x67uy; 0x02uy; 0xa4uy; 0xb3uy; 0x00uy; 0xc4uy; 0x72uy; 0xd1uy; 0x42uy; 0xbcuy; 0xa3uy; 0xa6uy; |]
        let inputBuffer2 = [| 0x2auy; 0x87uy; 0x01uy; 0x61uy; 0xb8uy; 0xcauy; 0xc4uy; 0x2fuy; 0xcfuy; 0xf3uy; 0x45uy; 0x56uy; 0x31uy; 0xcfuy; 0xe1uy; 0x3fuy |]
        let inputBuffer3 = [| 0xe9uy; 0x9fuy; 0x8cuy; 0x9fuy; 0xe3uy; 0xe2uy; 0xb6uy; 0xb3uy; 0xe0uy; 0x5euy; 0xaauy; 0xfbuy; 0x2cuy; 0x3euy; 0x92uy; 0xc2uy |]
        let outputBuffer = Array.zeroCreate 16
        let cfb = initCfbBlockCypher CryptoStreamMode.Read

        cfb.TransformBlock(inputBuffer1, 0, 16, outputBuffer, 0) |> ignore
        cfb.TransformBlock(inputBuffer2, 0, 16, outputBuffer, 0) |> ignore
        cfb.TransformBlock(inputBuffer3, 0, 16, outputBuffer, 0) |> ignore

        let expected = Array.create 16 0x99uy
        Assert.Equal<byte[]>("", expected, outputBuffer)

    let ``Decrypt first byte using CryptoStream`` () =
        let data = TestData.Encrypted1000Bytes
        let memoryStream = new MemoryStream(data)
        let key = Array.zeroCreate 16
        let decryptStream = SolidPgp.Parsing.SymmetricEncryption.decrypt Constants.SymmetricKeyAlgorithms.Aes128 key memoryStream

        let decrypted = decryptStream.ReadByte()

        Assert.Equal("", 0x88, decrypted)

    let ``Assert decryption is correct`` (data: byte[]) =
        let size = data.Length
        let memoryStream = new MemoryStream(data)
        let key = Array.zeroCreate 16
        let decryptStream = SolidPgp.Parsing.SymmetricEncryption.decrypt Constants.SymmetricKeyAlgorithms.Aes128 key memoryStream

        let decrypted = Array.zeroCreate size
        decryptStream.Read(decrypted, 0, size) |> ignore

        let expected = Array.create size 0x88uy
        Assert.Equal("decrypted data did not match expected", expected, decrypted)

    let ``Decrypt 15 bytes using CryptoStream`` () =
        ``Assert decryption is correct`` TestData.Encrypted15Bytes

    let ``Decrypt 16 bytes using CryptoStream`` () =
        ``Assert decryption is correct`` TestData.Encrypted16Bytes

    let ``Decrypt 17 bytes using CryptoStream`` () =
        ``Assert decryption is correct`` TestData.Encrypted17Bytes

    let ``Assert encryption is correct`` (data: byte[]) =
        let size = data.Length
        let memoryStream = new MemoryStream()
        let key = Array.zeroCreate 16
        let encryptStream = SolidPgp.Parsing.SymmetricEncryption.encrypt Constants.SymmetricKeyAlgorithms.Aes128 key memoryStream

        let plain = Array.create size 0x88uy
        encryptStream.Write(plain, 0, size) |> ignore
        encryptStream.Close()

        let encrypted = memoryStream.ToArray()
        Assert.Equal("encrypted data did not match expected", data, encrypted)

    let ``Encrypt 15 bytes using CryptoStream`` () =
        ``Assert encryption is correct`` TestData.Encrypted15Bytes

    let ``Encrypt 16 bytes using CryptoStream`` () =
        ``Assert encryption is correct`` TestData.Encrypted16Bytes

    let ``Encrypt 17 bytes using CryptoStream`` () =
        ``Assert encryption is correct`` TestData.Encrypted17Bytes

    let ``Decrypt 1000 bytes using CrypoStream`` () =
        let data = TestData.Encrypted1000Bytes
        let memoryStream = new MemoryStream(data)
        let key = Array.zeroCreate 16
        let decryptStream = SolidPgp.Parsing.SymmetricEncryption.decrypt Constants.SymmetricKeyAlgorithms.Aes128 key memoryStream

        let decrypted = Array.zeroCreate 1000
        decryptStream.Read(decrypted, 0, 1000) |> ignore

        printfn "decrypted: %A" decrypted.[980..]
        printfn "decrypted length: %A" decrypted.Length

        let expected = Array.create 1000 0x88uy
        printfn "expected length: %A" expected.Length
        Assert.Equal<byte[]>("", expected, decrypted)

    let ``AES should encrypt using ECB mode as expected`` () =
        let key = Array.zeroCreate 16
        let inputBuffer = Array.zeroCreate 16
        let outputBuffer = Array.zeroCreate 16
        
        let aes = new AesManaged()
        aes.Key <- key
        aes.Mode <- CipherMode.ECB
        
        aes.CreateEncryptor().TransformBlock (inputBuffer, 0, 16, outputBuffer, 0) |> ignore
        Trace.WriteLine(sprintf "outputBuffer: %A" outputBuffer)
        ()

    let ``Stress test CFB`` () =
        let random32MB = Array.zeroCreate (1024 * 1024 * 32)
        let rng = RandomNumberGenerator.Create()
        rng.GetBytes(random32MB)    

        let mutable count = 0L
        let mutable ticks : int64 = 0L
        let test (inputBuffer: byte[]) (offset: int) = 
            let outputBuffer = Array.zeroCreate 16
            let cfb = initCfbBlockCypher CryptoStreamMode.Write

            let watch = Stopwatch.StartNew ()

            cfb.TransformBlock(inputBuffer, offset, 16, outputBuffer, 0) |> ignore
            cfb.TransformBlock(inputBuffer, (offset + 16), 16, outputBuffer, 0) |> ignore
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