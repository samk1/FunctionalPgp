namespace Common.MPInteger

open System.IO

type internal MPInteger = 
    { 
        Length: int; 
        Bytes : byte[] 
    } with
    static member Read (input : Stream) : MPInteger =
        let (firstOctet, secondOctet) = (input.ReadByte(), input.ReadByte())
        let mpiLength = (firstOctet <<< 8) + secondOctet
        let mpiSize = (mpiLength + 7) / 8
        let mpiBytes = Array.zeroCreate mpiSize
        input.Read(mpiBytes, 0, mpiSize) |> ignore
        { Length = mpiLength; Bytes = mpiBytes }
