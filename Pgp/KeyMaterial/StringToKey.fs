module StringToKey

open Common.StringToKeySpecifiers
open Constants.SymmetricKeyAlgorithms
open Constants.HashAlgorithms
open System.Text

type PgpHashAlgorithm = Constants.HashAlgorithms.HashAlgorithm

let extractKey (data : byte[]) (keyLength : int) : byte[] =
    data.[0..((keyLength / 8) - 1)]

let simpleStringToKey (passPhrase : byte[]) (hashAlgorithmType : HashAlgorithmType) (symmetricAlgorithm : SymmetricKeyAlgorithmType) : byte[] =
    let keyLength = SymmetricKeyAlgorithmType.keyLength symmetricAlgorithm
    let hashLength = HashAlgorithm.hashLength hashAlgorithmType
    match hashLength > keyLength with
        | true ->
            extractKey ((HashAlgorithm (hashAlgorithmType)).hash(passPhrase)) keyLength
        | false -> 
            let digests = seq [ for i in 0 .. keyLength / hashLength -> 
                (HashAlgorithm (hashAlgorithmType)).load(Array.zeroCreate i).hash(passPhrase) ]
            extractKey (Array.concat digests) keyLength

let saltedStringToKey 
    (passPhrase : byte[]) 
    (salt : byte[]) 
    (hashAlgorithmType : HashAlgorithmType) 
    (symmetricAlgorithm : SymmetricKeyAlgorithmType) : byte[] =
    let passPhraseBytes = Array.concat ([salt; passPhrase])
    simpleStringToKey passPhraseBytes hashAlgorithmType symmetricAlgorithm

let rec iterateHash (data : byte[]) (contexts : seq<HashAlgorithm>) (count : int) (hashed : int) : byte[] =
    let nextContexts = Seq.map (fun (context : HashAlgorithm) -> context.load(data)) contexts
    let nextHashed = (Seq.fold (fun acc _ -> (acc + data.Length)) 0 contexts) + hashed
    let finished = hashed >= count
    match finished with
        | true -> Array.concat(Seq.map (fun (context : HashAlgorithm) -> context.unload ()) nextContexts)
        | false -> iterateHash data nextContexts count nextHashed

let iteratedAndSaltedStringToKey
    (passPhrase : byte[])
    (salt : byte[])
    (count : int)
    (hashAlgorithmType : HashAlgorithmType)
    (symmetricAlgorithm : SymmetricKeyAlgorithmType) : byte[] =
    let keyLength = SymmetricKeyAlgorithmType.keyLength symmetricAlgorithm
    let hashLength = HashAlgorithm.hashLength hashAlgorithmType
    let contexts = seq [ for i in 0 .. keyLength / hashLength -> 
                            (HashAlgorithm (hashAlgorithmType)).load(Array.zeroCreate i)]
    extractKey (iterateHash (Array.concat([salt; passPhrase])) contexts count 0) keyLength

exception BadStringToKeySpecifier

let stringToKey (passPhrase : string) (specifier : StringToKeySpecifier) (symmetricAlgorithm : SymmetricKeyAlgorithmType) : byte[] =
    let passPhraseBytes = Encoding.UTF8.GetBytes(passPhrase)
    match specifier with
        | SimpleStringToKey { HashAlgorithm = hashAlgorithm } -> 
            simpleStringToKey passPhraseBytes hashAlgorithm symmetricAlgorithm
        | SaltedStringToKey { HashAlgorithm = hashAlgorithm; SaltValue = salt } ->
            saltedStringToKey passPhraseBytes salt hashAlgorithm symmetricAlgorithm
        | IteratedAndSaltedStringToKey { HashAlgorithm = hashAlgorithm; SaltValue = salt; OctetCount = count } ->
            iteratedAndSaltedStringToKey passPhraseBytes salt count hashAlgorithm symmetricAlgorithm
        | UnknownStringToKeySpecifier -> raise BadStringToKeySpecifier