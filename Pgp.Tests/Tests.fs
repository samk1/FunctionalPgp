namespace Pgp.Tests

open Fuchu

module Tests =
    [<Tests>]
    let tests = testList "tests" [
        testCase "Encrypt first block" SymmetricEncryptionTests.``Encrypt first block in OpenPGP CFB Mode``
        testCase "Encrypt second block" SymmetricEncryptionTests.``Encrypt second block in OpenPGP CFB Mode``
        testCase "Encrypt third block" SymmetricEncryptionTests.``Encrypt third block in OpenPGP CFB Mode``
        testCase "Decrypt first block" SymmetricEncryptionTests.``Decrypt first block in OpenPGP CFB Mode``
        testCase "Decrypt second block" SymmetricEncryptionTests.``Decrypt second block in OpenPGP CFB Mode``
        testCase "Decrypt third block" SymmetricEncryptionTests.``Decrypt third block in OpenPGP CFB Mode``
        testCase "Decrypt single byte" SymmetricEncryptionTests.``Decrypt first byte using CryptoStream``
        testCase "Decrypt 15 bytes" SymmetricEncryptionTests.``Decrypt 15 bytes using CryptoStream``
        testCase "Decrypt 16 bytes" SymmetricEncryptionTests.``Decrypt 16 bytes using CryptoStream``
        testCase "Decrypt 17 bytes" SymmetricEncryptionTests.``Decrypt 17 bytes using CryptoStream``
        testCase "Encrypt 15 bytes" SymmetricEncryptionTests.``Encrypt 15 bytes using CryptoStream``
        testCase "Encrypt 16 bytes" SymmetricEncryptionTests.``Encrypt 16 bytes using CryptoStream``
        testCase "Encrypt 17 bytes" SymmetricEncryptionTests.``Encrypt 17 bytes using CryptoStream``
    ]