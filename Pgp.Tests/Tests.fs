namespace Pgp.Tests

open Fuchu

module Tests =
    [<Tests>]
    let tests = testList "tests" [
        testCase "Encrypt first block" OpenPgpCfbTests.``Encrypt first block in OpenPGP CFB Mode``
        testCase "Encrypt second block" OpenPgpCfbTests.``Encrypt second block in OpenPGP CFB Mode``
        testCase "Encrypt third block" OpenPgpCfbTests.``Encrypt third block in OpenPGP CFB Mode``
    ]