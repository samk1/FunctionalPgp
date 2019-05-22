namespace Pgp.Tests

open Fuchu

module Tests =
    [<Tests>]
    let tests = testList "tests" [
        testCase "Encrypt first block block" OpenPgpCfbTests.``Encrypt first block in OpenPGP CFB Mode``
    ]