namespace Pgp.Parsing.KeyMaterial

open Pgp.Parsing.Common

type internal ElgamalPublicParameters = { PrimeP : MPInteger; GroupGeneratorG : MPInteger }

type internal ElgamalPublicParametersError =
    | ElgamalPrimePReadError of MPIntegerError
    | ElgamalGroupGeneratorGReadError of MPIntegerError

module internal ElgamalPublicParameters = 
    let initial =
        { PrimeP = MPInteger.initial; GroupGeneratorG = MPInteger.initial }

    let parser =
        Parser.unit (initial, None)
        |> MPInteger.read (fun elgamal mpi -> { elgamal with PrimeP = mpi }) ElgamalPrimePReadError
        |> MPInteger.read (fun elgamal mpi -> { elgamal with GroupGeneratorG = mpi }) ElgamalGroupGeneratorGReadError

    let read withElgamal withElgamalError =
        Parser.foldpr withElgamal withElgamalError parser