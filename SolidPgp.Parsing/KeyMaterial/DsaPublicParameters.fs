namespace SolidPgp.Parsing.KeyMaterial

open SolidPgp.Parsing.Common

type internal DsaPublicParameters = 
    { PrimeP : MPInteger 
      GroupOrderQ : MPInteger 
      GroupGeneratorG : MPInteger 
      PublicKeyY : MPInteger }

type internal DsaPublicParametersError =
    | DsaPrimePReadError of MPIntegerError
    | DsaGroupOrderQReadError of MPIntegerError
    | DsaGroupGeneratorGReadError of MPIntegerError
    | DsaPublicKeyYReadError of MPIntegerError

module internal DsaPublicParameters =
    let initial =
        { PrimeP = MPInteger.initial
          GroupOrderQ = MPInteger.initial
          GroupGeneratorG = MPInteger.initial
          PublicKeyY = MPInteger.initial }

    let parser =
        Parser.unit (initial, None)
        |> MPInteger.read (fun dsa mpi -> { dsa with PrimeP = mpi }) DsaPrimePReadError
        |> MPInteger.read (fun dsa mpi -> { dsa with GroupOrderQ = mpi }) DsaGroupOrderQReadError
        |> MPInteger.read (fun dsa mpi -> { dsa with GroupGeneratorG = mpi }) DsaGroupGeneratorGReadError
        |> MPInteger.read (fun dsa mpi -> { dsa with PublicKeyY = mpi }) DsaPublicKeyYReadError

    let read withDsa withDsaError =
        Parser.foldpr withDsa withDsaError parser