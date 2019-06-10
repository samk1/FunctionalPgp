namespace Pgp.KeyMaterial

open Pgp.Common

type internal RsaPublicParameters = { ExponentE: MPInteger; ModulusN: MPInteger }

type internal RsaPublicParametersError =
    | RsaModulusNReadError of MPIntegerError
    | RsExponentEReadError of MPIntegerError

module internal RsaPublicParameters =
    let initial =
        { ExponentE = MPInteger.initial; ModulusN = MPInteger.initial }

    let parser =
        Parser.unit (initial, None)
        |> MPInteger.read (fun rsa mpi -> { rsa with ModulusN = mpi }) RsaModulusNReadError
        |> MPInteger.read (fun rsa mpi -> { rsa with ExponentE = mpi }) RsExponentEReadError

    let read withRsa withRsaError =
        Parser.foldpr withRsa withRsaError parser