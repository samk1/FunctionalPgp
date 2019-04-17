module internal Tests

open System
open Xunit

type TestType () = 
    class
    let mutable t1 = 3

    member x.addOne () =
        t1 <- t1 + 1
        ()

    member this.value =
        t1
    end



[<Fact>]
let ``My test`` () =
    let t1 = new TestType ()
    t1.addOne ();
    t1.addOne ();

    Assert.True(5 = t1.value)

