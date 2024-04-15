open Alcotest

let () =
  run
    "bip340"
    [ ( "keys"
      , [ test_case "private key to public key" `Quick (fun _ ->
            check
              string
              "pubkey"
              (Bip340.load_secret
                 (`Hex "e09a4ae9d179c85c1842ad53e19cad764f471ab8072b7cb7f8d58a76aa62e0aa"
                  |> Hex.to_bytes)
               |> Bip340.public_key
               |> Hex.of_bytes
               |> Hex.show)
              "d8c8987a525fa8c8bd895eef6cb84267391cedeb6fde3dcb70d3a192b342ed2d")
        ] )
    ; ( "signatures"
      , [ test_case "sign and verify" `Quick (fun _ ->
            let sec =
              Bip340.load_secret
                (`Hex "e09a4ae9d179c85c1842ad53e19cad764f471ab8072b7cb7f8d58a76aa62e0aa"
                 |> Hex.to_bytes)
            in
            let sig_ = Bip340.sign ~keypair:sec "message" in
            let pub =
              `Hex "d8c8987a525fa8c8bd895eef6cb84267391cedeb6fde3dcb70d3a192b342ed2d"
              |> Hex.to_bytes
            in
            let verified = Bip340.verify ~pubkey:pub "message" sig_ in
            check bool "sign verify" verified true)
        ] )
    ]
;;
