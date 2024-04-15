open Ctypes
open Foreign

(* types *)

type secp256k1_context = unit ptr

let secp256k1_context : secp256k1_context typ = ptr void

type secp256k1_keypair = unit ptr

let secp256k1_keypair : unit abstract typ =
  abstract ~name:"secp256k1_keypair" ~size:96 ~alignment:0
;;

type secp256k1_xonly_pubkey = unit ptr

let secp256k1_xonly_pubkey : unit abstract typ =
  abstract ~name:"secp256k1_xonly_pubkey" ~size:64 ~alignment:0
;;

(* bindings *)

let secp256k1_context_create =
  foreign "secp256k1_context_create" (uint @-> returning secp256k1_context)
;;

let secp256k1_schnorrsig_sign32 =
  foreign
    "secp256k1_schnorrsig_sign32"
    (secp256k1_context
     @-> ptr char
     @-> ptr char
     @-> ptr secp256k1_keypair
     @-> ptr char
     @-> returning int)
;;

let secp256k1_schnorrsig_verify =
  foreign
    "secp256k1_schnorrsig_verify"
    (secp256k1_context
     @-> ptr char
     @-> ptr char
     @-> size_t
     @-> ptr secp256k1_xonly_pubkey
     @-> returning int)
;;

let secp256k1_keypair_create =
  foreign
    "secp256k1_keypair_create"
    (secp256k1_context @-> ptr secp256k1_keypair @-> ptr char @-> returning int)
;;

let secp256k1_xonly_pubkey_parse =
  foreign
    "secp256k1_xonly_pubkey_parse"
    (secp256k1_context @-> ptr secp256k1_xonly_pubkey @-> ptr char @-> returning int)
;;

let secp256k1_keypair_xonly_pub =
  foreign
    "secp256k1_keypair_xonly_pub"
    (secp256k1_context
     @-> ptr secp256k1_xonly_pubkey
     @-> ptr int
     @-> ptr secp256k1_keypair
     @-> returning int)
;;

let secp256k1_xonly_pubkey_serialize =
  foreign
    "secp256k1_xonly_pubkey_serialize"
    (secp256k1_context @-> ptr char @-> ptr secp256k1_xonly_pubkey @-> returning int)
;;

(* wrappers *)

let ctx =
  secp256k1_context_create (Unsigned.UInt.of_int ((1 lsl 0) lor (1 lsl 8) lor (1 lsl 9)))
;;

let load_secret sec_bytes =
  let sec = allocate_n char ~count:32 in
  Bytes.iteri (fun i b -> sec +@ i <-@ b) sec_bytes;
  let keypair_alloc = allocate_n secp256k1_keypair ~count:1 in
  let keypair = keypair_alloc +@ 0 in
  let _ = secp256k1_keypair_create ctx keypair sec in
  keypair
;;

let public_key keypair =
  let xonly_alloc = allocate_n secp256k1_xonly_pubkey ~count:1 in
  let xonly = xonly_alloc +@ 0 in
  let parity = allocate int 0 in
  let _ = secp256k1_keypair_xonly_pub ctx xonly parity keypair in
  let output32 = allocate_n char ~count:32 in
  let _ = secp256k1_xonly_pubkey_serialize ctx output32 xonly in
  Bytes.init 32 (fun i -> !@(output32 +@ i))
;;

let sign ~keypair msg =
  let msg32 = allocate_n char ~count:32 in
  Sha256.string msg |> Sha256.to_bin |> String.iteri (fun i char -> msg32 +@ i <-@ char);
  let sig64 = allocate_n char ~count:64 in
  let aux_rand = allocate_n char ~count:32 in
  let _ = secp256k1_schnorrsig_sign32 ctx sig64 msg32 keypair aux_rand in
  Bytes.init 64 (fun i -> !@(sig64 +@ i))
;;

let verify ~pubkey msg sig_bytes =
  let msg32 = allocate_n char ~count:32 in
  Sha256.string msg |> Sha256.to_bin |> String.iteri (fun i char -> msg32 +@ i <-@ char);
  let sig64 = allocate_n char ~count:64 in
  sig_bytes |> Bytes.iteri (fun i char -> sig64 +@ i <-@ char);
  let xonly_pubkey_alloc = allocate_n secp256k1_xonly_pubkey ~count:1 in
  let xonly_pubkey = xonly_pubkey_alloc +@ 0 in
  let pubkey32 = allocate_n char ~count:32 in
  pubkey |> Bytes.iteri (fun i char -> pubkey32 +@ i <-@ char);
  let _ = secp256k1_xonly_pubkey_parse ctx xonly_pubkey pubkey32 in
  let ok =
    secp256k1_schnorrsig_verify ctx sig64 msg32 (Unsigned.Size_t.of_int 32) xonly_pubkey
  in
  ok == 1
;;
