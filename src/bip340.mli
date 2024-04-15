type secp256k1_context = unit Ctypes.ptr
type secp256k1_keypair = unit Ctypes.ptr
type secp256k1_xonly_pubkey = unit Ctypes.ptr

val load_secret : bytes -> (unit Ctypes.abstract, [ `C ]) Ctypes.pointer
val public_key : unit Ctypes.abstract Ctypes_static.ptr -> bytes
val sign : keypair:unit Ctypes.abstract Ctypes_static.ptr -> string -> bytes
val verify : pubkey:bytes -> string -> bytes -> bool
