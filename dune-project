(lang dune 3.14)
(name bip340)
(generate_opam_files true)
(source
 (github andunieee/bip340))
(authors "andunië")
(maintainers "andunie@cassis.cash")
(license MIT)
(package
 (name bip340)
 (synopsis "bitcoin schnorr signatures")
 (description "libsecp256k1 wrapper for OCaml that only exposes a few primitives required for creating and verifying Schnorr signatures.")
 (tags
  (topics bitcoin schnorr taproot bip340)))
