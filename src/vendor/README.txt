Monocypher 4.0.2 (single-file crypto library)

Source:  https://monocypher.org/download/monocypher-4.0.2.tar.gz
License: BSD-2-Clause / CC-0 (see LICENCE.md in the upstream tarball)
Date vendored: 2026-04-15

Files:
  monocypher.c   2956 lines
  monocypher.h    321 lines

SHA-256 of the exact bytes shipped with URTB (computed at vendor time):
  monocypher.c  afe2b098c8569577a84488e0b98d276d1fba6506adea68bb9241a52111734c59
  monocypher.h  f78bb31255cfb7beba66afd2137f5194c8a025cf40488b6cc1e295234d43f374

These hashes match the files extracted from monocypher-4.0.2.tar.gz src/
without any modification (verified by the URTB Phase B-0 build).

Used APIs (URTB Phase B):
  crypto_aead_lock        XChaCha20-Poly1305 encrypt
  crypto_aead_unlock      XChaCha20-Poly1305 decrypt
  crypto_blake2b_keyed    Session key + hello key derivation
  crypto_argon2           Capsule passphrase KDF (Argon2id)
  crypto_wipe             Secure zero of key material

Do not modify these files in place. To upgrade, replace both files from a
verified upstream tarball and update this README.
