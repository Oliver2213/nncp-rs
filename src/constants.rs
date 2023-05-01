//! various nncp constants

/// the noise pattern used by nncp
pub static NOISE_PROTO_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";
/// Our long about text, describing briefly what nncp is and what this program is and is not.
pub static LONG_ABOUT: &str = r###"
NNCP (Node to Node copy) is a collection of utilities simplifying secure store-and-forward file, mail and command exchange.
Currently aiming for on-disk compatibility, then on-wire.
See nncpgo.org for info; I am not the original author.
"###;