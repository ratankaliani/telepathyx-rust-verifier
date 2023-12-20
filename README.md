# Telepathy X Rust Verifier
This is an implementation of a Rust verifier for [Telepathy X](https://alpha.succinct.xyz/succinctlabs/telepathyx) using [arkworks-rs](https://github.com/arkworks-rs).

## Test Verifier

Test the verifier by running:
```
cargo test zk_step_with_serde
cargo test zk_rotate_with_serde
```

You can test this verifier with live proofs by selecting a proof from Telepathy X's latest proofs on the Succinct platform.