# nncp-rs - node to node copy utilities in rust

This is a very early port of [nncp](http://nncpgo.org) in rust.
## What works
* creating a local node, including the 3 required keypairs and saving it to disk - the nncp generate-node command
* calculating the ID of that node or other remote nodes - nncp print-id, optionally with -e to print an emoji representation of your ID.
* writing the default config (including generated node keys) to disk

## What doesn't work
* Serializing or deserializing nncp packets
* Hashing files using blake3 and the custom merkle tree node and leaf-keyed algorithm - I.E. getting a merkle hash, being able to verify a received file
* disk-based send / receive - I.E. nncp-xfer, nncp-bundle
* online protocol and live transfers - I.E. nncp-call, nncp-caller, nncp-daemon
* sending files, exec requests, receiving things...
