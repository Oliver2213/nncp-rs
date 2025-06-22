# nncp-rs - node to node copy utilities in rust

This is a port of [nncp](http://nncpgo.org) in rust, implementing the core NNCP protocol and packet handling functionality.

## What works
* Node management:
  * Creating local nodes with required keypairs and saving to disk
  * Node ID calculation and display (including emoji representation)
  * Configuration file generation and management
  * Area ID handling and name resolution
* Packet handling (comprehensive implementation):
  * File packets - for file transfers
  * Exec packets (regular and fat) - for remote command execution
  * Freq packets - for file requests
  * Transit packets - for store-and-forward routing
  * Acknowledgment packets - for delivery confirmation
  * Packet encoding/decoding with proper type validation
  * Niceness level support for packet prioritization
* Cryptographic operations:
  * Packet encryption and decryption
  * Digital signatures and verification
  * Secure key handling and derivation
  * Counter-based encryption with overflow protection
* Utility functions:
  * Base32 encoding/decoding for IDs
  * Niceness formatting and display
  * Terminal size detection and output formatting
  * Multi-reader support for streaming operations

## What doesn't work yet
* High-level send/receive operations
* Disk-based transfer utilities (nncp-xfer, nncp-bundle equivalents)
* Online protocol and live transfers (nncp-call, nncp-caller, nncp-daemon equivalents)
* Complete CLI interface matching original NNCP commands
* Spool directory management and packet queuing

## Roadmap

See the [ROADMAP.md](nncp_packet/ROADMAP.md) file for the implementation plan.
