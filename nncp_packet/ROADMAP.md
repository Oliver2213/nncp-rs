# NNCP Packet Implementation Roadmap

This document outlines the plan for implementing the NNCP (Node to Node Copy Protocol) packet handling in Rust, based on the Go implementation.

## Current Status

- ✅ Basic packet structure
- ✅ Packet encoding/decoding
- ✅ File packet implementation
- ✅ Exec packet implementation
- ✅ ExecFat packet implementation
- ✅ Freq packet implementation
- ✅ Trns packet implementation
- ✅ ACK packet implementation
- ✅ Basic tests

## Upcoming Features

### Packet Encryption

- [ ] Implement encrypted packet structure
- [ ] Add encryption/decryption functionality
- [ ] Support for node identity and key management
- [ ] Signature verification

### Command Line Tools

Based on the Go implementation, we need to implement the following commands:

#### Core Commands

- [ ] `nncp-pkt` - Packet handling utility
- [ ] `nncp-xfer` - Transfer files between nodes
- [ ] `nncp-daemon` - Run as a daemon processing packets
- [ ] `nncp-call` - Call another node via supported transports
- [ ] `nncp-toss` - Process incoming packets

#### File Operations

- [ ] `nncp-file` - Send a file to a remote node
- [ ] `nncp-freq` - Request a file from a remote node
- [ ] `nncp-bundle` - Create a bundle of packets

#### Command Execution

- [ ] `nncp-exec` - Execute a command on a remote node
- [ ] `nncp-execfs` - Execute commands via filesystem interface

#### Management

- [ ] `nncp-stat` - Show statistics about the spool
- [ ] `nncp-rm` - Remove packets from the spool
- [ ] `nncp-cfgdir` - Generate configuration from directory
- [ ] `nncp-cfgenc` - Encrypt configuration
- [ ] `nncp-reass` - Reassemble chunked packets
- [ ] `nncp-check` - Check node's configuration

#### Miscellaneous

- [ ] `nncp-ack` - Send acknowledgment
- [ ] `nncp-trns` - Transit packets to another node
- [ ] `nncp-hash` - Calculate hashes
- [ ] `nncp-newnode` - Generate new node keys

## Implementation Plan

### Phase 1: Core Packet Types (Current)

- Implement all packet types
- Ensure proper encoding/decoding
- Add comprehensive tests

### Phase 2: Encryption Layer

- Implement the encryption layer for packets
- Add key management
- Implement signature verification

### Phase 3: Command Line Tools

- Implement the basic CLI structure
- Add commands one by one, starting with core functionality
- Ensure compatibility with the Go implementation

### Phase 4: Advanced Features

- Implement chunking for large files
- Add support for areas
- Implement transit functionality
- Add bundle support

## Go Implementation Reference

The Go implementation includes the following main components:

1. Packet structure and encoding/decoding
2. Encryption and signature verification
3. Node identity management
4. Spool management
5. Command line tools for various operations

## Compatibility Goals

- Full compatibility with the Go implementation's packet format
- Ability to process packets created by the Go implementation
- Same command line interface for easy transition
