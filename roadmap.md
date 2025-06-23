# Roadmap

## Goals

1. **On-disk format compatibility** with Go NNCP implementation
2. **Over-the-wire compatibility** with Go NNCP implementation (if feasible)

## Implemented Commands

- `init` - Initialize NNCP configuration and spool directory
- `gen-node` - Generate a node and print its base 32 encoded keys  
- `print-id` - Print your local node's ID
- `hash` - Calculate MTH hash of a file
- `pkt` - Parse and display NNCP packet information
- `stat` - Show queue statistics
- `ack` - Send packet receipt acknowledgement

## Missing Commands (from Go NNCP)

### Core Functionality
- `file` - Send/receive files
- `freq` - File request functionality
- `exec` - Execute commands on remote nodes
- `trns` - Transition packets between nodes
- `toss` - Toss inbound packets to process them

### Network Operations  
- `call` - Call remote nodes
- `daemon` - Run as daemon for automatic processing
- `caller` - Automatically call nodes

### Utility Commands
- Encrypted config
- `log` - Parse and display log files
- `reass` - Reassemble chunked files
- `rm` - Remove packets from queues
