//! Multi-hop routing functionality for NNCP
//!
//! This module implements the routing logic for sending packets through intermediate nodes,
//! following the same approach as the Go NNCP implementation.

use crate::nncp::{NodeID, RemoteNNCPNode};
use anyhow::{Error, anyhow};
use std::collections::HashMap;

/// Represents a routing hop in the packet transmission path
#[derive(Debug, Clone)]
pub struct RoutingHop {
    /// The node ID of this hop
    pub node_id: NodeID,
    /// Reference to the node configuration
    pub node: RemoteNNCPNode,
}

/// Build hops array from destination node's via configuration
/// 
/// This function constructs the routing path following the same logic as Go NNCP:
/// - Start with the destination node
/// - Add intermediate nodes from the via field in reverse order
/// - Return the complete hop chain
pub fn build_hops(
    destination_node: &RemoteNNCPNode,
    neighbors: &HashMap<NodeID, RemoteNNCPNode>,
) -> Result<Vec<RoutingHop>, Error> {
    let mut hops = Vec::new();
    
    // First hop is always the destination node
    hops.push(RoutingHop {
        node_id: destination_node.id(),
        node: destination_node.clone(),
    });
    
    // Add intermediate nodes from via field in reverse order
    // This matches the Go implementation in tx.go lines 66-72
    for i in (0..destination_node.via.len()).rev() {
        let via_node_id = destination_node.via[i];
        
        // Look up the via node in neighbors
        let via_node = neighbors.get(&via_node_id)
            .ok_or_else(|| anyhow!("Via node {:?} not found in neighbors", 
                                 base32::encode(base32::Alphabet::RFC4648 { padding: false }, &via_node_id)))?;
        
        hops.push(RoutingHop {
            node_id: via_node_id,
            node: via_node.clone(),
        });
    }
    
    Ok(hops)
}

/// Via override functionality matching Go implementation
/// 
/// Parse comma-separated node identifiers and override the routing path
/// Supports both node names (if they exist in neighbors) and base32-encoded NodeIDs
pub fn parse_via_override(
    via_override: &str,
    _neighbors: &HashMap<NodeID, RemoteNNCPNode>,
    neighbor_aliases: &HashMap<String, NodeID>,
) -> Result<Vec<NodeID>, Error> {
    let mut via_nodes = Vec::new();
    
    for via_part in via_override.split(',') {
        let via_part = via_part.trim();
        
        // First try to find by alias/name
        if let Some(node_id) = neighbor_aliases.get(via_part) {
            via_nodes.push(*node_id);
            continue;
        }
        
        // Try to decode as base32 NodeID
        match base32::decode(base32::Alphabet::RFC4648 { padding: false }, via_part) {
            Some(bytes) if bytes.len() == 32 => {
                let mut node_id = [0u8; 32];
                node_id.copy_from_slice(&bytes);
                via_nodes.push(node_id);
            }
            _ => {
                return Err(anyhow!("Unknown via node: {}", via_part));
            }
        }
    }
    
    Ok(via_nodes)
}

/// Apply via override to a node, creating a new node with updated routing path
/// 
/// This matches the ViaOverride function in Go's via.go
pub fn apply_via_override(
    node: &RemoteNNCPNode,
    via_override: &str,
    neighbors: &HashMap<NodeID, RemoteNNCPNode>,
    neighbor_aliases: &HashMap<String, NodeID>,
) -> Result<RemoteNNCPNode, Error> {
    let via_nodes = parse_via_override(via_override, neighbors, neighbor_aliases)?;
    
    // Create a new node with the overridden via path
    let mut new_node = node.clone();
    new_node.via = via_nodes;
    
    Ok(new_node)
}

/// Check if a node requires multi-hop routing
pub fn requires_routing(node: &RemoteNNCPNode) -> bool {
    !node.via.is_empty()
}

/// Get the next hop for a given destination
/// 
/// Returns the immediate next node to send to for reaching the destination
pub fn get_next_hop<'a>(
    destination_node: &'a RemoteNNCPNode,
    neighbors: &'a HashMap<NodeID, RemoteNNCPNode>,
) -> Result<&'a RemoteNNCPNode, Error> {
    if destination_node.via.is_empty() {
        // Direct delivery
        Ok(destination_node)
    } else {
        // Get the last via node (immediate next hop)
        let next_hop_id = destination_node.via[destination_node.via.len() - 1];
        neighbors.get(&next_hop_id)
            .ok_or_else(|| anyhow!("Next hop node {:?} not found in neighbors", 
                                 base32::encode(base32::Alphabet::RFC4648 { padding: false }, &next_hop_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nncp::RemoteNNCPNode;
    
    fn create_test_node(id_byte: u8, via: Vec<NodeID>) -> RemoteNNCPNode {
        let signpub_bytes = [id_byte; 32];
        let exchpub_bytes = [id_byte; 32];
        RemoteNNCPNode::new(signpub_bytes, exchpub_bytes, None, via).unwrap()
    }
    
    #[test]
    fn test_build_hops_direct() {
        let destination = create_test_node(1, Vec::new());
        let neighbors = HashMap::new();
        
        let hops = build_hops(&destination, &neighbors).unwrap();
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].node_id, destination.id());
    }
    
    #[test]
    fn test_build_hops_multi_hop() {
        let intermediate1 = create_test_node(2, Vec::new());
        let intermediate2 = create_test_node(3, Vec::new());
        let intermediate1_id = intermediate1.id();
        let intermediate2_id = intermediate2.id();
        let destination = create_test_node(1, vec![intermediate1_id, intermediate2_id]);
        
        let mut neighbors = HashMap::new();
        neighbors.insert(intermediate1_id, intermediate1);
        neighbors.insert(intermediate2_id, intermediate2);
        
        let hops = build_hops(&destination, &neighbors).unwrap();
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].node_id, destination.id());
        assert_eq!(hops[1].node_id, intermediate2_id); // Reverse order
        assert_eq!(hops[2].node_id, intermediate1_id);
    }
    
    #[test]
    fn test_parse_via_override() {
        let node1 = create_test_node(1, Vec::new());
        let node2 = create_test_node(2, Vec::new());
        let node1_id = node1.id();
        let node2_id = node2.id();
        
        let mut neighbor_aliases = HashMap::new();
        neighbor_aliases.insert("node1".to_string(), node1_id);
        neighbor_aliases.insert("node2".to_string(), node2_id);
        
        let neighbors = HashMap::new();
        
        let via_nodes = parse_via_override("node1,node2", &neighbors, &neighbor_aliases).unwrap();
        assert_eq!(via_nodes.len(), 2);
        assert_eq!(via_nodes[0], node1_id);
        assert_eq!(via_nodes[1], node2_id);
    }
    
    #[test]
    fn test_requires_routing() {
        let direct_node = create_test_node(1, Vec::new());
        assert!(!requires_routing(&direct_node));
        
        let routed_node = create_test_node(1, vec![[2u8; 32]]);
        assert!(requires_routing(&routed_node));
    }
    
    #[test]
    fn test_get_next_hop_direct() {
        let destination = create_test_node(1, Vec::new());
        let neighbors = HashMap::new();
        
        let next_hop = get_next_hop(&destination, &neighbors).unwrap();
        assert_eq!(next_hop.id(), destination.id());
    }
    
    #[test]
    fn test_get_next_hop_routed() {
        let intermediate = create_test_node(2, Vec::new());
        let intermediate_id = intermediate.id(); // Get the actual computed ID
        let destination = create_test_node(1, vec![intermediate_id]);
        
        let mut neighbors = HashMap::new();
        neighbors.insert(intermediate_id, intermediate);
        
        let next_hop = get_next_hop(&destination, &neighbors).unwrap();
        assert_eq!(next_hop.id(), intermediate_id);
    }
}