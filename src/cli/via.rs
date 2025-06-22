//! Via override functionality for NNCP commands
//!
//! This module implements via path override functionality, allowing commands
//! to specify custom routing paths for packet transmission.

use nncp_rs::nncp::{NodeID, RemoteNNCPNode};
use nncp_rs::routing;
use super::Context;
use anyhow::{Error, anyhow};
use std::collections::HashMap;

/// Via arguments for commands that support routing path override
#[derive(Debug, Clone)]
pub struct ViaArgs {
    /// Via override string from command line (empty = use config, "-" = direct)
    pub via_override: Option<String>,
}

impl ViaArgs {
    /// Create new ViaArgs with via override
    pub fn new(via_override: Option<String>) -> Self {
        Self { via_override }
    }
    
    /// Create ViaArgs with no override (use config defaults)
    pub fn none() -> Self {
        Self { via_override: None }
    }
    
    /// Create ViaArgs for direct routing (bypass config via)
    pub fn direct() -> Self {
        Self { via_override: Some("-".to_string()) }
    }
    
    /// Check if via override is specified
    pub fn has_override(&self) -> bool {
        self.via_override.is_some()
    }
    
    /// Check if direct routing is specified
    pub fn is_direct(&self) -> bool {
        self.via_override.as_deref() == Some("-")
    }
}

/// Via override functionality matching Go nncp.ViaOverride()
/// 
/// This function modifies a node's via path based on command-line override,
/// following the same logic as the Go implementation:
/// - Empty/None: Use config defaults (no change)
/// - "-": Clear via path (direct routing)
/// - Comma-separated nodes: Override with specified path
pub fn apply_via_override(
    node: &mut RemoteNNCPNode,
    via_args: &ViaArgs,
    ctx: &Context,
) -> Result<(), Error> {
    let via_override = match &via_args.via_override {
        Some(override_str) => override_str,
        None => return Ok(()), // No override specified
    };
    
    if via_override.is_empty() {
        return Ok(()); // Empty string means no override
    }
    
    if via_override == "-" {
        // Direct routing: clear via path
        node.via.clear();
        return Ok(());
    }
    
    // Parse comma-separated via nodes and override the path
    let via_nodes = routing::parse_via_override(
        via_override,
        &ctx.neighbors,
        &ctx.neighbor_aliases,
    )?;
    
    node.via = via_nodes;
    Ok(())
}

/// Apply via override to a cloned node (non-mutating version)
/// 
/// This is useful when you need to create a temporary node with overridden
/// via path without modifying the original node in the context.
pub fn apply_via_override_clone(
    node: &RemoteNNCPNode,
    via_args: &ViaArgs,
    ctx: &Context,
) -> Result<RemoteNNCPNode, Error> {
    let mut cloned_node = node.clone();
    apply_via_override(&mut cloned_node, via_args, ctx)?;
    Ok(cloned_node)
}

/// Get the effective routing target for a node with via override applied
/// 
/// This function returns the node that should be used for packet transmission,
/// with via override already applied. It's the main entry point for commands
/// that need to send packets with custom routing.
pub fn get_routing_target(
    target_node: &RemoteNNCPNode,
    via_args: &ViaArgs,
    ctx: &Context,
) -> Result<RemoteNNCPNode, Error> {
    apply_via_override_clone(target_node, via_args, ctx)
}

/// Parse via override from command line argument
/// 
/// This is a helper for commands to parse their --via flags into ViaArgs
pub fn parse_via_args(via_flag: Option<&str>) -> ViaArgs {
    ViaArgs::new(via_flag.map(|s| s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nncp_rs::nncp::RemoteNNCPNode;
    
    fn create_test_node(id_byte: u8, via: Vec<NodeID>) -> RemoteNNCPNode {
        let signpub_bytes = [id_byte; 32];
        let exchpub_bytes = [id_byte; 32];
        RemoteNNCPNode::new(signpub_bytes, exchpub_bytes, None, via).unwrap()
    }
    
    fn create_test_context() -> Context {
        Context::new("/tmp/config", "/tmp/log", "/tmp/spool")
    }
    
    #[test]
    fn test_via_args_creation() {
        let no_override = ViaArgs::none();
        assert!(!no_override.has_override());
        assert!(!no_override.is_direct());
        
        let direct = ViaArgs::direct();
        assert!(direct.has_override());
        assert!(direct.is_direct());
        
        let with_via = ViaArgs::new(Some("node1,node2".to_string()));
        assert!(with_via.has_override());
        assert!(!with_via.is_direct());
    }
    
    #[test]
    fn test_apply_via_override_direct() {
        let mut node = create_test_node(1, vec![[2u8; 32], [3u8; 32]]);
        let ctx = create_test_context();
        let via_args = ViaArgs::direct();
        
        apply_via_override(&mut node, &via_args, &ctx).unwrap();
        assert!(node.via.is_empty());
    }
    
    #[test]
    fn test_apply_via_override_none() {
        let original_via = vec![[2u8; 32], [3u8; 32]];
        let mut node = create_test_node(1, original_via.clone());
        let ctx = create_test_context();
        let via_args = ViaArgs::none();
        
        apply_via_override(&mut node, &via_args, &ctx).unwrap();
        assert_eq!(node.via, original_via); // Should be unchanged
    }
    
    #[test]
    fn test_apply_via_override_clone() {
        let original_via = vec![[2u8; 32], [3u8; 32]];
        let node = create_test_node(1, original_via.clone());
        let ctx = create_test_context();
        let via_args = ViaArgs::direct();
        
        let modified_node = apply_via_override_clone(&node, &via_args, &ctx).unwrap();
        
        // Original should be unchanged
        assert_eq!(node.via, original_via);
        // Modified should be cleared
        assert!(modified_node.via.is_empty());
    }
    
    #[test]
    fn test_parse_via_args() {
        let none_args = parse_via_args(None);
        assert!(!none_args.has_override());
        
        let direct_args = parse_via_args(Some("-"));
        assert!(direct_args.is_direct());
        
        let via_args = parse_via_args(Some("node1,node2"));
        assert!(via_args.has_override());
        assert!(!via_args.is_direct());
    }
}