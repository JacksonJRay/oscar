//! Local Linux node network troubleshooting tools (status, routes, sockets, ping, DNS).

use crate::sync::{command_on_path, run_json_command, run_text_command};
use crate::traits::{Tool, ToolContext, ToolMeta, ToolResult};
use crate::ToolRegistry;
use async_trait::async_trait;
use oscar_core::{Capability, Cloud, ToolDomain};
use serde_json::json;
use std::sync::Arc;

pub fn register_node(registry: &mut ToolRegistry) {
    registry.register(Arc::new(NodeNetStatus));
    registry.register(Arc::new(NodeNetRouteTable));
    registry.register(Arc::new(NodeNetRouteGet));
    registry.register(Arc::new(NodeNetNeigh));
    registry.register(Arc::new(NodeNetSs));
    registry.register(Arc::new(NodeNetPing));
    registry.register(Arc::new(NodeNetTraceroute));
    registry.register(Arc::new(NodeNetDnsLookup));
    registry.register(Arc::new(NodeBpfProgsList));
    registry.register(Arc::new(NodeBpfNetShow));
}

fn timeout_arg(args: &serde_json::Value, default: u64) -> u64 {
    args.get("timeout_sec")
        .and_then(|v| v.as_u64())
        .unwrap_or(default)
        .clamp(1, 60)
}

struct NodeNetStatus;
struct NodeNetRouteTable;
struct NodeNetRouteGet;
struct NodeNetNeigh;
struct NodeNetSs;
struct NodeNetPing;
struct NodeNetTraceroute;
struct NodeNetDnsLookup;
struct NodeBpfProgsList;
struct NodeBpfNetShow;

#[async_trait]
impl Tool for NodeNetStatus {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "node.net.status".into(),
            name: "Node network status snapshot".into(),
            description: "Local Linux network snapshot: default route, primary addresses/links (MTU/state), DNS resolvers. First tool for node connectivity issues before cloud path analyzers.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "node".into(),
                "network".into(),
                "status".into(),
                "health".into(),
                "mtu".into(),
                "route".into(),
                "dns".into(),
                "troubleshoot".into(),
                "analyze".into(),
                "connectivity".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "timeout_sec": { "type": "integer", "default": 8 }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let t = timeout_arg(&args, 8);
        let mut parts = serde_json::Map::new();
        let mut notes: Vec<String> = Vec::new();

        if command_on_path("ip").await {
            if let Ok(v) = run_json_command("ip", &["-j", "route", "show", "default"]).await {
                parts.insert("default_routes".into(), v);
            } else if let Ok(txt) =
                run_text_command("ip", &["route", "show", "default"], t).await
            {
                parts.insert("default_routes_text".into(), json!(txt.trim()));
            }
            if let Ok(v) = run_json_command("ip", &["-j", "addr", "show"]).await {
                // Summarize: keep name, state, mtu, addresses only
                let summary = summarize_ip_addr(&v);
                parts.insert("interfaces".into(), summary);
            } else if let Ok(txt) = run_text_command("ip", &["-br", "addr"], t).await {
                parts.insert("interfaces_text".into(), json!(txt.trim()));
            }
            if let Ok(v) = run_json_command("ip", &["-j", "link", "show"]).await {
                parts.insert("links".into(), summarize_ip_link(&v));
            }
        } else {
            notes.push("ip not on PATH".into());
        }

        if command_on_path("resolvectl").await {
            if let Ok(txt) = run_text_command("resolvectl", &["status"], t).await {
                parts.insert(
                    "dns_resolvectl".into(),
                    json!(truncate_lines(txt.trim(), 40)),
                );
            }
        } else if let Ok(raw) = tokio::fs::read_to_string("/etc/resolv.conf").await {
            parts.insert("dns_resolv_conf".into(), json!(raw.trim()));
        }

        if parts.is_empty() {
            return ToolResult::error(
                "No node network data: install `iproute2` (ip) and ensure PATH is set",
            );
        }
        let def = parts
            .get("default_routes")
            .or_else(|| parts.get("default_routes_text"))
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".into());
        ToolResult::success(
            format!("Node net status: default_route≈{def}"),
            json!({
                "format": "NodeNetStatus",
                "target": "local",
                "data": parts,
                "notes": notes
            }),
        )
    }
}

fn summarize_ip_addr(v: &serde_json::Value) -> serde_json::Value {
    let mut out = Vec::new();
    if let Some(arr) = v.as_array() {
        for ifc in arr.iter().take(32) {
            let ifname = ifc.get("ifname").and_then(|x| x.as_str()).unwrap_or("?");
            let oper = ifc
                .get("operstate")
                .and_then(|x| x.as_str())
                .unwrap_or("?");
            let mtu = ifc.get("mtu");
            let mut addrs = Vec::new();
            if let Some(alist) = ifc.get("addr_info").and_then(|a| a.as_array()) {
                for a in alist.iter().take(8) {
                    if let Some(local) = a.get("local").and_then(|x| x.as_str()) {
                        let pfx = a.get("prefixlen").and_then(|x| x.as_u64()).unwrap_or(0);
                        addrs.push(format!("{local}/{pfx}"));
                    }
                }
            }
            out.push(json!({
                "ifname": ifname,
                "operstate": oper,
                "mtu": mtu,
                "addresses": addrs
            }));
        }
    }
    json!(out)
}

fn summarize_ip_link(v: &serde_json::Value) -> serde_json::Value {
    let mut out = Vec::new();
    if let Some(arr) = v.as_array() {
        for ifc in arr.iter().take(32) {
            out.push(json!({
                "ifname": ifc.get("ifname"),
                "operstate": ifc.get("operstate"),
                "mtu": ifc.get("mtu"),
                "link_type": ifc.get("link_type"),
            }));
        }
    }
    json!(out)
}

fn truncate_lines(s: &str, max_lines: usize) -> String {
    s.lines()
        .take(max_lines)
        .collect::<Vec<_>>()
        .join("\n")
}

#[async_trait]
impl Tool for NodeNetRouteTable {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "node.net.route.table".into(),
            name: "Node route table".into(),
            description: "Show local Linux routing tables (ip route). Optional dest filter via substring on printed routes.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "node".into(),
                "route".into(),
                "route-table".into(),
                "network".into(),
                "status".into(),
                "blackhole".into(),
                "troubleshoot".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "table": { "type": "string", "description": "Route table name/id or 'all'", "default": "main" },
                    "filter": { "type": "string", "description": "Optional substring filter on routes" },
                    "timeout_sec": { "type": "integer", "default": 8 }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        if !command_on_path("ip").await {
            return ToolResult::error("`ip` (iproute2) not on PATH");
        }
        let t = timeout_arg(&args, 8);
        let table = args
            .get("table")
            .and_then(|v| v.as_str())
            .unwrap_or("main");
        let filter = args
            .get("filter")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let txt = if table == "all" {
            run_text_command("ip", &["route", "show", "table", "all"], t).await
        } else {
            run_text_command("ip", &["route", "show", "table", table], t).await
        };
        match txt {
            Ok(mut s) => {
                if !filter.is_empty() {
                    s = s
                        .lines()
                        .filter(|l| l.to_ascii_lowercase().contains(&filter))
                        .collect::<Vec<_>>()
                        .join("\n");
                }
                let lines = s.lines().count();
                ToolResult::success(
                    format!("Node routes table={table}: {lines} line(s)"),
                    json!({
                        "format": "NodeRouteTable",
                        "table": table,
                        "filter": filter,
                        "routes_text": s.trim()
                    }),
                )
            }
            Err(e) => ToolResult::error(e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for NodeNetRouteGet {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "node.net.route.get".into(),
            name: "Node FIB lookup (ip route get)".into(),
            description: "Kernel fib lookup for a destination: next hop, device, src. Prefer this over full table dumps when checking one target.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "node".into(),
                "route".into(),
                "fib".into(),
                "next-hop".into(),
                "path".into(),
                "connectivity".into(),
                "analyze".into(),
                "troubleshoot".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "destination": { "type": "string", "description": "Dest IP or hostname" },
                    "from": { "type": "string", "description": "Optional source IP" },
                    "timeout_sec": { "type": "integer", "default": 5 }
                },
                "required": ["destination"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let dest = args
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if dest.is_empty() {
            return ToolResult::error("destination is required");
        }
        if !command_on_path("ip").await {
            return ToolResult::error("`ip` (iproute2) not on PATH");
        }
        let t = timeout_arg(&args, 5);
        let mut argv: Vec<String> = vec!["route".into(), "get".into(), dest.into()];
        if let Some(f) = args.get("from").and_then(|v| v.as_str()) {
            if !f.is_empty() {
                argv.push("from".into());
                argv.push(f.into());
            }
        }
        let refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        match run_text_command("ip", &refs, t).await {
            Ok(s) => ToolResult::success(
                format!("ip route get {dest}: {}", s.lines().next().unwrap_or("").trim()),
                json!({
                    "format": "NodeRouteGet",
                    "destination": dest,
                    "result_text": s.trim()
                }),
            ),
            Err(e) => ToolResult::error(e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for NodeNetNeigh {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "node.net.neigh".into(),
            name: "Node ARP/ND neighbor table".into(),
            description: "Show ARP/IPv6 neighbor cache (ip neigh). Useful for L2 reachability on the same segment.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "node".into(),
                "arp".into(),
                "neigh".into(),
                "l2".into(),
                "network".into(),
                "status".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "filter": { "type": "string" },
                    "timeout_sec": { "type": "integer", "default": 5 }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        if !command_on_path("ip").await {
            return ToolResult::error("`ip` not on PATH");
        }
        let t = timeout_arg(&args, 5);
        let filter = args
            .get("filter")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match run_text_command("ip", &["neigh", "show"], t).await {
            Ok(s) => {
                let body = if filter.is_empty() {
                    s
                } else {
                    s.lines()
                        .filter(|l| l.to_ascii_lowercase().contains(&filter))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                ToolResult::success(
                    format!("Neighbors: {} line(s)", body.lines().count()),
                    json!({ "format": "NodeNeigh", "neigh_text": body.trim() }),
                )
            }
            Err(e) => ToolResult::error(e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for NodeNetSs {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "node.net.ss".into(),
            name: "Node sockets (ss)".into(),
            description: "List listening/established sockets via ss. Filter by port, state, or host substring. Use for connection refused vs nothing listening.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "node".into(),
                "ss".into(),
                "socket".into(),
                "listen".into(),
                "port".into(),
                "connect".into(),
                "status".into(),
                "troubleshoot".into(),
                "connectivity".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "listening": { "type": "boolean", "default": true, "description": "If true, only listening sockets (-l)" },
                    "tcp": { "type": "boolean", "default": true },
                    "udp": { "type": "boolean", "default": false },
                    "filter": { "type": "string", "description": "Substring e.g. :443 or 10.0.1" },
                    "timeout_sec": { "type": "integer", "default": 5 }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        if !command_on_path("ss").await {
            return ToolResult::error("`ss` (iproute2) not on PATH");
        }
        let t = timeout_arg(&args, 5);
        let listening = args
            .get("listening")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let tcp = args.get("tcp").and_then(|v| v.as_bool()).unwrap_or(true);
        let udp = args.get("udp").and_then(|v| v.as_bool()).unwrap_or(false);
        let filter = args
            .get("filter")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let mut flags = String::from("-H");
        if listening {
            flags.push('l');
        }
        flags.push('n');
        if tcp {
            flags.push('t');
        }
        if udp {
            flags.push('u');
        }
        // processes if permitted
        flags.push('p');

        match run_text_command("ss", &[&flags], t).await {
            Ok(s) => {
                let body = if filter.is_empty() {
                    s.lines().take(200).collect::<Vec<_>>().join("\n")
                } else {
                    s.lines()
                        .filter(|l| l.to_ascii_lowercase().contains(&filter))
                        .take(200)
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                ToolResult::success(
                    format!("ss: {} line(s)", body.lines().filter(|l| !l.is_empty()).count()),
                    json!({
                        "format": "NodeSs",
                        "flags": flags,
                        "filter": filter,
                        "sockets_text": body
                    }),
                )
            }
            Err(e) => ToolResult::error(e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for NodeNetPing {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "node.net.ping".into(),
            name: "Node ICMP ping".into(),
            description: "ICMP reachability from this host (ping -c count). Time-boxed; does not prove TCP port open.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "node".into(),
                "ping".into(),
                "icmp".into(),
                "connectivity".into(),
                "status".into(),
                "troubleshoot".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "destination": { "type": "string" },
                    "count": { "type": "integer", "default": 3, "maximum": 10 },
                    "timeout_sec": { "type": "integer", "default": 10 }
                },
                "required": ["destination"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let dest = args
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if dest.is_empty() {
            return ToolResult::error("destination is required");
        }
        if !command_on_path("ping").await {
            return ToolResult::error("`ping` not on PATH");
        }
        let count = args
            .get("count")
            .and_then(|v| v.as_u64())
            .unwrap_or(3)
            .clamp(1, 10)
            .to_string();
        let t = timeout_arg(&args, 10);
        // -W 2 per-packet wait where supported; -c count
        match run_text_command("ping", &["-c", &count, "-W", "2", dest], t).await {
            Ok(s) => {
                let ok = !s.contains("[exit") && (s.contains("bytes from") || s.contains("ttl="));
                ToolResult::success(
                    format!(
                        "ping {dest}: {}",
                        if ok { "replies seen" } else { "no replies / error" }
                    ),
                    json!({
                        "format": "NodePing",
                        "destination": dest,
                        "reachable_hint": ok,
                        "output": s.trim()
                    }),
                )
            }
            Err(e) => ToolResult::error(e.to_string()),
        }
    }
}

#[async_trait]
impl Tool for NodeNetTraceroute {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "node.net.traceroute".into(),
            name: "Node traceroute / tracepath / mtr".into(),
            description: "Hop path from this host. Prefers mtr report mode, then traceroute, then tracepath.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "node".into(),
                "traceroute".into(),
                "mtr".into(),
                "path".into(),
                "hops".into(),
                "connectivity".into(),
                "analyze".into(),
                "troubleshoot".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "destination": { "type": "string" },
                    "timeout_sec": { "type": "integer", "default": 30 }
                },
                "required": ["destination"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let dest = args
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if dest.is_empty() {
            return ToolResult::error("destination is required");
        }
        let t = timeout_arg(&args, 30);
        if command_on_path("mtr").await {
            match run_text_command("mtr", &["-r", "-c", "5", "-n", dest], t).await {
                Ok(s) => {
                    return ToolResult::success(
                        format!("mtr report → {dest}"),
                        json!({ "format": "NodeTraceroute", "tool": "mtr", "destination": dest, "output": s.trim() }),
                    );
                }
                Err(e) => {
                    return ToolResult::error(e.to_string());
                }
            }
        }
        if command_on_path("traceroute").await {
            match run_text_command("traceroute", &["-n", "-w", "2", "-q", "1", "-m", "20", dest], t)
                .await
            {
                Ok(s) => {
                    return ToolResult::success(
                        format!("traceroute → {dest}"),
                        json!({ "format": "NodeTraceroute", "tool": "traceroute", "destination": dest, "output": s.trim() }),
                    );
                }
                Err(e) => return ToolResult::error(e.to_string()),
            }
        }
        if command_on_path("tracepath").await {
            match run_text_command("tracepath", &["-n", dest], t).await {
                Ok(s) => {
                    return ToolResult::success(
                        format!("tracepath → {dest}"),
                        json!({ "format": "NodeTraceroute", "tool": "tracepath", "destination": dest, "output": s.trim() }),
                    );
                }
                Err(e) => return ToolResult::error(e.to_string()),
            }
        }
        ToolResult::error("Install mtr, traceroute, or tracepath on PATH")
    }
}

#[async_trait]
impl Tool for NodeNetDnsLookup {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "node.net.dns.lookup".into(),
            name: "Node local DNS lookup".into(),
            description: "Resolve a name via local resolver (dig preferred, else getent hosts). Complements cloud dns.where for 'what does this node see?'.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "node".into(),
                "dns".into(),
                "resolve".into(),
                "lookup".into(),
                "dig".into(),
                "status".into(),
                "troubleshoot".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "type": { "type": "string", "default": "A", "description": "Record type for dig" },
                    "timeout_sec": { "type": "integer", "default": 8 }
                },
                "required": ["name"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let name = args
            .get("name")
            .or_else(|| args.get("destination"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if name.is_empty() {
            return ToolResult::error("name is required");
        }
        let rtype = args
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("A");
        let t = timeout_arg(&args, 8);
        if command_on_path("dig").await {
            match run_text_command("dig", &["+short", name, rtype], t).await {
                Ok(s) => {
                    return ToolResult::success(
                        format!("dig {name} {rtype}: {}", s.lines().next().unwrap_or("(empty)").trim()),
                        json!({
                            "format": "NodeDnsLookup",
                            "tool": "dig",
                            "name": name,
                            "type": rtype,
                            "answers": s.trim()
                        }),
                    );
                }
                Err(e) => return ToolResult::error(e.to_string()),
            }
        }
        if command_on_path("getent").await {
            match run_text_command("getent", &["hosts", name], t).await {
                Ok(s) => {
                    return ToolResult::success(
                        format!("getent hosts {name}"),
                        json!({
                            "format": "NodeDnsLookup",
                            "tool": "getent",
                            "name": name,
                            "answers": s.trim()
                        }),
                    );
                }
                Err(e) => return ToolResult::error(e.to_string()),
            }
        }
        ToolResult::error("Install dig (bind-utils/dnsutils) or getent")
    }
}

#[async_trait]
impl Tool for NodeBpfProgsList {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "node.bpf.progs.list".into(),
            name: "List loaded BPF programs".into(),
            description: "Inventory loaded eBPF programs via bpftool prog show. First step before live tcpconnect/retrans traces.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "node".into(),
                "bpf".into(),
                "ebpf".into(),
                "bpftool".into(),
                "xdp".into(),
                "status".into(),
                "troubleshoot".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "timeout_sec": { "type": "integer", "default": 8 }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        if !command_on_path("bpftool").await {
            return ToolResult::error(
                "`bpftool` not on PATH — install linux-tools/bpftool (see system.binaries.install_plan)",
            );
        }
        let t = timeout_arg(&args, 8);
        // Prefer JSON; fall back to text
        match run_text_command("bpftool", &["-j", "prog", "show"], t).await {
            Ok(s) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(s.trim()) {
                    let n = v.as_array().map(|a| a.len()).unwrap_or(0);
                    return ToolResult::success(
                        format!("bpftool prog show: {n} program(s)"),
                        json!({ "format": "BpfProgs", "programs": v }),
                    );
                }
                ToolResult::success(
                    "bpftool prog show (text)",
                    json!({ "format": "BpfProgs", "programs_text": truncate_lines(s.trim(), 80) }),
                )
            }
            Err(_) => match run_text_command("bpftool", &["prog", "show"], t).await {
                Ok(s) => ToolResult::success(
                    "bpftool prog show (text)",
                    json!({ "format": "BpfProgs", "programs_text": truncate_lines(s.trim(), 80) }),
                ),
                Err(e) => ToolResult::error(e.to_string()),
            },
        }
    }
}

#[async_trait]
impl Tool for NodeBpfNetShow {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "node.bpf.net.show".into(),
            name: "BPF net attachments (XDP/tc)".into(),
            description: "Show eBPF programs attached to networking (bpftool net show) — XDP/tc drop/redirect paths.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "node".into(),
                "bpf".into(),
                "ebpf".into(),
                "xdp".into(),
                "tc".into(),
                "bpftool".into(),
                "drop".into(),
                "status".into(),
                "troubleshoot".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "timeout_sec": { "type": "integer", "default": 8 }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        if !command_on_path("bpftool").await {
            return ToolResult::error("`bpftool` not on PATH");
        }
        let t = timeout_arg(&args, 8);
        match run_text_command("bpftool", &["-j", "net", "show"], t).await {
            Ok(s) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(s.trim()) {
                    return ToolResult::success(
                        "bpftool net show",
                        json!({ "format": "BpfNet", "net": v }),
                    );
                }
                ToolResult::success(
                    "bpftool net show",
                    json!({ "format": "BpfNet", "net_text": s.trim() }),
                )
            }
            Err(_) => match run_text_command("bpftool", &["net", "show"], t).await {
                Ok(s) => ToolResult::success(
                    "bpftool net show",
                    json!({ "format": "BpfNet", "net_text": s.trim() }),
                ),
                Err(e) => ToolResult::error(e.to_string()),
            },
        }
    }
}
