# Multi-cloud network fabric coverage

Oscar network inventory + pattern tools for **core VPC/VNet** and **connectivity fabric** (routes, peering, sharing, hybrid, private endpoints).

## Coverage matrix

| Service class | AWS | GCP | Azure | Pattern tool(s) |
|---------------|-----|-----|-------|-----------------|
| VPC / VNet | ✓ describe-vpcs | ✓ networks list | ✓ vnet list | `*.network.vpc\|vnet.pattern` |
| Subnet | ✓ | ✓ | ✓ | `*.network.subnet.pattern` |
| Address / IP | ✓ ENI/EIP | ✓ addresses + NICs | ✓ PIP + NIC | `*.ip.locate`, pattern.search |
| SG / Firewall / NSG | ✓ SG | ✓ firewall | ✓ NSG | `sg\|firewall\|nsg.pattern` |
| NACL | ✓ | — (use firewall) | — (use NSG) | `aws.network.nacl.pattern` |
| Route tables / routes | ✓ | ✓ global routes | ✓ UDR | `route\|route_table.pattern` |
| **VPC/VNet peering** | ✓ describe-vpc-peering | ✓ peerings on network | ✓ virtualNetworkPeerings | `*.network.peering.pattern` |
| **Transit / hub** | ✓ TGW | NCC hub (future) | VWAN hub (future) | `aws.network.tgw.pattern` |
| **VPN** | ✓ VPN connections | ✓ vpn-tunnels | ✓ vnet-gateway | `*.network.vpn.pattern` |
| **Hybrid (on-prem)** | ✓ Direct Connect | ✓ Interconnect | ✓ ExpressRoute | `*.network.hybrid.pattern` |
| **Private endpoints** | ✓ VPC endpoints / PrivateLink | PSC (partial / related_ids) | ✓ Private Endpoints | `*.network.endpoint.pattern` (aws/azure) |
| **NAT** | ✓ NAT GW | ✓ Cloud NAT on routers | ✓ NAT gateway | `*.network.nat.pattern` |
| **Internet GW** | ✓ IGW | default internet route | default | `aws.network.igw.pattern` |
| **Network share** | RAM (future deep) | ✓ Shared VPC assoc | subscription share (future) | `gcp.network.share.pattern` |
| **Prefix lists** | ✓ managed prefix lists | — | IP groups (future) | `aws.network.prefix_list.pattern` |
| **Broad fabric** | ✓ | ✓ | ✓ | `*.network.service.pattern` |
| Functions | ✓ Lambda | ✓ CF + Cloud Run | ✓ Function Apps | `*.compute.function.pattern` |
| Path analyze | ✓ Reachability | ✓ Connectivity Test | ✓ NW troubleshoot | path / connectivity tools |

## Agent usage

```
1. aws|gcp|azure.network.inventory.sync   # fill services[]
2. network.pattern.find / *.network.service.pattern   # broad
3. *.network.peering|vpn|hybrid|endpoint|nat|tgw.pattern   # narrow
4. path.analyze / connectivity.test if needed
```

## ResourceKind values (hits)

`peering`, `transit_gateway`, `vpn`, `hybrid_connection`, `private_endpoint`, `nat_gateway`, `internet_gateway`, `network_share`, `prefix_list` (+ existing vpc/subnet/route/…).

## Find → troubleshoot → mutate

| Intent | Mode | Tools |
|--------|------|--------|
| **Find** | Read | `*.pattern*`, inventory.sync, ip.locate |
| **Troubleshoot** | Read | path.analyze, connectivity.test, next_hop, playbook, node.*, mesh.envoy.*, access.troubleshoot |
| **Add / change** | **Write** | `*.network.*.create`, SG authorize, route create, peering create/accept, endpoint create, DNS record create |
| **Delete / revoke** | **Write** | `*.network.*.delete`, SG revoke, route delete, peering delete, endpoint delete, DNS record delete |

### Mode control (hard)

- Session **readonly** (default): only `Capability::Read` tools execute.
- Session **readwrite**: Read + Write.
- Enforced in `ToolRegistry::execute` → `oscar_mode::check_capability` → `ModeDenied` if write under readonly.
- Write tool descriptions include: *Requires session mode readwrite*.

## Gaps / next

- AWS RAM resource shares (explicit list) + NAT create (costly; intentional omit)
- GCP Private Service Connect service attachments
- Azure Virtual WAN hubs / Private Endpoint create (complex ARM)
- TGW route tables / attachments as first-class rows
- Load balancers in inventory (kind exists)
