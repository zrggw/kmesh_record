# Istio

## sidecar
Benefits of deploying a sidecar
1. Decoupling and centralized management
2. Network policies and traffic control
3. Enhanced security
4. Improved observability
5. Support for heterogeneous, multi-language environments
6. Extensible flexibility

**How the proxy is implemented**
1. Transparent proxy: the sidecar runs in the same pod and network namespace as the application container. The sidecar intercepts the application traffic via `iptables`, forwards it into the sidecar container, and the sidecar then handles the traffic.
2. For outbound traffic, `iptables` redirects the application container traffic into the sidecar, so both the source and destination IPs appear to be the sidecar's IP.


### Envoy
Envoy acts as both an edge proxy and a service proxy. As a service proxy it can play two roles: 1. a cluster ingress / API gateway; 2. a sidecar that intercepts and manages east-west traffic inside the mesh.
**Fundamental concepts**
- "Listener": the port that Envoy listens on to accept downstream (client) connections. The Listener configuration / discovery service is LDS.
- "Cluster": each upstream service that Envoy connects to is modeled as a Cluster. Cluster configuration / discovery is handled by CDS. When a Cluster uses EDS, its endpoints are delivered by xDS rather than DNS. The service that delivers endpoints is called EDS.
- "Router": the listener accepts connections from downstream, and the router decides which Cluster should handle the traffic after the connection/data is received. Routers define the forwarding rules. Router configuration/discovery is RDS.
- "Filter": conceptually a plugin that provides extensibility. All filter configurations are embedded in LDS, CDS, and RDS.
`xDS` refers to Envoy's configuration and service discovery system, encompassing LDS, CDS, EDS, and RDS. Envoy consumes runtime configuration via the xDS APIs.

#### Envoy filter chain
Envoy processes traffic through a series of filters chained together into a Filter Chain.

**Key terms**
- **Listener**: listens on a specific network port. A sidecar typically contains two listeners: one for inbound traffic and one for outbound traffic.
- **Filter**: the basic unit in the chain that performs a concrete task such as protocol parsing, routing, or authentication.
    - **Network Filters**: handle L3/L4 traffic such as TCP connection management or TLS termination.
    - **HTTP Filters**: handle L7 traffic like HTTP routing, request/response transformation, etc.
- **Filter Chain**: a listener can have multiple filter chains, each containing multiple filters. Envoy selects the appropriate chain based on destination port, IP, SNI, etc.

#### Incremental xDS
The discoveryResponse sent by the Envoy control plane is traditionally a full snapshot containing every resource, which creates unnecessary traffic. Since a sidecar does not know in advance which services it needs, it ends up tracking metadata for every mesh service even though most applications only talk to a few targets. With delta xDS, Envoy only sends the resources that actually changed during each update.
**Three features enabled by delta xDS**
1. **Lazy Loading**: subscribe to a resource only when it is first needed, fetching the configuration on-demand. Initial access may have a small latency penalty.
2. **Incremental Updates**: update only the resources that changed instead of refreshing everything, reducing bandwidth usage.
3. **Cache eviction**: dynamically adjust the resource subscriptions set based on actual traffic. Remove inactive resources from Envoy's memory to save RAM at very large scale.

## Other
## RBAC permission model
Three core concepts: **users**, **roles**, **permissions**
#### RBAC model variants
**RBAC0**: the basic model where users and roles have many-to-many relationships and roles and permissions are also many-to-many.
**RBAC1**: builds on RBAC0 by introducing role hierarchies, allowing roles to inherit from one another.
**RBAC2**: adds constraints among users, roles, and permissions, enabling both static and dynamic separation of duties.
**RBAC3**: a combination of RBAC1 and RBAC2.

## ambient

### waypoint
Waypoint is used for L7 proxying. Istio's official documentation explains it in depth: [Istio Waypoint](https://istio.io/latest/zh/docs/ambient/usage/waypoint/)

