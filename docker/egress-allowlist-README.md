# Aspirational RPC egress allowlist

This is a design sketch for the manual-only Docker container. The
repository does not provision the network or enforce an RPC egress
allowlist. The host subprocess is the only supported ForgeRunner path.

`--network=shadow-strike-egress` in the Dockerfile's run example refers
to a Docker network with an egress firewall rule allowing DNS + HTTPS
to exactly one host: the RPC provider named in `MAINNET_RPC_URL` for
that run. This is NOT configured by the Dockerfile itself (Docker has
no first-class "allow only this host" primitive) — set it up once with
your platform's firewall / iptables / cloud security-group equivalent,
or terminate it at an egress proxy the container is forced through.

Minimum viable version (iptables, run once per host):

    iptables -N shadow-strike-egress
    iptables -A shadow-strike-egress -d <RPC_PROVIDER_IP> -j ACCEPT
    iptables -A shadow-strike-egress -j DROP
    # attach this chain to the container's network namespace via your
    # container runtime's standard mechanism (Docker network + a
    # firewalld/iptables rule keyed to the bridge interface, or a
    # dedicated egress proxy sidecar if running on Kubernetes).

This file documents the requirement; it does not implement the
platform-specific firewall rule, since that genuinely differs between
bare Docker, Kubernetes, and each cloud provider.
