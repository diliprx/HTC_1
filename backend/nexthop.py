"""
HTC NetFlow Analyzer Pro — Layer-2 Next-Hop Resolver
====================================================
Raw packet captures carry no NetFlow 'nexthop' field, so the routing hop of
each outbound flow is derived from the Ethernet header instead: the
destination MAC of a private -> public packet is the router that forwards it.
Router MACs are resolved to IPs from ARP traffic, or from packets the router
sends with its own IP. A MAC that cannot be resolved is kept as 'mac:<addr>'
so that hosts egressing through an unknown router are still reported.
"""

from collections import Counter

NO_NEXTHOP = "0.0.0.0"


def _octets(ip_str):
    try:
        p = list(map(int, ip_str.split('.')))
        return p if len(p) == 4 else None
    except (AttributeError, ValueError):
        return None


def is_private_ip(ip_str):
    """RFC1918 + loopback (same definition as analyzer._is_private_sql)."""
    p = _octets(ip_str)
    return bool(p) and (p[0] == 10 or p[0] == 127
                        or (p[0] == 192 and p[1] == 168)
                        or (p[0] == 172 and 16 <= p[1] <= 31))


def is_public_ip(ip_str):
    """Routable unicast outside RFC1918: excludes 0/8, loopback, link-local,
    multicast, reserved and broadcast (same as analyzer._is_public_sql)."""
    p = _octets(ip_str)
    return bool(p) and not is_private_ip(ip_str) and not (
        p[0] == 0 or p[0] >= 224 or (p[0] == 169 and p[1] == 254))


def fmt_mac(raw):
    if isinstance(raw, (bytes, bytearray)):
        return ':'.join(f'{b:02x}' for b in raw)
    return str(raw).lower() if raw else None


class NextHopResolver:
    def __init__(self):
        self.arp = {}        # mac -> ip learned from ARP
        self.host_ips = {}   # mac -> Counter of private IPs seen using that MAC as their own
        self.egress_srcs = set()
        self.egress_dsts = set()

    def learn_arp(self, mac, ip):
        if mac and ip and ip != NO_NEXTHOP:
            self.arp[mac] = ip

    def learn_packet(self, src_mac, dst_mac, src_ip, dst_ip):
        if src_mac and is_private_ip(src_ip):
            self.host_ips.setdefault(src_mac, Counter())[src_ip] += 1
        if dst_mac and is_private_ip(dst_ip):
            self.host_ips.setdefault(dst_mac, Counter())[dst_ip] += 1
        if src_mac and dst_mac and is_private_ip(src_ip) and is_public_ip(dst_ip):
            self.egress_srcs.add(src_mac)
            self.egress_dsts.add(dst_mac)

    def resolve(self, mac):
        if mac in self.arp:
            return self.arp[mac]
        if mac in self.host_ips:
            return self.host_ips[mac].most_common(1)[0][0]
        return f"mac:{mac}"

    def nexthop(self, src_mac, dst_mac, src_ip, dst_ip):
        """Next hop of an outbound (private -> public) packet; NO_NEXTHOP otherwise."""
        if not (dst_mac and is_private_ip(src_ip) and is_public_ip(dst_ip)):
            return NO_NEXTHOP
        # Packets originated by a router itself (its MAC is also an egress hop
        # for other hosts) are not forwarded traffic, so they get no next hop.
        if src_mac in self.egress_dsts:
            return NO_NEXTHOP
        return self.resolve(dst_mac)
