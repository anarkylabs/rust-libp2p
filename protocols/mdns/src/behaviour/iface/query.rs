// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    borrow::Cow,
    fmt,
    net::{Ipv6Addr, SocketAddr},
    str,
    time::{Duration, Instant},
};

use hickory_proto::{
    op::Message,
    rr::{Name, RData},
};
use libp2p_core::multiaddr::{Multiaddr, Protocol};
use libp2p_identity::PeerId;
use libp2p_swarm::_address_translation;

use super::dns;
use crate::{META_QUERY_SERVICE_FQDN, SERVICE_NAME_FQDN};

/// A valid mDNS packet received by the service.
#[derive(Debug)]
pub(crate) enum MdnsPacket {
    /// A query made by a remote.
    Query(MdnsQuery),
    /// A response sent by a remote in response to one of our queries.
    Response(MdnsResponse),
    /// A request for service discovery.
    ServiceDiscovery(MdnsServiceDiscovery),
}

impl MdnsPacket {
    pub(crate) fn new_from_bytes(
        buf: &[u8],
        from: SocketAddr,
    ) -> Result<Option<MdnsPacket>, hickory_proto::ProtoError> {
        let packet = Message::from_vec(buf)?;

        if packet.query().is_none() {
            return Ok(Some(MdnsPacket::Response(MdnsResponse::new(&packet, from))));
        }

        if packet
            .queries()
            .iter()
            .any(|q| q.name().to_utf8() == SERVICE_NAME_FQDN)
        {
            return Ok(Some(MdnsPacket::Query(MdnsQuery {
                from,
                query_id: packet.header().id(),
            })));
        }

        if packet
            .queries()
            .iter()
            .any(|q| q.name().to_utf8() == META_QUERY_SERVICE_FQDN)
        {
            // TODO: what if multiple questions,
            // one with SERVICE_NAME and one with META_QUERY_SERVICE?
            return Ok(Some(MdnsPacket::ServiceDiscovery(MdnsServiceDiscovery {
                from,
                query_id: packet.header().id(),
            })));
        }

        Ok(None)
    }
}

/// A received mDNS query.
pub(crate) struct MdnsQuery {
    /// Sender of the address.
    from: SocketAddr,
    /// Id of the received DNS query. We need to pass this ID back in the results.
    query_id: u16,
}

impl MdnsQuery {
    /// Source address of the packet.
    pub(crate) fn remote_addr(&self) -> &SocketAddr {
        &self.from
    }

    /// Query id of the packet.
    pub(crate) fn query_id(&self) -> u16 {
        self.query_id
    }
}

impl fmt::Debug for MdnsQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MdnsQuery")
            .field("from", self.remote_addr())
            .field("query_id", &self.query_id)
            .finish()
    }
}

/// A received mDNS service discovery query.
pub(crate) struct MdnsServiceDiscovery {
    /// Sender of the address.
    from: SocketAddr,
    /// Id of the received DNS query. We need to pass this ID back in the results.
    query_id: u16,
}

impl MdnsServiceDiscovery {
    /// Source address of the packet.
    pub(crate) fn remote_addr(&self) -> &SocketAddr {
        &self.from
    }

    /// Query id of the packet.
    pub(crate) fn query_id(&self) -> u16 {
        self.query_id
    }
}

impl fmt::Debug for MdnsServiceDiscovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MdnsServiceDiscovery")
            .field("from", self.remote_addr())
            .field("query_id", &self.query_id)
            .finish()
    }
}

/// A received mDNS response.
pub(crate) struct MdnsResponse {
    peers: Vec<MdnsPeer>,
    from: SocketAddr,
}

impl MdnsResponse {
    /// Creates a new `MdnsResponse` based on the provided `Packet`.
    pub(crate) fn new(packet: &Message, from: SocketAddr) -> MdnsResponse {
        let peers = packet
            .answers()
            .iter()
            .filter_map(|record| {
                if record.name().to_string() != SERVICE_NAME_FQDN {
                    return None;
                }

                let RData::PTR(record_value) = record.data() else {
                    return None;
                };

                MdnsPeer::new(packet, record_value, record.ttl())
            })
            .collect();

        MdnsResponse { peers, from }
    }

    pub(crate) fn extract_discovered(
        &self,
        now: Instant,
        local_peer_id: PeerId,
    ) -> impl Iterator<Item = (PeerId, Multiaddr, Instant)> + '_ {
        self.discovered_peers()
            .filter(move |peer| peer.id() != &local_peer_id)
            .flat_map(move |peer| {
                let observed = self.observed_address();
                let new_expiration = now + peer.ttl();

                peer.addresses().iter().filter_map(move |address| {
                    if !same_ip_family(address, &observed) {
                        return None;
                    }
                    let new_addr = _address_translation(address, &observed)?;
                    let new_addr = add_ipv6_zone(new_addr, self.remote_addr());
                    let new_addr = new_addr.with_p2p(*peer.id()).ok()?;

                    Some((*peer.id(), new_addr, new_expiration))
                })
            })
    }

    /// Source address of the packet.
    pub(crate) fn remote_addr(&self) -> &SocketAddr {
        &self.from
    }

    fn observed_address(&self) -> Multiaddr {
        // We replace the IP address with the address we observe the
        // remote as and the address they listen on.
        let obs_ip = Protocol::from(self.remote_addr().ip());
        let obs_port = Protocol::Udp(self.remote_addr().port());

        Multiaddr::empty().with(obs_ip).with(obs_port)
    }

    /// Returns the list of peers that have been reported in this packet.
    ///
    /// > **Note**: Keep in mind that this will also contain the responses we sent ourselves.
    fn discovered_peers(&self) -> impl Iterator<Item = &MdnsPeer> {
        self.peers.iter()
    }
}

/// Return whether two addresses can be translated without changing IP family.
///
/// mDNS receives responses per network family and interface. Translating an
/// advertised IPv4 listen address through an observed IPv6 packet source, or
/// vice versa, manufactures cross-family addresses that combine one socket's IP
/// with another socket's port. Keep translations family-preserving so peers dial
/// addresses that correspond to a real listener.
fn same_ip_family(address: &Multiaddr, observed: &Multiaddr) -> bool {
    match (address.iter().next(), observed.iter().next()) {
        (Some(Protocol::Ip4(_)), Some(Protocol::Ip4(_)))
        | (Some(Protocol::Ip6(_)), Some(Protocol::Ip6(_))) => true,
        (Some(Protocol::Ip4(_)), Some(Protocol::Ip6(_)))
        | (Some(Protocol::Ip6(_)), Some(Protocol::Ip4(_))) => false,
        _ => true,
    }
}

/// Add an `ip6zone` component to discovered link-local IPv6 addresses.
///
/// mDNS responses only carry the peer's IP and port. For `fe80::/10`
/// link-local addresses that is not enough to dial: the same address can exist
/// on multiple interfaces, so the OS also needs a scope id. The UDP socket that
/// received the response has that scope id, so preserve it in the multiaddr.
fn add_ipv6_zone(addr: Multiaddr, remote_addr: &SocketAddr) -> Multiaddr {
    let SocketAddr::V6(remote_addr) = remote_addr else {
        return addr;
    };
    let scope_id = remote_addr.scope_id();
    if scope_id == 0 {
        return addr;
    }

    let mut scoped = Multiaddr::empty();
    let mut added_zone = false;
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip6(ip) if is_ipv6_link_local(&ip) && !added_zone => {
                scoped.push(Protocol::Ip6(ip));
                scoped.push(Protocol::Ip6zone(Cow::Owned(scope_id.to_string())));
                added_zone = true;
            }
            Protocol::Ip6zone(_) => {}
            other => scoped.push(other),
        }
    }

    scoped
}

/// Return whether an address is in `fe80::/10`, the IPv6 link-local prefix.
fn is_ipv6_link_local(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

impl fmt::Debug for MdnsResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MdnsResponse")
            .field("from", self.remote_addr())
            .finish()
    }
}

/// A peer discovered by the service.
pub(crate) struct MdnsPeer {
    addrs: Vec<Multiaddr>,
    /// Id of the peer.
    peer_id: PeerId,
    /// TTL of the record in seconds.
    ttl: u32,
}

impl MdnsPeer {
    /// Creates a new `MdnsPeer` based on the provided `Packet`.
    pub(crate) fn new(packet: &Message, record_value: &Name, ttl: u32) -> Option<MdnsPeer> {
        let mut my_peer_id: Option<PeerId> = None;
        let addrs = packet
            .additionals()
            .iter()
            .filter_map(|add_record| {
                if add_record.name() != record_value {
                    return None;
                }

                if let RData::TXT(ref txt) = add_record.data() {
                    Some(txt)
                } else {
                    None
                }
            })
            .flat_map(|txt| txt.iter())
            .filter_map(|txt| {
                // TODO: wrong, txt can be multiple character strings
                let addr = dns::decode_character_string(txt).ok()?;

                if !addr.starts_with(b"dnsaddr=") {
                    return None;
                }

                let mut addr = str::from_utf8(&addr[8..]).ok()?.parse::<Multiaddr>().ok()?;

                match addr.pop() {
                    Some(Protocol::P2p(peer_id)) => {
                        if let Some(pid) = &my_peer_id {
                            if peer_id != *pid {
                                return None;
                            }
                        } else {
                            my_peer_id.replace(peer_id);
                        }
                    }
                    _ => return None,
                };
                Some(addr)
            })
            .collect();

        my_peer_id.map(|peer_id| MdnsPeer {
            addrs,
            peer_id,
            ttl,
        })
    }

    /// Returns the id of the peer.
    #[inline]
    pub(crate) fn id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Returns the requested time-to-live for the record.
    #[inline]
    pub(crate) fn ttl(&self) -> Duration {
        Duration::from_secs(u64::from(self.ttl))
    }

    /// Returns the list of addresses the peer says it is listening on.
    ///
    /// Filters out invalid addresses.
    pub(crate) fn addresses(&self) -> &Vec<Multiaddr> {
        &self.addrs
    }
}

impl fmt::Debug for MdnsPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MdnsPeer")
            .field("peer_id", &self.peer_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{super::dns::build_query_response, *};

    #[test]
    fn test_create_mdns_peer() {
        let ttl = 300;
        let peer_id = PeerId::random();

        let mut addr1: Multiaddr = "/ip4/1.2.3.4/tcp/5000".parse().expect("bad multiaddress");
        let mut addr2: Multiaddr = "/ip6/::1/udp/10000".parse().expect("bad multiaddress");
        addr1.push(Protocol::P2p(peer_id));
        addr2.push(Protocol::P2p(peer_id));

        let packets = build_query_response(
            0xf8f8,
            peer_id,
            vec![&addr1, &addr2].into_iter(),
            Duration::from_secs(60),
        );

        for bytes in packets {
            let packet = Message::from_vec(&bytes).expect("unable to parse packet");
            let record_value = packet
                .answers()
                .iter()
                .filter_map(|record| {
                    if record.name().to_utf8() != SERVICE_NAME_FQDN {
                        return None;
                    }
                    let RData::PTR(record_value) = record.data() else {
                        return None;
                    };
                    Some(record_value)
                })
                .next()
                .expect("empty record value");

            let peer = MdnsPeer::new(&packet, record_value, ttl).expect("fail to create peer");
            assert_eq!(peer.peer_id, peer_id);
        }
    }

    #[test]
    fn adds_ipv6_zone_to_link_local_addresses() {
        let addr: Multiaddr = "/ip6/fe80::1/udp/1234/quic-v1"
            .parse()
            .expect("bad multiaddress");
        let remote_addr = "[fe80::2%42]:5353".parse().expect("bad socket address");

        assert_eq!(
            add_ipv6_zone(addr, &remote_addr),
            "/ip6/fe80::1/ip6zone/42/udp/1234/quic-v1"
                .parse()
                .expect("bad multiaddress")
        );
    }

    #[test]
    fn does_not_add_ipv6_zone_to_global_addresses() {
        let addr: Multiaddr = "/ip6/2001:db8::1/udp/1234/quic-v1"
            .parse()
            .expect("bad multiaddress");
        let remote_addr = "[fe80::2%42]:5353".parse().expect("bad socket address");

        assert_eq!(
            add_ipv6_zone(addr, &remote_addr),
            "/ip6/2001:db8::1/udp/1234/quic-v1"
                .parse()
                .expect("bad multiaddress")
        );
    }

    #[test]
    fn only_translates_observed_address_with_same_ip_family() {
        let peer_id = PeerId::random();
        let response = MdnsResponse {
            peers: vec![MdnsPeer {
                addrs: vec![
                    "/ip4/0.0.0.0/udp/1000/quic-v1"
                        .parse()
                        .expect("bad multiaddress"),
                    "/ip6/::/udp/2000/quic-v1"
                        .parse()
                        .expect("bad multiaddress"),
                ],
                peer_id,
                ttl: 60,
            }],
            from: "[fe80::2%42]:5353".parse().expect("bad socket address"),
        };

        let discovered = response
            .extract_discovered(Instant::now(), PeerId::random())
            .map(|(_, addr, _)| addr)
            .collect::<Vec<_>>();

        assert_eq!(
            discovered,
            vec![
                format!("/ip6/fe80::2/ip6zone/42/udp/2000/quic-v1/p2p/{peer_id}")
                    .parse()
                    .expect("bad multiaddress")
            ]
        );
    }
}
