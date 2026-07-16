//! Comprehensive local tests for the real libp2p transport (spec §4).
//!
//! These stand up **actual libp2p swarms on `127.0.0.1`** and drive real [`Node`]s over them —
//! not the in-process fabric. The headline test proves a real, HPKE-sealed MOTE crosses a real
//! libp2p swarm (TCP + Noise + Yamux), is decrypted by the receiver, and the delivery `ack`
//! travels back over the same connection until the sender's queue reaches `ACKED`. A second test
//! exercises a Kademlia PUT/GET of a `LocationRecord`-shaped value (§4.2 `key → location`).
//!
//! Scope is honest: this is **loopback** — both peers are directly reachable, so the relay + DCUtR
//! NAT-traversal path (wired and live in the swarm) is not exercised end-to-end here.

use super::*;
use dmtap::identity::IdentityKey;
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::outbound::OutState;

/// A generous loopback timeout: real dialing + Noise handshake + Yamux + request-response take
/// tens of ms, occasionally more under load; poll loops below spin up to this bound.
const SPIN: Duration = Duration::from_secs(15);

/// Take the first TCP listen multiaddr the transport has bound (waits for it to appear).
fn tcp_listener(t: &Libp2pTransport) -> Multiaddr {
    let ls = t.wait_for_listener(SPIN);
    ls.into_iter()
        .find(|a| a.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_))))
        .expect("a bound TCP listen addr")
}

/// Poll `node` (draining the live swarm inbox) until `pred` holds or `SPIN` elapses.
fn poll_until<T: Transport>(node: &mut Node<T>, mut pred: impl FnMut(&Node<T>) -> bool) -> bool {
    let deadline = std::time::Instant::now() + SPIN;
    loop {
        node.poll();
        if pred(node) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return pred(node);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn builds_and_listens() {
    let t = Libp2pTransport::new(b"node".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
        .unwrap();
    assert!(!t.wait_for_listener(SPIN).is_empty(), "should bind a listen addr");
}

/// THE milestone test: two real libp2p nodes on loopback exchange a real sealed MOTE + ack.
#[test]
fn two_real_libp2p_nodes_exchange_sealed_mote_and_ack() {
    // Real DMTAP identities + sealing keys for both nodes.
    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal_pub = *alice_seal.public();

    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();

    // Two real libp2p swarms, each bound to an ephemeral loopback TCP port.
    let alice_tp =
        Libp2pTransport::new(alice_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .unwrap();
    let bob_tp =
        Libp2pTransport::new(bob_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .unwrap();

    // Alice learns how to reach Bob (his PeerId + a dialable multiaddr) — the §4.2 record stand-in.
    // Bob will AUTO-LEARN Alice from her inbound frame, so the ack routes back with no lookup.
    let bob_addr = tcp_listener(&bob_tp);
    alice_tp.add_peer(bob_ik_pub.clone(), bob_tp.peer_id(), bob_addr);

    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_tp);
    let mut bob = Node::with_identity(bob_ik, bob_seal, bob_tp);
    alice.add_contact(&bob_ik_pub, bob_seal_pub);
    bob.add_contact(&alice_ik_pub, alice_seal_pub);

    // Alice seals + dispatches a real MOTE onto the swarm.
    let secret = b"a real MOTE crossing a real libp2p swarm";
    let id = alice.send_mail(&bob_ik_pub, "hello over libp2p", secret).expect("send");
    assert_eq!(alice.outbound_state(&id), Some(OutState::InFlight), "handed to the swarm");

    // Bob receives it off the wire, runs §2.7 validation, decrypts, stores.
    assert!(
        poll_until(&mut bob, |b| b.inbox().exists() == 1),
        "the sealed MOTE should arrive + decrypt over libp2p"
    );
    let outcomes = bob.poll();
    let _ = outcomes; // dispositions already asserted via inbox growth above.
    let raw = &bob.inbox().messages[0].raw;
    assert!(
        raw.windows(secret.len()).any(|w| w == secret),
        "the decrypted plaintext round-trips over the real swarm"
    );

    // The ack travels back over the same connection until Alice's queue reaches ACKED.
    assert!(
        poll_until(&mut alice, |a| a.outbound_state(&id) == Some(OutState::Acked)),
        "the ack returns over libp2p and the sender queue reaches ACKED"
    );
}

/// Prove the sender-retry contract holds on the real transport: an unresolved peer is `Unreachable`
/// (drives §20.1 `RETRY`), and once its route is learned a re-dispatch reaches `ACKED`.
#[test]
fn unknown_peer_is_unreachable_then_reachable_after_learning_route() {
    let alice_ik = IdentityKey::generate();
    let alice_seal = SealKeypair::generate();
    let alice_ik_pub = alice_ik.public();
    let alice_seal_pub = *alice_seal.public();

    let bob_ik = IdentityKey::generate();
    let bob_seal = SealKeypair::generate();
    let bob_ik_pub = bob_ik.public();
    let bob_seal_pub = *bob_seal.public();

    let alice_tp =
        Libp2pTransport::new(alice_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .unwrap();
    let bob_tp =
        Libp2pTransport::new(bob_ik_pub.clone(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
            .unwrap();
    let bob_addr = tcp_listener(&bob_tp);
    let bob_peer = bob_tp.peer_id();

    // Capture a control handle before Alice's transport is moved into her Node, so we can teach her
    // the route at runtime (mid-flight route learning, §4.2/§20.1).
    let alice_route = alice_tp.handle();

    let mut alice = Node::with_identity(alice_ik, alice_seal, alice_tp);
    let mut bob = Node::with_identity(bob_ik, bob_seal, bob_tp);
    alice.add_contact(&bob_ik_pub, bob_seal_pub);
    bob.add_contact(&alice_ik_pub, alice_seal_pub);

    // No route yet ⇒ the transport reports the peer unreachable ⇒ the entry parks in RETRY (§20.1).
    let id = alice.send_mail(&bob_ik_pub, "before route", b"queued while unreachable").unwrap();
    assert_eq!(alice.outbound_state(&id), Some(OutState::Retry), "unreachable ⇒ RETRY");

    // Learn the route and re-fire the retry timer: the same immutable MOTE now reaches ACKED.
    alice_route.add_peer(bob_ik_pub.clone(), bob_peer, bob_addr);
    alice.retry_pending();
    assert!(
        poll_until(&mut bob, |b| b.inbox().exists() == 1),
        "the retried MOTE arrives once the route is known"
    );
    bob.poll();
    assert!(
        poll_until(&mut alice, |a| a.outbound_state(&id) == Some(OutState::Acked)),
        "retry ⇒ delivered ⇒ ACKED over libp2p"
    );
}

/// Kademlia PUT/GET of a signed-`LocationRecord`-shaped value across two connected DHT nodes
/// (§4.2 `key → location`). Node A stores the record under `hash(ik)`; node B resolves it.
#[test]
fn kademlia_put_get_location_record() {
    let a = Libp2pTransport::new(b"kad-a".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
        .unwrap();
    let b = Libp2pTransport::new(b"kad-b".to_vec(), &["/ip4/127.0.0.1/tcp/0".parse().unwrap()])
        .unwrap();
    let a_addr = tcp_listener(&a);
    let b_addr = tcp_listener(&b);

    // Introduce the two nodes to each other's routing tables (the DHT is not self-forming on
    // loopback; a fresh contact needs a non-DHT bootstrap path, §4.2).
    a.add_peer(b"kad-b".to_vec(), b.peer_id(), b_addr);
    b.add_peer(b"kad-a".to_vec(), a.peer_id(), a_addr);
    // Give identify/connection a moment so the buckets are populated before the query.
    std::thread::sleep(Duration::from_millis(300));

    // A location record keyed by (a stand-in for) hash(ik).
    let key = b"loc:00112233445566778899aabbccddeeff";
    let record = b"LocationRecord{peer_id,addrs,seq,ttl,sig}";
    assert!(a.kad_put(key, record), "PUT should store on >=1 peer");

    // B resolves the same key from the DHT.
    let got = b.kad_get(key);
    assert_eq!(got.as_deref(), Some(&record[..]), "B resolves the record A published");
}
