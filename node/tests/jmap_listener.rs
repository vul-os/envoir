//! Integration tests for the node-native **JMAP** listener (spec §8.1).
//!
//! These drive the real surface end-to-end over a real TCP socket: a client authenticates with an
//! app-password (spec §8.2) and runs `Session` / `Mailbox/get` / `Email/query` + `Email/get` against
//! a node whose INBOX holds a **genuinely delivered MOTE** (Alice → Bob over the in-memory mesh, Bob
//! validates + decrypts + stores it, §2.7). The client therefore sees the node's *live* mail, not a
//! fresh empty store. A bad app-password is rejected fail-closed with a Basic challenge.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dmtap::identity::IdentityKey;
use dmtap::inbound::InboundOutcome;
use dmtap::jmap_api::{run_loop_with_apis, JmapApi};
use dmtap::mote::SealKeypair;
use dmtap::node::Node;
use dmtap::transport::{InMemoryNetwork, InMemoryTransport};

use dmtap_mail::jmap::{CAP_CORE, CAP_MAIL};
use dmtap_mail::util::base64_encode;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ACCOUNT: &str = "bob@dmtap.local";
const APP_PW: &str = "device-app-password";

fn make_node(net: &InMemoryNetwork) -> (Node<InMemoryTransport>, Vec<u8>, [u8; 32]) {
    let ik = IdentityKey::generate();
    let seal = SealKeypair::generate();
    let ik_pub = ik.public();
    let seal_pub = *seal.public();
    let transport = net.endpoint(ik_pub.clone());
    (Node::with_identity(ik, seal, transport), ik_pub, seal_pub)
}

/// Basic auth header value for `user:pass`.
fn basic(user: &str, pass: &str) -> String {
    format!("Basic {}", base64_encode(format!("{user}:{pass}").as_bytes()))
}

/// One HTTP/1.1 request→response round trip over a fresh `Connection: close` socket. Returns the
/// status code and the response body bytes.
async fn roundtrip(
    addr: SocketAddr,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    if let Some(a) = auth {
        head.push_str(&format!("Authorization: {a}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();

    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("response has a header/body split");
    let head = String::from_utf8_lossy(&buf[..split]);
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .expect("status line");
    (status, buf[split + 4..].to_vec())
}

#[tokio::test]
async fn client_authenticates_and_reads_genuinely_delivered_mail_over_tcp() {
    // --- 1. Deliver a REAL end-to-end-encrypted MOTE from Alice to Bob over the mesh. -----------
    let net = InMemoryNetwork::new();
    let (mut alice, alice_ik, alice_seal) = make_node(&net);
    let (mut bob, bob_ik, bob_seal) = make_node(&net);
    alice.add_contact(&bob_ik, bob_seal);
    bob.add_contact(&alice_ik, alice_seal);

    let secret = b"the JMAP client must see this exact delivered plaintext";
    alice.send_mail(&bob_ik, "Delivered over the mesh", secret).expect("send");
    let outcomes = bob.poll();
    assert!(matches!(outcomes[0], InboundOutcome::Stored { .. }), "Bob stored the MOTE");
    assert_eq!(bob.inbox().exists(), 1, "the live store holds the delivered MOTE");

    // --- 2. Bind the node-native JMAP listener over Bob's LIVE store. ---------------------------
    let jmap = JmapApi::new(
        ACCOUNT,
        "http://127.0.0.1", // base URL is cosmetic for this test
        bob_ik.clone(),
        &[(ACCOUNT.to_string(), APP_PW.to_string())],
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // --- 3. A client task: bad password rejected, then a full Session + Mailbox + Email flow. ---
    // (A plain atomic flag drives shutdown — the node crate's tokio has no `sync` feature.)
    let done = Arc::new(AtomicBool::new(false));
    let done_client = done.clone();
    let client = tokio::spawn(async move {
        let mut out = Vec::new();

        // Bad app-password → 401 fail-closed.
        let (st, _b) = roundtrip(addr, "GET", "/jmap/session", Some(&basic(ACCOUNT, "WRONG")), b"").await;
        out.push(("bad_pw".to_string(), st, Vec::new()));

        // No credential at all → 401.
        let (st, _b) = roundtrip(addr, "GET", "/jmap/session", None, b"").await;
        out.push(("no_pw".to_string(), st, Vec::new()));

        let auth = basic(ACCOUNT, APP_PW);

        // Session/get.
        let (st, body) = roundtrip(addr, "GET", "/jmap/session", Some(&auth), b"").await;
        out.push(("session".to_string(), st, body));

        // Mailbox/get.
        let req = json!({
            "using": [CAP_CORE, CAP_MAIL],
            "methodCalls": [["Mailbox/get", { "accountId": ACCOUNT, "ids": null }, "m"]]
        });
        let (st, body) = roundtrip(addr, "POST", "/jmap/api/", Some(&auth), &serde_json::to_vec(&req).unwrap()).await;
        out.push(("mailbox".to_string(), st, body));

        // Email/query → Email/get (chained via back-reference).
        let req = json!({
            "using": [CAP_MAIL],
            "methodCalls": [
                ["Email/query", { "accountId": ACCOUNT, "filter": { "inMailbox": "INBOX" } }, "q"],
                ["Email/get", { "accountId": ACCOUNT, "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" } }, "g"]
            ]
        });
        let (st, body) = roundtrip(addr, "POST", "/jmap/api/", Some(&auth), &serde_json::to_vec(&req).unwrap()).await;
        out.push(("email".to_string(), st, body));

        done_client.store(true, Ordering::SeqCst);
        out
    });

    // --- 4. Run the daemon serve loop (JMAP only) until the client is done. ---------------------
    run_loop_with_apis(
        &mut bob,
        None,
        None,
        Some(&jmap),
        Some(listener),
        Duration::from_millis(5),
        async {
            while !done.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        },
    )
    .await;
    let results = client.await.unwrap();

    // --- 5. Assertions. ------------------------------------------------------------------------
    let get = |name: &str| results.iter().find(|(n, _, _)| n == name).unwrap();

    assert_eq!(get("bad_pw").1, 401, "a bad app-password is rejected fail-closed");
    assert_eq!(get("no_pw").1, 401, "a missing credential is rejected fail-closed");

    let (_, st, body) = get("session");
    assert_eq!(*st, 200);
    let session: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(session["primaryAccounts"][CAP_MAIL], json!(ACCOUNT));
    assert!(session["apiUrl"].as_str().unwrap().ends_with("/jmap/api/"));

    let (_, st, body) = get("mailbox");
    assert_eq!(*st, 200);
    let mailbox: Value = serde_json::from_slice(body).unwrap();
    let inbox = mailbox["methodResponses"][0][1]["list"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == json!("INBOX"))
        .expect("INBOX present");
    assert_eq!(inbox["totalEmails"], json!(1), "the live INBOX shows the delivered MOTE");

    let (_, st, body) = get("email");
    assert_eq!(*st, 200);
    let email: Value = serde_json::from_slice(body).unwrap();
    let msg = &email["methodResponses"][1][1]["list"][0];
    assert_eq!(msg["subject"], json!("Delivered over the mesh"));
    // The exact delivered plaintext is visible to the JMAP client — proof it is the live store.
    let preview = msg["preview"].as_str().unwrap_or("");
    let body_val = msg["bodyValues"]["1"]["value"].as_str().unwrap_or("");
    let secret_str = std::str::from_utf8(secret).unwrap();
    assert!(
        preview.contains(secret_str) || body_val.contains(secret_str),
        "the JMAP client sees the exact delivered plaintext; preview={preview:?} body={body_val:?}"
    );
}
