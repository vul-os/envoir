//! Envoir reference node — CLI entry point.
//!
//! The node is the whole client side (spec §0.2): identity, mailbox, mesh participation,
//! delivery, messaging, files, and client protocols. It *is* the mesh. See the DMTAP spec
//! repo (../dmtap/).
//!
//! This is a scaffold: subsystems are stubbed. Build order (spec §10.6):
//!   identity → mote → naming → transport → messaging → privacy → clients → abuse.

use dmtap::Suite;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");

    match cmd {
        "version" => {
            println!("envoir-node {} (pre-alpha scaffold)", env!("CARGO_PKG_VERSION"));
            println!("default suite: {:?}", Suite::Classical);
        }
        "init" => {
            // TODO: generate root identity key (Ed25519), device key, recovery policy
            // (spec §1.2, §1.4), and publish Identity + KeyPackages.
            eprintln!("`init` not yet implemented — see spec §1 (identity lifecycle)");
        }
        "run" => {
            // TODO: start libp2p mesh (Kad/Relay/DCUtR/AutoNAT/mDNS), mixnet client,
            // MLS delivery service, client protocol servers (JMAP/IMAP), retry queue.
            // NOTE: MLS handshakes go over an ORDERED channel, not the mixnet (spec §5.1).
            eprintln!("`run` not yet implemented — see spec §4 (transport), §5 (messaging)");
        }
        "gateway" => {
            // A node MAY run in gateway mode if it has a reputable IP + domain (spec §7);
            // the dedicated implementation lives in ../gateway/.
            eprintln!("run the dedicated `envoir-gateway` binary — see ../gateway/ and spec §7");
        }
        _ => {
            println!(
                "envoir-node — Decentralized Message Transfer & Access Protocol (reference)\n\
                 \n\
                 USAGE:\n\
                 \x20 envoir-node <command>\n\
                 \n\
                 COMMANDS:\n\
                 \x20 init       create a new identity (keys + recovery policy)\n\
                 \x20 run        run the node (mesh + mixnet + delivery + clients)\n\
                 \x20 version    print version and default suite\n\
                 \x20 help       show this help\n\
                 \n\
                 Spec: ../dmtap/  (the DMTAP spec repo is normative; this binary is a reference)."
            );
        }
    }
}
