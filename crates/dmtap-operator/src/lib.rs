//! # dmtap-operator — reference machinery for a third-party DMTAP operator
//!
//! Envoir does not run a business. Nobody is charged from inside this workspace, and there is no
//! control plane. But a **third-party operator** — anyone who runs a node or gateway for other
//! people — has real, legitimate, non-commercial needs: track usage, enforce quotas, authorize
//! legacy egress without opening a spam relay, and automate the DNS a gateway domain requires.
//! This crate is a working reference implementation of exactly that, and nothing more.
//!
//! ## Where this came from
//!
//! An earlier prototype, `envoir-cloud`, bundled this operational machinery together with a full
//! commercial billing engine (a price book, invoicing, proration, dunning, plan lifecycle) and a
//! single-vendor VM provisioner. That prototype has been retired. Folding it back into the OSS
//! workspace was **mostly deletion**:
//!
//! - **Dropped entirely**: the price book and usage raters, billing periods/proration/invoices,
//!   declined-payment dunning retry, the plan lifecycle (subscribe/change-plan/cancel), the
//!   multi-tenant superadmin surface (tenant listing, reputation registry, revenue reports), and
//!   the single-vendor (Hetzner) VM provisioner. None of that is this crate's job — an operator who
//!   wants to charge for hosting runs their own billing system and attaches it at the
//!   `dmtap-seam` boundary; an operator who wants to provision VMs picks their own host.
//! - **Kept, because usage tracking, quotas, and authorization are real operator needs, not
//!   commercial policy**:
//!   - [`queue`] — a bounded, idempotent, backpressured usage-ingest queue
//!     ([`queue::MeteringQueue`]) plus [`queue::Accumulator`], the reference sink that sums usage
//!     per account/dimension and can hand the totals to a [`dmtap_seam::BillingSink`] — a no-op by
//!     default (TODO(patala): the not-yet-ready billing system this is a boundary for).
//!   - [`policy`] — [`policy::StaticQuotas`], a flat-limit reference [`dmtap_seam::Policy`]: one
//!     number per dimension, no plans, no per-account entitlement table.
//!   - [`authz`] — the fail-closed [`dmtap_seam::GatewayAuthz`] reference logic (spec §12.2): the
//!     online accountability check, and the strictly narrower safe default a gateway MUST fall
//!     back to when an out-of-process operator is unreachable. Preserved bit-for-bit; only the
//!     billing-flavored doc comments were reworded.
//!   - [`dns`] — the gateway-domain DNS record-set builder ([`dns::gateway_zone_records`]: MX /
//!     SPF / delegated DKIM / DMARC / `_dmtap`) plus the `DnsProvider` trait and its one real
//!     Cloudflare implementation, behind the non-default `net` feature. Domain DNS shape has no
//!     notion of price, so this module was already commercial-free; it moved over unchanged.
//!   - [`http`] — the injectable outbound transport [`dns`] needs, trimmed to the four HTTP verbs
//!     it actually uses.
//!
//! No module in this crate computes a price, renders an invoice, or talks to a payment processor,
//! and none ever will — that is Patala's job, entirely outside this repository, attaching (if an
//! operator wants it at all) at [`dmtap_seam::BillingSink`].
//!
//! ## The inviolable rule (unchanged, restated)
//!
//! Privacy, cryptography, metadata privacy, and recovery are **never** behind any of this. Native
//! node-to-node delivery has no operator on the path, so there is nothing here to meter, quota, or
//! bill — this crate's traits only ever engage once an operator's own infrastructure (a gateway, a
//! hosted node, a relay) is actually in the path.

pub mod authz;
pub mod dns;
pub mod http;
pub mod policy;
pub mod queue;
