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
//! Parts of this crate were first written for `envoir-cloud`, a **separate, private** control plane
//! that is not part of this workspace and is not open source. It is a live, independently developed
//! system, not a dead branch of this repo; this crate is not a replacement for it and makes no claim
//! about it beyond the two facts an OSS reader needs:
//!
//! 1. **No dependency runs in that direction.** Nothing in this workspace requires, calls, or
//!    assumes any private control plane. Every trait here is a `dmtap-seam` impl an operator may
//!    swap for their own, and the self-host defaults in [`dmtap_seam`] mean a node with no operator
//!    attached behaves identically.
//! 2. **What crossed over is only the non-commercial machinery.** Pricing, invoicing, and payment
//!    processing are outside this repository and stay there; this crate never computes a price,
//!    renders an invoice, or talks to a payment processor, and none of it ever will.
//!
//! What this crate actually contains — usage tracking, quotas, and authorization, which are real
//! operator needs rather than commercial policy:
//!
//! - [`queue`] — a bounded, idempotent, backpressured usage-ingest queue
//!   ([`queue::MeteringQueue`]) plus [`queue::Accumulator`], the reference sink that **sums** usage
//!   per account/dimension and can hand the totals to a [`dmtap_seam::BillingSink`] — a no-op by
//!   default (TODO(patala): the not-yet-ready billing system this is a boundary for). The summing
//!   semantics are a *contract*, not an implementation detail: see [`queue::Accumulator`] and
//!   [`dmtap_seam::UsageKind::StorageBytes`] before writing anything that feeds it a **level**.
//! - [`policy`] — [`policy::StaticQuotas`], a flat-limit reference [`dmtap_seam::Policy`]: one
//!   number per dimension, no plans, no per-account entitlement table.
//! - [`authz`] — the fail-closed [`dmtap_seam::GatewayAuthz`] reference logic (spec §12.2): the
//!   online accountability check, and the strictly narrower safe default a gateway MUST fall
//!   back to when an out-of-process operator is unreachable.
//! - [`dns`] — the gateway-domain DNS record-set builder ([`dns::gateway_zone_records`]: MX /
//!   SPF / delegated DKIM / DMARC / `_dmtap`) plus the `DnsProvider` trait and its one real
//!   Cloudflare implementation, behind the non-default `net` feature. Domain DNS shape has no
//!   notion of price, so this module is commercial-free by construction.
//! - [`http`] — the injectable outbound transport [`dns`] needs, trimmed to the four HTTP verbs
//!   it actually uses.
//!
//! An operator who wants to charge for hosting runs their own billing system and attaches it at the
//! [`dmtap_seam::BillingSink`] boundary; an operator who wants to provision VMs picks their own
//! host. Neither is this crate's job.
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
