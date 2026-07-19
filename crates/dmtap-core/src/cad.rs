//! CAD / Artifact Profile over DMTAP-PUB (spec §23).
//!
//! An **application profile** over the DMTAP-PUB extension ([`crate::pubobj`], §22): a metadata
//! schema ([`ArtifactMetadata`], §23.3) carried inside a `pub_announce`'s `meta["artifact"]` bytes,
//! and a parts-DAG structure ([`AssemblyStructure`], §23.6.2) published as an ordinary §22 public
//! blob. This profile introduces **zero new wire mechanisms and zero new crypto** — every byte is
//! either unsigned application data that inherits its authenticity from the already-signed
//! `pub_announce` it rides inside, or a convention a CAD-aware client applies. A generic §22 node
//! stores and serves every object here without parsing any of it.
//!
//! The maps use the same compact integer-keyed deterministic CBOR (§18.1.2) as the core wire
//! format, even though they are profile-local (not §21 registry entries). Per §23.3.1's
//! forward-compat rule these are **unsigned** application maps, so §18.1.2's *unsigned*-object
//! ignore rule applies: a decoder MUST ignore unrecognized integer keys (keys ≥ 64 reserved) and
//! preserve them on re-serialize — it MUST NOT fail closed on them the way a signed object does.
//!
//! ## Conformance checklist (§23.10)
//! [`ArtifactMetadata::validate`] enforces CAD-1..7; [`AssemblyStructure`]/[`AssemblyChild`] decode
//! enforces CAD-9; [`walk_bom`] enforces CAD-10 (cycle rejection). CAD-8 (deprecation is
//! supersede-only, never deletion) and CAD-11 (no index is authoritative) are structural — this
//! module simply defines no deletion operation, and treats indexes as derived data.

use crate::cbor::{self, as_bytes, as_bool, as_text, as_u64, Cv, Fields};
use crate::id::ContentId;
use crate::pubobj::PubError;

/// A §23 CAD-profile validation error. These are **profile-level** faults: a generic §22 node still
/// stores/serves the object unaffected (§22 has no concept of artifacts); only a CAD-aware
/// client/index rejects it (§23.4, §23.10).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CadError {
    /// CAD-1 (§23.4): the artifact announce carries no `license`.
    #[error("CAD-1: license (SPDX expression) is required for a profile artifact (§23.4)")]
    MissingLicense,
    /// CAD-2 (§23.3.4): `formats` is empty.
    #[error("CAD-2: formats must contain at least one entry (§23.3.4)")]
    NoFormats,
    /// CAD-3 (§23.3.4): not exactly one canonical-source (non-assembly) / structure (assembly).
    #[error("CAD-3: exactly one canonical-source (non-assembly) or structure (assembly) format required (§23.3.4)")]
    CanonicalSourceCardinality,
    /// CAD-4 (§23.3.4): a glTF/mesh entry marked canonical-source.
    #[error("CAD-4: a glTF/mesh (format_id=3) format MUST NOT be canonical-source (§23.3.4)")]
    MeshCanonicalSource,
    /// CAD-5 (§23.3.4): a derived-rendition entry lacking `derived_from_format`.
    #[error("CAD-5: every derived-rendition (role=2) format must carry derived_from_format (§23.3.4)")]
    DerivedMissingProvenance,
    /// CAD-6 (§23.3.3): `units.length_unit` absent — MUST NOT be defaulted/inferred.
    #[error("CAD-6: units.length_unit is required and MUST NOT be defaulted or inferred (§23.3.3)")]
    MissingLengthUnit,
    /// CAD-7 (§23.3.1): `deprecated = true` without `deprecation_reason`.
    #[error("CAD-7: deprecated=true requires a deprecation_reason (§23.3.1)")]
    DeprecatedMissingReason,
    /// CAD-9 (§23.6.1): an assembly child `ref_kind` outside {pin(1), track(2)}.
    #[error("CAD-9: assembly child ref_kind must be pin(1) or track(2) (§23.6.1)")]
    BadRefKind,
    /// CAD-10 (§23.6.3): a cycle in an assembly's resolved DAG.
    #[error("CAD-10: cycle detected in the assembly DAG — abort the walk, never recurse (§23.6.3)")]
    Cycle,
    /// A structural malformation (empty children, quantity < 1, wrong CBOR type, …).
    #[error("CAD structural: {0}")]
    Structural(String),
    /// A lower-level canonical-CBOR violation on decode.
    #[error("CBOR: {0}")]
    Cbor(#[from] cbor::CborError),
}

// ── Registries (§23.3.2, profile-local) ──────────────────────────────────────────────────────

/// Artifact kinds (§23.3.2). Retained as raw `u64` on the wire (unrecognized values are preserved,
/// not fatal, per §23.3.1); these constants name the v0 profile values.
pub mod artifact_kind {
    pub const PART: u64 = 1;
    pub const ASSEMBLY: u64 = 2;
    pub const PCB: u64 = 3;
    pub const SCHEMATIC: u64 = 4;
    pub const DRAWING: u64 = 5;
    pub const DATASET: u64 = 6;
    pub const DOC: u64 = 7;
}

/// Format ids (§23.3.2).
pub mod format_id {
    pub const STEP: u64 = 1;
    pub const NATIVE: u64 = 2;
    pub const GLTF_MESH: u64 = 3;
    pub const ECAD: u64 = 4;
    pub const PDF: u64 = 5;
    pub const ASSEMBLY_STRUCTURE: u64 = 6;
    pub const OPAQUE: u64 = 7;
}

/// Format roles (§23.3.2).
pub mod role {
    pub const CANONICAL_SOURCE: u64 = 1;
    pub const DERIVED_RENDITION: u64 = 2;
    pub const STRUCTURE: u64 = 3;
}

/// Assembly child reference modes (§23.6.1).
pub mod ref_kind {
    pub const PIN: u64 = 1;
    pub const TRACK: u64 = 2;
}

// ── Units (§23.3.3) ──────────────────────────────────────────────────────────────────────────

/// Explicit unit declaration (§23.3.3). `length_unit` MUST always be present and MUST NOT be
/// defaulted or inferred — unit ambiguity in interchanged engineering data is a catastrophic-
/// failure-class bug this profile closes structurally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Units {
    /// key 1 — REQUIRED, explicit (e.g. `"m"`, `"mm"`, `"in"`); no implied default.
    pub length_unit: String,
    /// key 2 — default `"rad"` if absent.
    pub angle_unit: Option<String>,
    /// key 3 — OPTIONAL, for BOM mass properties.
    pub mass_unit: Option<String>,
}

impl Units {
    fn to_cv(&self) -> Cv {
        let mut m = vec![(1u64, Cv::Text(self.length_unit.clone()))];
        if let Some(a) = &self.angle_unit {
            m.push((2, Cv::Text(a.clone())));
        }
        if let Some(mu) = &self.mass_unit {
            m.push((3, Cv::Text(mu.clone())));
        }
        Cv::Map(m)
    }

    fn from_fields(cv: Cv) -> Result<Self, CadError> {
        let mut f = Fields::from_cv(cv)?;
        // CAD-6: length_unit (key 1) is REQUIRED; a missing key is MissingLengthUnit, not a generic
        // decode error — the profile refuses to interpret geometry until it is supplied.
        let length_unit = match f.take(1) {
            Some(cv) => as_text(cv)?,
            None => return Err(CadError::MissingLengthUnit),
        };
        if length_unit.is_empty() {
            return Err(CadError::MissingLengthUnit);
        }
        let angle_unit = f.take(2).map(as_text).transpose()?;
        let mass_unit = f.take(3).map(as_text).transpose()?;
        // Unsigned application map (§23.3.1): ignore unrecognized keys, do NOT deny_unknown.
        Ok(Units { length_unit, angle_unit, mass_unit })
    }
}

// ── ArtifactFormat (§23.3.4) ─────────────────────────────────────────────────────────────────

/// One rendition of an artifact (§23.3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactFormat {
    /// key 1 — rendition format (§23.3.2).
    pub format_id: u64,
    /// key 2 — the §22 public-blob manifest root for this rendition's bytes.
    pub manifest_root: ContentId,
    /// key 3 — canonical-source(1) / derived-rendition(2) / structure(3).
    pub role: u64,
    /// key 4 — MUST iff `role = 2`: the `manifest_root` this rendition was generated from.
    pub derived_from_format: Option<ContentId>,
    /// key 5 — free-form tool/variant string; display/index hint only.
    pub format_version: Option<String>,
}

impl ArtifactFormat {
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.format_id)),
            (2, Cv::Bytes(self.manifest_root.as_bytes().to_vec())),
            (3, Cv::U64(self.role)),
        ];
        if let Some(d) = &self.derived_from_format {
            m.push((4, Cv::Bytes(d.as_bytes().to_vec())));
        }
        if let Some(v) = &self.format_version {
            m.push((5, Cv::Text(v.clone())));
        }
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, CadError> {
        let mut f = Fields::from_cv(cv)?;
        let format_id = as_u64(f.req(1).map_err(CadError::Cbor)?)?;
        let manifest_root = ContentId(as_bytes(f.req(2).map_err(CadError::Cbor)?)?);
        let role = as_u64(f.req(3).map_err(CadError::Cbor)?)?;
        let derived_from_format = f.take(4).map(as_bytes).transpose()?.map(ContentId);
        let format_version = f.take(5).map(as_text).transpose()?;
        Ok(ArtifactFormat { format_id, manifest_root, role, derived_from_format, format_version })
    }
}

// ── ArtifactMetadata (§23.3.1) ───────────────────────────────────────────────────────────────

/// The artifact metadata map (§23.3.1), carried as the deterministically-encoded `bytes` value
/// under the profile-named text key `"artifact"` in a `pub_announce`'s `meta` map. Because it rides
/// inside the signed announce body, it is covered by the announce's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMetadata {
    /// key 1 — human-readable name (UTF-8; not unique).
    pub name: String,
    /// key 2 — free-form description; MAY be empty.
    pub description: String,
    /// key 3 — one of the §23.3.2 kinds (raw; unrecognized preserved).
    pub artifact_kind: u64,
    /// key 4 — at least one rendition (§23.3.4).
    pub formats: Vec<ArtifactFormat>,
    /// key 5 — explicit unit declaration (§23.3.3).
    pub units: Units,
    /// key 6 — free-form tags; advisory index input only.
    pub tags: Vec<String>,
    /// key 7 — SPDX license expression (REQUIRED, §23.4).
    pub license: String,
    /// key 8 — present-and-true iff this revision deprecates/yanks the artifact (§23.5).
    pub deprecated: bool,
    /// key 9 — human reason; MUST be present iff `deprecated`.
    pub deprecation_reason: Option<String>,
    /// key 10 — announce id of the cross-identity ancestor this forks from (§23.5).
    pub derived_from: Option<ContentId>,
}

impl ArtifactMetadata {
    /// The `meta["artifact"]` text key under which the encoded metadata rides (§23.3.1).
    pub const META_KEY: &'static str = "artifact";

    /// Encode to the deterministic CBOR bytes embedded under `meta["artifact"]` (§23.3.1).
    pub fn det_cbor(&self) -> Vec<u8> {
        let mut m = vec![
            (1u64, Cv::Text(self.name.clone())),
            (2, Cv::Text(self.description.clone())),
            (3, Cv::U64(self.artifact_kind)),
            (4, Cv::Array(self.formats.iter().map(|f| f.to_cv()).collect())),
            (5, self.units.to_cv()),
        ];
        if !self.tags.is_empty() {
            m.push((6, Cv::Array(self.tags.iter().map(|t| Cv::Text(t.clone())).collect())));
        }
        m.push((7, Cv::Text(self.license.clone())));
        if self.deprecated {
            m.push((8, Cv::Bool(true)));
        }
        if let Some(r) = &self.deprecation_reason {
            m.push((9, Cv::Text(r.clone())));
        }
        if let Some(d) = &self.derived_from {
            m.push((10, Cv::Bytes(d.as_bytes().to_vec())));
        }
        cbor::encode(&Cv::Map(m))
    }

    /// Decode from the `meta["artifact"]` embedded bytes (§23.3.1). Enforces CAD-1 (a missing
    /// `license` is [`CadError::MissingLicense`]) and CAD-6 (a missing `units.length_unit` is
    /// [`CadError::MissingLengthUnit`]) as profile faults rather than generic decode errors. Per
    /// §23.3.1 this is an **unsigned** application map, so unrecognized integer keys are ignored
    /// (forward-compat), never fatal.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CadError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let name = as_text(f.req(1).map_err(CadError::Cbor)?)?;
        let description = as_text(f.req(2).map_err(CadError::Cbor)?)?;
        let artifact_kind = as_u64(f.req(3).map_err(CadError::Cbor)?)?;
        let formats: Vec<ArtifactFormat> = cbor::as_array(f.req(4).map_err(CadError::Cbor)?)?
            .into_iter()
            .map(ArtifactFormat::from_cv)
            .collect::<Result<_, _>>()?;
        let units = Units::from_fields(f.req(5).map_err(CadError::Cbor)?)?;
        let tags = match f.take(6) {
            Some(cv) => cbor::as_array(cv)?.into_iter().map(as_text).collect::<Result<_, _>>()?,
            None => Vec::new(),
        };
        // CAD-1: license (key 7) is REQUIRED for a profile artifact.
        let license = match f.take(7) {
            Some(cv) => as_text(cv)?,
            None => return Err(CadError::MissingLicense),
        };
        if license.is_empty() {
            return Err(CadError::MissingLicense);
        }
        let deprecated = f.take(8).map(as_bool).transpose()?.unwrap_or(false);
        let deprecation_reason = f.take(9).map(as_text).transpose()?;
        let derived_from = f.take(10).map(as_bytes).transpose()?.map(ContentId);
        // Unsigned application map (§23.3.1): ignore unrecognized keys, do NOT deny_unknown.
        Ok(ArtifactMetadata {
            name,
            description,
            artifact_kind,
            formats,
            units,
            tags,
            license,
            deprecated,
            deprecation_reason,
            derived_from,
        })
    }

    /// Validate the §23.10 profile MUSTs the object can be checked against in isolation:
    /// CAD-2 (≥1 format), CAD-3 (exactly one canonical-source / structure), CAD-4 (no mesh
    /// canonical-source), CAD-5 (derived renditions carry provenance), CAD-7 (deprecation carries a
    /// reason). CAD-1/CAD-6 are enforced at [`ArtifactMetadata::from_det_cbor`] time (a missing
    /// required field). Returns the first violation.
    pub fn validate(&self) -> Result<(), CadError> {
        // CAD-2.
        if self.formats.is_empty() {
            return Err(CadError::NoFormats);
        }
        // CAD-4: a glTF/mesh entry is NEVER canonical-source.
        for fmt in &self.formats {
            if fmt.format_id == format_id::GLTF_MESH && fmt.role == role::CANONICAL_SOURCE {
                return Err(CadError::MeshCanonicalSource);
            }
            // CAD-5: every derived-rendition carries derived_from_format.
            if fmt.role == role::DERIVED_RENDITION && fmt.derived_from_format.is_none() {
                return Err(CadError::DerivedMissingProvenance);
            }
        }
        // CAD-3: exactly one canonical-source (non-assembly) or structure (assembly).
        if self.artifact_kind == artifact_kind::ASSEMBLY {
            let structures = self.formats.iter().filter(|f| f.role == role::STRUCTURE).count();
            if structures != 1 {
                return Err(CadError::CanonicalSourceCardinality);
            }
        } else {
            let canonical = self.formats.iter().filter(|f| f.role == role::CANONICAL_SOURCE).count();
            if canonical != 1 {
                return Err(CadError::CanonicalSourceCardinality);
            }
        }
        // CAD-7: deprecated ⇒ a reason.
        if self.deprecated && self.deprecation_reason.as_deref().unwrap_or("").is_empty() {
            return Err(CadError::DeprecatedMissingReason);
        }
        Ok(())
    }

    /// Decode from the embedded bytes AND run [`ArtifactMetadata::validate`] — the full profile
    /// admission a CAD-aware index applies before treating an announce as a usable artifact.
    pub fn parse_and_validate(bytes: &[u8]) -> Result<Self, CadError> {
        let md = Self::from_det_cbor(bytes)?;
        md.validate()?;
        Ok(md)
    }
}

// ── AssemblyStructure (§23.6.2) ──────────────────────────────────────────────────────────────

/// One direct child of an assembly (§23.6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyChild {
    /// key 1 — pin(1) / track(2) (§23.6.1).
    pub ref_kind: u64,
    /// key 2 — a `manifest_root` (pin) or a `pub_announce` id (track).
    pub reference: ContentId,
    /// key 3 — instance count in the parent; MUST be ≥ 1.
    pub quantity: u64,
    /// key 4 — OPTIONAL placement/orientation data; byte format out of scope for this profile.
    pub transform: Option<Vec<u8>>,
}

impl AssemblyChild {
    fn to_cv(&self) -> Cv {
        let mut m = vec![
            (1u64, Cv::U64(self.ref_kind)),
            (2, Cv::Bytes(self.reference.as_bytes().to_vec())),
            (3, Cv::U64(self.quantity)),
        ];
        if let Some(t) = &self.transform {
            m.push((4, Cv::Bytes(t.clone())));
        }
        Cv::Map(m)
    }

    fn from_cv(cv: Cv) -> Result<Self, CadError> {
        let mut f = Fields::from_cv(cv)?;
        let ref_kind = as_u64(f.req(1).map_err(CadError::Cbor)?)?;
        // CAD-9: ref_kind MUST be pin(1) or track(2).
        if ref_kind != ref_kind::PIN && ref_kind != ref_kind::TRACK {
            return Err(CadError::BadRefKind);
        }
        let reference = ContentId(as_bytes(f.req(2).map_err(CadError::Cbor)?)?);
        let quantity = as_u64(f.req(3).map_err(CadError::Cbor)?)?;
        // §23.6.2: quantity MUST be ≥ 1 (a zero count is expressed by omitting the child).
        if quantity < 1 {
            return Err(CadError::Structural("assembly child quantity must be >= 1 (§23.6.2)".into()));
        }
        let transform = f.take(4).map(as_bytes).transpose()?;
        Ok(AssemblyChild { ref_kind, reference, quantity, transform })
    }
}

/// The parts-DAG of an assembly (§23.6.2), published as an ordinary §22 public blob; its
/// authenticity is the authenticity of the manifest that names it (content addressing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyStructure {
    /// key 1 — one or more sub-part/sub-assembly references (≥ 1).
    pub children: Vec<AssemblyChild>,
}

impl AssemblyStructure {
    /// Encode to the deterministic CBOR bytes of the public blob (§23.6.2).
    pub fn det_cbor(&self) -> Vec<u8> {
        cbor::encode(&Cv::Map(vec![(1, Cv::Array(self.children.iter().map(|c| c.to_cv()).collect()))]))
    }

    /// Decode (§23.6.2). Enforces CAD-9 (valid `ref_kind`) and the ≥1-children / ≥1-quantity
    /// structural rules.
    pub fn from_det_cbor(bytes: &[u8]) -> Result<Self, CadError> {
        let mut f = Fields::from_cv(cbor::decode(bytes)?)?;
        let children: Vec<AssemblyChild> = cbor::as_array(f.req(1).map_err(CadError::Cbor)?)?
            .into_iter()
            .map(AssemblyChild::from_cv)
            .collect::<Result<_, _>>()?;
        // §23.6.2: an assembly with zero children is malformed (use a part-kind artifact instead).
        if children.is_empty() {
            return Err(CadError::Structural("assembly must have >= 1 child (§23.6.2)".into()));
        }
        Ok(AssemblyStructure { children })
    }
}

/// The result of a BOM (bill-of-materials) walk: a per-leaf effective quantity keyed by the leaf's
/// resolved content address, with `quantity` multiplied along every path (§23.6.3).
pub type Bom = std::collections::BTreeMap<Vec<u8>, u64>;

/// Walk an assembly's DAG (§23.6.3), accumulating a BOM. `resolve` maps a child reference (a `pin`
/// manifest root or a `track` announce id, resolved to a concrete revision by the caller) to the
/// child's own [`AssemblyStructure`] when that child is itself an assembly, or `None` when it is a
/// leaf part. **Cycles MUST be rejected** ([`CadError::Cycle`], CAD-10): the walker maintains the
/// set of references on the current path and aborts the subtree on re-encounter, never recursing
/// indefinitely nor silently dropping it. `quantity` multiplies along the path.
pub fn walk_bom<F>(root: &AssemblyStructure, resolve: &F) -> Result<Bom, CadError>
where
    F: Fn(&ContentId) -> Option<AssemblyStructure>,
{
    fn recurse<F>(
        node: &AssemblyStructure,
        multiplier: u64,
        path: &mut Vec<Vec<u8>>,
        resolve: &F,
        bom: &mut Bom,
    ) -> Result<(), CadError>
    where
        F: Fn(&ContentId) -> Option<AssemblyStructure>,
    {
        for child in &node.children {
            let key = child.reference.as_bytes().to_vec();
            // CAD-10: re-encountering a reference already on the current path is a cycle.
            if path.contains(&key) {
                return Err(CadError::Cycle);
            }
            let effective = multiplier.saturating_mul(child.quantity);
            match resolve(&child.reference) {
                Some(sub) => {
                    // A sub-assembly: recurse, tracking this reference on the path.
                    path.push(key);
                    recurse(&sub, effective, path, resolve, bom)?;
                    path.pop();
                }
                None => {
                    // A leaf part: accumulate its effective quantity.
                    *bom.entry(key).or_insert(0) += effective;
                }
            }
        }
        Ok(())
    }
    let mut bom = Bom::new();
    let mut path: Vec<Vec<u8>> = Vec::new();
    recurse(root, 1, &mut path, resolve, &mut bom)?;
    Ok(bom)
}

/// §23.5 / CAD-8: retraction is expressed **only** as a successor announcement — a deprecation
/// marker (`deprecated = true` + `deprecation_reason`) whose `pub_announce` `supersedes` the retired
/// revision — never as a deletion (there is no such operation; a published object is irrevocable,
/// §22.7). This helper produces the deprecating `ArtifactMetadata` for a successor announce, given
/// the prior metadata; the caller wraps it in a `pub_announce` with `supersedes` set to the retired
/// announce id. Returns [`PubError`]-free CAD metadata; the same-author supersede check itself lives
/// in [`crate::pubobj::check_supersede`].
pub fn deprecate(prior: &ArtifactMetadata, reason: impl Into<String>) -> ArtifactMetadata {
    let mut next = prior.clone();
    next.deprecated = true;
    next.deprecation_reason = Some(reason.into());
    next
}

/// A convenience marker: there is deliberately **no** `delete`/`unpublish` operation in this
/// profile (CAD-8, §23.5, §22.7). This function documents that fact by construction — it always
/// reports that deletion is not an available operation, so a caller that tries to "delete" is
/// steered to [`deprecate`] instead.
pub fn deletion_is_not_an_operation() -> Result<(), PubError> {
    // Irrevocability (§22.7): a published object cannot be un-published; retraction is supersede-only.
    Err(PubError::NotServed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubobj::check_supersede;

    fn sample_units() -> Units {
        Units { length_unit: "mm".into(), angle_unit: None, mass_unit: None }
    }

    fn part_with(formats: Vec<ArtifactFormat>, kind: u64) -> ArtifactMetadata {
        ArtifactMetadata {
            name: "bracket".into(),
            description: String::new(),
            artifact_kind: kind,
            formats,
            units: sample_units(),
            tags: vec![],
            license: "CERN-OHL-S-2.0".into(),
            deprecated: false,
            deprecation_reason: None,
            derived_from: None,
        }
    }

    fn fmt(format_id: u64, role: u64, derived: Option<ContentId>) -> ArtifactFormat {
        ArtifactFormat { format_id, manifest_root: ContentId::of(&[format_id as u8, role as u8]), role, derived_from_format: derived, format_version: None }
    }

    #[test]
    fn valid_part_roundtrips_and_validates() {
        let md = part_with(vec![fmt(format_id::NATIVE, role::CANONICAL_SOURCE, None)], artifact_kind::PART);
        md.validate().expect("valid part");
        let bytes = md.det_cbor();
        let back = ArtifactMetadata::parse_and_validate(&bytes).expect("roundtrip+validate");
        assert_eq!(back, md);
        assert_eq!(back.det_cbor(), bytes, "canonical re-encode");
    }

    #[test]
    fn cad1_missing_license_rejected() {
        // Build a metadata map WITHOUT key 7 and confirm decode raises MissingLicense.
        let md = part_with(vec![fmt(format_id::NATIVE, role::CANONICAL_SOURCE, None)], artifact_kind::PART);
        let cv = cbor::decode(&md.det_cbor()).unwrap();
        let mut pairs = match cv { Cv::Map(p) => p, _ => panic!() };
        pairs.retain(|(k, _)| *k != 7);
        let bytes = cbor::encode(&Cv::Map(pairs));
        assert_eq!(ArtifactMetadata::from_det_cbor(&bytes), Err(CadError::MissingLicense));
    }

    #[test]
    fn cad2_empty_formats_rejected() {
        let md = part_with(vec![], artifact_kind::PART);
        assert_eq!(md.validate(), Err(CadError::NoFormats));
    }

    #[test]
    fn cad3_ambiguous_canonical_and_assembly_missing_structure() {
        // Two canonical-source entries → ambiguous.
        let two = part_with(
            vec![fmt(format_id::NATIVE, role::CANONICAL_SOURCE, None), fmt(format_id::STEP, role::CANONICAL_SOURCE, None)],
            artifact_kind::PART,
        );
        assert_eq!(two.validate(), Err(CadError::CanonicalSourceCardinality));
        // Assembly with no structure entry → malformed.
        let asm = part_with(vec![fmt(format_id::NATIVE, role::CANONICAL_SOURCE, None)], artifact_kind::ASSEMBLY);
        assert_eq!(asm.validate(), Err(CadError::CanonicalSourceCardinality));
    }

    #[test]
    fn cad4_mesh_canonical_source_rejected() {
        let md = part_with(vec![fmt(format_id::GLTF_MESH, role::CANONICAL_SOURCE, None)], artifact_kind::PART);
        assert_eq!(md.validate(), Err(CadError::MeshCanonicalSource));
    }

    #[test]
    fn cad5_derived_without_provenance_rejected() {
        let md = part_with(
            vec![
                fmt(format_id::NATIVE, role::CANONICAL_SOURCE, None),
                fmt(format_id::STEP, role::DERIVED_RENDITION, None), // missing derived_from_format
            ],
            artifact_kind::PART,
        );
        assert_eq!(md.validate(), Err(CadError::DerivedMissingProvenance));
    }

    #[test]
    fn cad6_missing_length_unit_rejected() {
        // Units map without key 1.
        let bytes = cbor::encode(&Cv::Map(vec![(2, Cv::Text("rad".into()))]));
        assert_eq!(Units::from_fields(cbor::decode(&bytes).unwrap()), Err(CadError::MissingLengthUnit));
    }

    #[test]
    fn cad7_deprecated_without_reason_rejected() {
        let mut md = part_with(vec![fmt(format_id::NATIVE, role::CANONICAL_SOURCE, None)], artifact_kind::PART);
        md.deprecated = true;
        md.deprecation_reason = None;
        assert_eq!(md.validate(), Err(CadError::DeprecatedMissingReason));
        // A deprecation with a reason is valid (CAD-8: retraction is a successor, not a deletion).
        let dep = deprecate(&md, "superseded by rev B; tolerance error");
        dep.validate().expect("deprecation with reason is valid");
    }

    #[test]
    fn cad8_deletion_is_not_an_operation() {
        assert!(deletion_is_not_an_operation().is_err());
        // Retraction path: a deprecation successor by the SAME author is a valid supersede.
        let pk = vec![1u8; 32];
        assert_eq!(check_supersede(&pk, &pk), Ok(()));
    }

    #[test]
    fn cad9_bad_ref_kind_rejected() {
        // ref_kind = 3 (neither pin nor track).
        let bad = cbor::encode(&Cv::Map(vec![(1, Cv::Array(vec![Cv::Map(vec![
            (1, Cv::U64(3)),
            (2, Cv::Bytes(ContentId::of(b"x").as_bytes().to_vec())),
            (3, Cv::U64(1)),
        ])]))]));
        assert_eq!(AssemblyStructure::from_det_cbor(&bad), Err(CadError::BadRefKind));
    }

    #[test]
    fn cad10_cycle_rejected_and_valid_bom_walks() {
        // A track cycle across revisions: assembly A tracks B, and B (republished as an assembly)
        // tracks back to A. Walking A must abort at the cycle, never recurse indefinitely.
        let a = ContentId::of(b"assembly-A");
        let b = ContentId::of(b"assembly-B");
        let struct_a = AssemblyStructure { children: vec![AssemblyChild { ref_kind: ref_kind::TRACK, reference: b.clone(), quantity: 2, transform: None }] };
        let struct_b = AssemblyStructure { children: vec![AssemblyChild { ref_kind: ref_kind::TRACK, reference: a.clone(), quantity: 1, transform: None }] };
        let (sa, sb) = (struct_a.clone(), struct_b.clone());
        let resolve = move |r: &ContentId| -> Option<AssemblyStructure> {
            if r == &a {
                Some(sa.clone())
            } else if r == &b {
                Some(sb.clone())
            } else {
                None
            }
        };
        // Walk from A (as an outer structure whose sole child is A): A → B → A (on path) → Cycle.
        let outer = struct_a.clone();
        assert_eq!(walk_bom(&outer, &resolve), Err(CadError::Cycle));

        // A valid acyclic BOM: A → [bolt x4, plate x1]; quantities multiply.
        let bolt = ContentId::of(b"bolt-m3");
        let plate = ContentId::of(b"plate");
        let valid = AssemblyStructure { children: vec![
            AssemblyChild { ref_kind: ref_kind::PIN, reference: bolt.clone(), quantity: 4, transform: None },
            AssemblyChild { ref_kind: ref_kind::PIN, reference: plate.clone(), quantity: 1, transform: None },
        ] };
        let bom = walk_bom(&valid, &|_r: &ContentId| None).expect("acyclic BOM walks");
        assert_eq!(bom.get(bolt.as_bytes()), Some(&4));
        assert_eq!(bom.get(plate.as_bytes()), Some(&1));
    }

    #[test]
    fn cad10_quantity_multiplies_along_path() {
        // outer → sub (x3) ; sub → bolt (x4)  ⇒  bolt effective = 12.
        let sub_id = ContentId::of(b"sub-assembly");
        let bolt = ContentId::of(b"bolt");
        let sub = AssemblyStructure { children: vec![AssemblyChild { ref_kind: ref_kind::PIN, reference: bolt.clone(), quantity: 4, transform: None }] };
        let outer = AssemblyStructure { children: vec![AssemblyChild { ref_kind: ref_kind::PIN, reference: sub_id.clone(), quantity: 3, transform: None }] };
        let sub2 = sub.clone();
        let resolve = |r: &ContentId| -> Option<AssemblyStructure> { if r == &sub_id { Some(sub2.clone()) } else { None } };
        let bom = walk_bom(&outer, &resolve).unwrap();
        assert_eq!(bom.get(bolt.as_bytes()), Some(&12));
    }
}
