use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};

/// One theorem certificate served to clients.
///
/// Schema is intentionally close to what Cloco's Python SDK (`kenosian_vault.Vault`)
/// expects: `verified` is `Some(true)` for a validated theorem, `None` for unknown.
/// `axiom_level` is not present on v1 records — inserted later by post-audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub fqn: String,
    pub verified: Option<bool>,
    pub axiom_level: Option<String>,
    pub olean_sha256: Option<String>,
    pub commit: String,
    pub statement: Option<String>,
    pub sorry_axioms_detected: Option<u32>,
    pub arxiv_id: Option<String>,
    pub citations: Option<u32>,
    pub d3_tier: Option<String>,
    /// Sale tier — Jay 2026-08-18 10:19 KST direction: dual-track sale.
    /// Highest tier the record qualifies for:
    ///   "kernel-standard"  → Track 2 premium (only propext/Classical.choice/Quot.sound)
    ///   "sorryAx-free"     → Track 1 base    (source-level sorry/sorryAx audit at zero)
    ///   "not-audited"      → excluded from sale
    /// Derived, not stored: recomputed at load time from the two measured fields.
    pub sale_tier: String,
}

/// Raw v1 JSONL record shape (only the fields we lift into the router).
#[derive(Debug, Deserialize)]
struct V1Record {
    metadata: V1Metadata,
    formal_ground_truth: V1GroundTruth,
    #[serde(default)]
    execution_target: Option<V1ExecutionTarget>,
}

#[derive(Debug, Deserialize)]
struct V1Metadata {
    #[serde(default)]
    canonical_namespace: Option<String>,
    #[serde(default)]
    theorem_identifier: Option<String>,
    #[serde(default)]
    arxiv_id: Option<String>,
    #[serde(default)]
    citations: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct V1GroundTruth {
    #[serde(default)]
    kernel_status: Option<String>,
    #[serde(default)]
    sorry_axioms_detected: Option<u32>,
    #[serde(default)]
    olean_sha256: Option<String>,
    #[serde(default)]
    cryptographic_commit: Option<String>,
    #[serde(default)]
    axiom_level: Option<String>,
}

#[derive(Debug, Deserialize)]
struct V1ExecutionTarget {
    #[serde(default)]
    lean4_full_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EnrichedAtomRecord {
    pub fqn: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub structural_hash: Option<String>,
    #[serde(default)]
    pub canonical_head: Option<String>,
    #[serde(default)]
    pub classification: Option<EnrichedClassification>,
    #[serde(default)]
    pub difficulty_metrics: Option<EnrichedDifficulty>,
}

#[derive(Debug, Deserialize)]
pub struct EnrichedClassification {
    #[serde(default)]
    pub grade_tier: Option<String>,
    #[serde(default)]
    pub axiom_level: Option<String>,
    #[serde(default)]
    pub sorry_count: Option<u32>,
    #[serde(default)]
    pub kernel_verified: Option<bool>,
    #[serde(default)]
    pub kernel_verified_source: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EnrichedDifficulty {
    #[serde(default)]
    pub difficulty_tier: Option<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("open {path}: {source}")]
    Open {
        path: String,
        source: std::io::Error,
    },
    #[error("read line {line}: {source}")]
    Read {
        line: usize,
        source: std::io::Error,
    },
}

pub struct FormalHashRouter {
    by_fqn: HashMap<String, Certificate, ahash::RandomState>,
    dataset_path: String,
    total_ingested: u64,
    total_skipped: u64,
    /// Manifest: content-address of the *set* of FQNs served at this commit.
    /// Cheap running XOR of ahash(fqn); enough to detect "did the vault
    /// change under me?" without committing to a full Merkle tree yet.
    manifest_xor: u64,
}

impl FormalHashRouter {
    pub async fn from_jsonl(path: &str) -> Result<Self, LoadError> {
        let file = File::open(path).await.map_err(|e| LoadError::Open {
            path: path.to_string(),
            source: e,
        })?;
        let reader = BufReader::with_capacity(1 << 20, file);
        let mut lines = reader.lines();

        let mut by_fqn: HashMap<String, Certificate, ahash::RandomState> =
            HashMap::with_capacity_and_hasher(1_000_000, ahash::RandomState::new());
        let mut ingested: u64 = 0;
        let mut skipped: u64 = 0;
        let mut line_no: usize = 0;
        let manifest_hasher = ahash::RandomState::with_seed(0);
        let mut manifest_xor: u64 = 0;

        while let Some(line) = lines
            .next_line()
            .await
            .map_err(|e| LoadError::Read {
                line: line_no,
                source: e,
            })?
        {
            line_no += 1;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(record) = serde_json::from_str::<V1Record>(&line) {
                let fqn = match derive_fqn(&record) {
                    Some(f) => f,
                    None => {
                        skipped += 1;
                        continue;
                    }
                };
                let verified = match record.formal_ground_truth.kernel_status.as_deref() {
                    Some("VERIFIED_SORRY_AX_FREE") => Some(true),
                    _ => None,
                };
                let d3_tier = record
                    .metadata
                    .canonical_namespace
                    .as_deref()
                    .and_then(|ns| ns.rsplit('.').next().map(str::to_string));
                let statement = record
                    .execution_target
                    .as_ref()
                    .and_then(|e| e.lean4_full_code.as_deref())
                    .map(mask_lean_body);

                let sale_tier = derive_sale_tier(
                    record.formal_ground_truth.axiom_level.as_deref(),
                    record.formal_ground_truth.sorry_axioms_detected,
                    record.formal_ground_truth.kernel_status.as_deref(),
                );
                let cert = Certificate {
                    fqn: fqn.clone(),
                    verified,
                    axiom_level: record.formal_ground_truth.axiom_level,
                    olean_sha256: record.formal_ground_truth.olean_sha256,
                    commit: record
                        .formal_ground_truth
                        .cryptographic_commit
                        .unwrap_or_default(),
                    statement,
                    sorry_axioms_detected: record.formal_ground_truth.sorry_axioms_detected,
                    arxiv_id: record.metadata.arxiv_id,
                    citations: record.metadata.citations,
                    d3_tier,
                    sale_tier,
                };
                manifest_xor ^= manifest_hasher.hash_one(&fqn);
                by_fqn.insert(fqn, cert);
                ingested += 1;
                continue;
            }

            if let Ok(record) = serde_json::from_str::<EnrichedAtomRecord>(&line) {
                let fqn = record.fqn.clone();
                let (axiom_level, sorry_count, verified) = if let Some(cls) = &record.classification {
                    (cls.axiom_level.clone(), cls.sorry_count, cls.kernel_verified)
                } else {
                    (None, None, Some(true))
                };
                let sale_tier = if axiom_level.as_deref() == Some("kernel-standard") {
                    "kernel-standard".to_string()
                } else if sorry_count == Some(0) || sorry_count.is_none() {
                    "sorryAx-free".to_string()
                } else {
                    "not-audited".to_string()
                };
                let d3_tier = record.difficulty_metrics.as_ref().and_then(|d| d.difficulty_tier.map(|t| format!("D3-Tier-{}", t)));
                let cert = Certificate {
                    fqn: fqn.clone(),
                    verified,
                    axiom_level,
                    olean_sha256: record.structural_hash.clone(),
                    commit: record.structural_hash.unwrap_or_else(|| "uncommitted".to_string()),
                    statement: record.canonical_head,
                    sorry_axioms_detected: sorry_count,
                    arxiv_id: None,
                    citations: None,
                    d3_tier,
                    sale_tier,
                };
                manifest_xor ^= manifest_hasher.hash_one(&fqn);
                by_fqn.insert(fqn, cert);
                ingested += 1;
                continue;
            }

            skipped += 1;
        }

        Ok(Self {
            by_fqn,
            dataset_path: path.to_string(),
            total_ingested: ingested,
            total_skipped: skipped,
            manifest_xor,
        })
    }

    pub fn get(&self, fqn: &str) -> Option<&Certificate> {
        self.by_fqn.get(fqn)
    }

    pub fn len(&self) -> usize {
        self.by_fqn.len()
    }

    pub fn total_ingested(&self) -> u64 {
        self.total_ingested
    }

    pub fn total_skipped(&self) -> u64 {
        self.total_skipped
    }

    pub fn dataset_path(&self) -> &str {
        &self.dataset_path
    }

    pub fn manifest_xor_hex(&self) -> String {
        format!("{:016x}", self.manifest_xor)
    }
}

/// Zero-Leak: strip everything after `:= by` (the proof body).
/// Buyers see the theorem signature and can decide whether to pay for the
/// ground-truth proof, but bulk scraping only yields signatures.
fn mask_lean_body(full: &str) -> String {
    match full.find(":= by") {
        Some(idx) => {
            let signature = &full[..idx];
            format!("{}:= by ⟨omitted⟩", signature)
        }
        None => "⟨signature unavailable⟩".to_string(),
    }
}

/// Assign the highest sale tier this record qualifies for.
///
/// Order: kernel-standard > sorryAx-free > not-audited.
/// The two measurement fields drive it:
///   - `axiom_level == "kernel-standard"` promotes to Track 2.
///   - kernel_status VERIFIED_SORRY_AX_FREE with sorry_count 0 keeps Track 1.
///   - Neither → not-audited (should not be served to buyers).
fn derive_sale_tier(
    axiom_level: Option<&str>,
    sorry_count: Option<u32>,
    kernel_status: Option<&str>,
) -> String {
    if matches!(axiom_level, Some("kernel-standard")) {
        return "kernel-standard".to_string();
    }
    let sorry_zero = matches!(sorry_count, Some(0));
    let status_ok = matches!(kernel_status, Some("VERIFIED_SORRY_AX_FREE"));
    if sorry_zero && status_ok {
        return "sorryAx-free".to_string();
    }
    "not-audited".to_string()
}

fn derive_fqn(record: &V1Record) -> Option<String> {
    let ns = record.metadata.canonical_namespace.as_deref()?;
    let ident = record.metadata.theorem_identifier.as_deref()?;
    Some(format!("{}.{}", ns, ident))
}

#[derive(Clone)]
pub struct AppState {
    pub router: Arc<FormalHashRouter>,
    pub commit_hash: String,
}
