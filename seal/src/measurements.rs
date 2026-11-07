//! The published list of Seal builds and the rules for reading it.
//!
//! The list is `enclave/measurements.json` in the repository, and the app
//! pins a list of the same format. Each build is named by its three Nitro
//! measurements: PCR0 (the whole enclave image, the Seal's answer
//! measurement), PCR1 (the kernel and boot ramdisk) and PCR2 (the Seal
//! program). A document is accepted only when all three equal one build
//! whose status is `allowed`; a build marked `revoked` is never accepted and
//! never given M.
//!
//! ```json
//! {"version": 1, "builds": [{"name": "seal-2026-11-01", "released": "2026-11-01",
//!   "pcr0": "<96 hex>", "pcr1": "<96 hex>", "pcr2": "<96 hex>", "status": "allowed"}]}
//! ```
//!
//! The reader is strict: the version must be 1, every build has exactly
//! these six fields, PCRs are 96 lowercase hex digits and never all zeros
//! (a debug-mode enclave reports zeros), `released` is a real date, names are
//! unique, and no two builds share PCR0. Anything else refuses the whole
//! list. An empty list is valid and refuses every Seal.
//!
//! The published file may also carry `"signature"`: the release key's
//! ML-DSA-65 signature (context [`RELEASE_CONTEXT`]) over
//! [`MeasurementList::signing_message`], as lowercase hex. The signature
//! covers the builds, not the JSON spacing.
//!
//! # Which list an enclave enforces
//!
//! An enclave never takes a list on the host's word. The only list it checks
//! another enclave against is a [`TrustedList`], made of:
//!
//! - the builds compiled into its own image ([`COMPILED_BUILDS`]);
//! - a list signed by the release key whose public key is compiled into its
//!   own image ([`RELEASE_KEY_HEX`]); the private key is held offline and is
//!   never in the repository, an image or a fixture;
//! - its own build, read from its own attestation document: an identical
//!   image is the same code that already holds M.
//!
//! A build that any of these marks `revoked` is refused, whatever another
//! says. An unsigned list, or one whose signature does not verify under the
//! compiled-in key, is refused, and a signed list never replaces a held one
//! that it does not extend (it must keep every build already held, with the
//! same PCRs, and keep every revoked build revoked).

use core::fmt;

use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

use crate::answer::MEASUREMENT_BYTES;
use crate::attestation::{AttestationError, AttestationRejected, AttestationSource, AttestationVerifier};

/// The format version this reader accepts.
pub const MEASUREMENTS_VERSION: u64 = 1;
/// The ML-DSA context string of the release key's signature over a list.
pub const RELEASE_CONTEXT: &[u8] = b"ghost-seal measurements";
/// The label in front of a list's digest in the signed message.
pub const RELEASE_LABEL: &[u8] = b"ghost-seal/v1/measurements/release";
/// An ML-DSA-65 verifying key's length.
pub const RELEASE_KEY_BYTES: usize = 1952;
/// An ML-DSA-65 signature's length.
pub const RELEASE_SIGNATURE_BYTES: usize = 3309;

/// The release key's ML-DSA-65 verifying key, as lowercase hex, compiled into
/// every enclave image. Empty until the release key is made offline: an
/// image built with no release key accepts no signed list, and trusts only
/// [`COMPILED_BUILDS`] and its own build.
pub const RELEASE_KEY_HEX: &str = "73840f0ef9551356f000411598a054b5a1e6ddcb2f93ec07ee279be1ba42b8fd164df9a061b93e2e0b106d92f5a23bc4e4acfa2529aaa1fc8da31e49499bf63647bcd47b74808bd1b5f8a6e816abf196283fda24b20e50ac4b197a9653b5ebd901a50bf590b45c01d1cf1f553978b8d259c1b6d847767eecfab95d6eff6d731e78b5cc7ecbd4b7fa0d6b243cd3c32787a88b187255536681ca7765acfc3fa072fb73d5d98ddc2f0e4166529b653b022fd1a83bac3b604ea22b48d7fe64bde41bf31edf9d97d94d38dc4246af2d117c3af1f9d188d225e96def4d3a43621aa967d79b405365f055c783a06c244044bffd1e97c7f5921e1fa521b025319acc3da83c29c60b820ea4877c0554a902fd3942ddb55fb0bef89227998fea2ac2bc9d24bc622b958fe1cefad3d6569c369db4d4cf226c76b01abafbcf286977db85395e432000b625b19459db91b8315a73caa084e931317540e95143281bc15e7143e0f7f36b2722965797d4db490acebf6940384230fa69482403e5abd0e82a7c3616ff2015010353e47db8d9fa768bba56d7caa0cbea34a7600356c01b686d88bcc16e385ffef8ef84ed39babad5d05f90a91abb775779792e3bf230179d73af17fb62398390435888ffacf14b19e106c5f4d55759a2c9e66a05a8d4cda3d0a69ad0990338c4b3512185b8c8e1a8aedd60e0c80e6dc58d6d44ae1926b7243e356b1438e96b4b7f04f54c51044f9f071538ee0f332c737cdbd46ba135698a5ccad950042a7a57db710aa844b5156fa6b1cec398ccc36350809f9a7a7662a1155bf81358b40575c6f4c9a8fb1acd7e786521604d43117b72b34c49ec5f3ce4b08bf814ecd07f07a38dc2485052564db6c62f0ce191d835283a4c2d943ee283a1e95a4d4b8fa96201d9da4dcb7993959b4c2effae759589ca171d6508af89c35418f1cda29ea56291cdac00a8517319cb0169b71100727a89c0ca67114b6a341494d84916cbb00eefd8232c9fb3efe1ac83776f180cef17c4f472abfa6f7354cdb92f57ac0274ca84c567acdea690c77f45eeb8927bb2ee49b079f329897bb0dfd13c029d3a482cd37125f1256524a5d19eb5ddfa6a38d5543c7838cf37cf3bc640b8bf67dcec707eae20f1722bdb412317a733541440b7f5414a609fc37b9fae33676f8659bcb6a8b8952248dc068660f594b259d23eb994615eaf2107a95545810c4cc527d9981a64c32316dcb8abd1cffbc0587f0c668d972d385c5e2a2df6581faa5d15fe338074db4e31872f9b28c625228cdcad65164b07b8088fc64c3ab0fea5dcbc243d4ddb445c37c05b12ff1cc084814b2cc959a9d7264dbfdb298052fc0087b05bcc75293894c0f7f8d6dad1da3a85b05eed4891f0ddd7648b78be21dd05f79a99e22b2c9025e7d8b5076ceb03ed4ba67d3b2c6944763f1dcebd6d848f981a8cf1b7a7706c826e2d3063ef27484a6526de42f3ae597258baccc5e75bad04618ce568471f2607fe406c69c93f5115d3660ee8dd39ea56d00572c70275246f78e4cf35c8f37b52a3c24882b508ef3477eb4dd2affba216e03a771490cc7378723596cd49647d4d28e7e7ef56882f9d5d2272f90ab390cd13ffc322fc1379e74c029c7116104fc2abbd477808be4c76b9073bfe398cf964ab683ebc70ad6650d87f9e959541e1d10bb6fafe86271190ffd4a72ccc928214f296fcde950dcc2e362c6339ba9f2e032151b40669d797f10c26381dde8c61f0a882ffe93733a7c7cef62fb452ecf570858c54c01262be55083befabd7ac419e6ae72e78164742a7eeab863bba377b508e7a69e4c22762cc271940d58ae3848ddf8d824cf69e9bec5d279fcf437187a75dadfe5df89cf9d3d16f7958e3e3021011a356b4f249aad2b29588648ef4541db5273fe755e4a92736bd0999d00faf99e527830a8515c552def55175a65c9c56e2d6b4a12757c3b6e1ab75295a8822a70d328deab54e457e88e29178106eff3c712d06ffc191fbd91c503d22461228c48bc71691b957047380c554d3f3db6e3970e5e4afad0e76f8c5df4d95321ba68d67f656409b41c36de7d80cf942109a6193d20779884ebb265f4fd5885f181ed2b921d97d08970422afbfb5726e83a1bb3a00208d27ebd76cabb0bb19aff9d2b1b74cd06d29fa4078a0f6810813f6f5d661deb46efaaf67251023304cb11bca15fdeac3d5a579bfcfba3ea6e55f7f1147e50e390d23f883b56434755258f3a37bf7d50a07eafb896f368bd4838958d064c05d82ab6b743777134d7ba791dbfc44a8dbf36cd86649fc9fdf5c86fa052469d56ea8f92fa67fddd8f24794a015eb01640f316b7efe92a1f0e5d22c92425dc6b784fbf19f2bccdff48e7084b7295eb1d19ab7f885f417131c3e3521e7be926001a1ee8f757c47653dc7b67c3a020d0a406a1e787ef5035b003850d0af93954a22682a3983caa2fa99ad09983429ce1837db77f57c64ddcb68a2cdddf6a49c1bef8864cb1471b6ecc6f5f49e9af8b6136ccde078b4a16707a9b6ab5cd01e440145082932116c5256505f0cc6ba359546a5121d923fc266399ead75c2f5451349646a2a71437cba095f588e10825cd1dadc38d3f01822626cf0738489b6fc433fc698ee004db0af442ca82487afe93693affdc5b9971513afd7e96557ea038b58efa28fd5590c1aea664ab7a791379179b70dd06521181d27214466eeb86f68be7a61d4bce5811568632b80e0e1a0d453983711c8c495b6df";

/// The builds compiled into this image, in the published format (no
/// signature needed: the image's own measurement covers them). An image
/// cannot list itself or later builds, so this holds earlier builds it may
/// take M from or give M to; later builds come in a signed list.
pub const COMPILED_BUILDS: &str = r#"{"version": 1, "builds": []}"#;

/// The name [`TrustedList::check`] gives the enclave's own build.
pub const OWN_BUILD_NAME: &str = "this-image";
/// The most builds a list may hold.
pub const MAX_BUILDS: usize = 256;
/// The longest build name, in bytes.
pub const MAX_NAME_BYTES: usize = 64;

/// One PCR value: SHA-384, 48 bytes.
pub type Pcr = [u8; MEASUREMENT_BYTES];

/// The three measurements that name a build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pcrs {
    /// The enclave image.
    pub pcr0: Pcr,
    /// The kernel and boot ramdisk.
    pub pcr1: Pcr,
    /// The Seal program.
    pub pcr2: Pcr,
}

/// Whether a build may run as the Seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildStatus {
    /// Accepted, and may be given M.
    Allowed,
    /// Never accepted, never given M.
    Revoked,
}

/// One published build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    /// Its name.
    pub name: String,
    /// The day it was published, `YYYY-MM-DD`.
    pub released: String,
    /// Its measurements.
    pub pcrs: Pcrs,
    /// Whether it may run.
    pub status: BuildStatus,
}

/// Why a list could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListError {
    /// Not JSON, or JSON nested too deep.
    Syntax(&'static str),
    /// JSON, but not this format.
    Format(String),
    /// No release signature, a signature that does not verify under the
    /// release key, or no release key to check it with.
    Signature(&'static str),
    /// A signed list that does not extend the one already held.
    Rollback(String),
}

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListError::Syntax(what) => write!(f, "measurements list is not JSON: {what}"),
            ListError::Format(what) => write!(f, "measurements list: {what}"),
            ListError::Signature(what) => write!(f, "measurements list: signature: {what}"),
            ListError::Rollback(what) => write!(f, "measurements list: not a later list: {what}"),
        }
    }
}

impl std::error::Error for ListError {}

/// Why measurements were not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeasurementRefused {
    /// No build has these three measurements.
    NotListed,
    /// The build with these measurements is revoked.
    Revoked {
        /// The build's name.
        name: String,
    },
    /// A PCR is all zeros: an enclave started in debug mode.
    DebugMode,
}

impl fmt::Display for MeasurementRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MeasurementRefused::NotListed => f.write_str("the measurements are not on the published list"),
            MeasurementRefused::Revoked { name } => write!(f, "build {name} is revoked"),
            MeasurementRefused::DebugMode => f.write_str("a debug-mode enclave is never accepted"),
        }
    }
}

impl std::error::Error for MeasurementRefused {}

/// A published list of builds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MeasurementList {
    builds: Vec<Build>,
}

impl MeasurementList {
    /// A list with no build: every Seal is refused.
    pub fn empty() -> MeasurementList {
        MeasurementList { builds: Vec::new() }
    }

    /// Reads a list in the published format. A `signature` field, when
    /// present, must be well formed but is not checked here: this is the
    /// reader for lists that are trusted for another reason (the app's
    /// pinned list). An enclave reads lists only through [`TrustedList`].
    pub fn parse(text: &str) -> Result<MeasurementList, ListError> {
        Self::parse_with_signature(text).map(|(list, _)| list)
    }

    /// Reads a list and checks its release signature under `key`: a list
    /// with no signature, or one that does not verify, is refused.
    pub fn parse_signed(text: &str, key: &ReleaseKey) -> Result<MeasurementList, ListError> {
        let (list, signature) = Self::parse_with_signature(text)?;
        let signature = signature.ok_or(ListError::Signature("the list is not signed"))?;
        let signature = Signature::<MlDsa65>::try_from(signature.as_slice())
            .map_err(|_| ListError::Signature("not an ML-DSA-65 signature"))?;
        if !key.0.verify_with_context(&list.signing_message(), RELEASE_CONTEXT, &signature) {
            return Err(ListError::Signature("the signature does not verify under the release key"));
        }
        Ok(list)
    }

    /// The message the release key signs: [`RELEASE_LABEL`] || [`Self::digest`].
    pub fn signing_message(&self) -> Vec<u8> {
        [RELEASE_LABEL, &self.digest()[..]].concat()
    }

    fn parse_with_signature(text: &str) -> Result<(MeasurementList, Option<Vec<u8>>), ListError> {
        let value = json::parse(text)?;
        let top = value.object("the list")?;
        json::only_keys(top, &["version", "builds", "signature"], "the list")?;
        let signature = match top.iter().find(|(k, _)| k == "signature") {
            None => None,
            Some((_, value)) => {
                let text = value.string("signature")?;
                let bytes = parse_hex(text)
                    .filter(|b| b.len() == RELEASE_SIGNATURE_BYTES)
                    .ok_or_else(|| format_error(format!("signature is not {} lowercase hex digits", 2 * RELEASE_SIGNATURE_BYTES)))?;
                Some(bytes)
            }
        };
        let version = json::field(top, "version", "the list")?.integer("version")?;
        if version != MEASUREMENTS_VERSION {
            return Err(format_error(format!("version {version} is not {MEASUREMENTS_VERSION}")));
        }
        let entries = json::field(top, "builds", "the list")?.array("builds")?;
        if entries.len() > MAX_BUILDS {
            return Err(format_error(format!("more than {MAX_BUILDS} builds")));
        }
        let mut builds: Vec<Build> = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let build = read_build(entry, index)?;
            if builds.iter().any(|b| b.name == build.name) {
                return Err(format_error(format!("build name {} is listed twice", build.name)));
            }
            if builds.iter().any(|b| shares_pcr(&b.pcrs, &build.pcrs)) {
                return Err(format_error(format!("build {} repeats a listed PCR0", build.name)));
            }
            builds.push(build);
        }
        Ok((MeasurementList { builds }, signature))
    }

    /// The builds, in the order listed.
    pub fn builds(&self) -> &[Build] {
        &self.builds
    }

    /// The builds that may run.
    pub fn allowed(&self) -> impl Iterator<Item = &Build> {
        self.builds.iter().filter(|b| b.status == BuildStatus::Allowed)
    }

    /// Whether no build is listed.
    pub fn is_empty(&self) -> bool {
        self.builds.is_empty()
    }

    /// Accepts `pcrs` only when PCR0, PCR1 and PCR2 all equal one allowed
    /// build's, and returns that build.
    pub fn check(&self, pcrs: &Pcrs) -> Result<&Build, MeasurementRefused> {
        if is_zero(&pcrs.pcr0) || is_zero(&pcrs.pcr1) || is_zero(&pcrs.pcr2) {
            return Err(MeasurementRefused::DebugMode);
        }
        let build = self.builds.iter().find(|b| &b.pcrs == pcrs).ok_or(MeasurementRefused::NotListed)?;
        match build.status {
            BuildStatus::Allowed => Ok(build),
            BuildStatus::Revoked => Err(MeasurementRefused::Revoked { name: build.name.clone() }),
        }
    }

    /// SHA3-256 of the list in its canonical form (the builds in order, each
    /// field length-prefixed), so two copies holding the same list agree on
    /// its hash however the JSON was spaced.
    pub fn digest(&self) -> [u8; 32] {
        let mut parts: Vec<Vec<u8>> = vec![b"ghost-seal/v1/measurements".to_vec()];
        parts.push((self.builds.len() as u32).to_be_bytes().to_vec());
        for build in &self.builds {
            for field in [build.name.as_bytes(), build.released.as_bytes()] {
                parts.push((field.len() as u32).to_be_bytes().to_vec());
                parts.push(field.to_vec());
            }
            parts.push(build.pcrs.pcr0.to_vec());
            parts.push(build.pcrs.pcr1.to_vec());
            parts.push(build.pcrs.pcr2.to_vec());
            parts.push(vec![match build.status {
                BuildStatus::Allowed => 1,
                BuildStatus::Revoked => 2,
            }]);
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        crate::primitives::sha3_256(&refs)
    }
}

/// The release key's ML-DSA-65 verifying key: the only key whose signature
/// makes a list trusted.
#[derive(Clone)]
pub struct ReleaseKey(VerifyingKey<MlDsa65>);

impl ReleaseKey {
    /// The key compiled into this image ([`RELEASE_KEY_HEX`]); refused while
    /// none has been made.
    pub fn compiled_in() -> Result<ReleaseKey, ListError> {
        if RELEASE_KEY_HEX.is_empty() {
            return Err(ListError::Signature("this image has no release key, so it accepts no signed list"));
        }
        let bytes = parse_hex(RELEASE_KEY_HEX).ok_or(ListError::Signature("the compiled-in release key is not hex"))?;
        ReleaseKey::from_bytes(&bytes)
    }

    /// A key from its encoded bytes. The enclave uses [`Self::compiled_in`];
    /// tests pass their own test-only key here.
    pub fn from_bytes(bytes: &[u8]) -> Result<ReleaseKey, ListError> {
        let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(bytes)
            .map_err(|_| ListError::Signature("not an ML-DSA-65 verifying key"))?;
        Ok(ReleaseKey(VerifyingKey::decode(&encoded)))
    }
}

impl fmt::Debug for ReleaseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReleaseKey")
    }
}

/// Why an enclave could not learn its own build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnBuildError {
    /// No document from the NSM.
    Attestation(AttestationError),
    /// The enclave's own document does not verify.
    Rejected(AttestationRejected),
    /// A debug-mode enclave (zero PCRs) is never trusted.
    DebugMode,
}

impl fmt::Display for OwnBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OwnBuildError::Attestation(why) => write!(f, "own build: {why}"),
            OwnBuildError::Rejected(why) => write!(f, "own build: {why}"),
            OwnBuildError::DebugMode => f.write_str("own build: a debug-mode enclave"),
        }
    }
}

impl std::error::Error for OwnBuildError {}

/// The `user_data` label of the document an enclave reads its own build from.
pub const OWN_BUILD_LABEL: &[u8] = b"ghost-seal/v1/own-build";

/// The only list an enclave checks another enclave against: what its own
/// image compiles in, a list signed by the compiled-in release key, and its
/// own attested build. Nothing the host says unsigned ever gets in; there is
/// no way to make one from a plain [`MeasurementList`].
#[derive(Debug, Clone)]
pub struct TrustedList {
    compiled: MeasurementList,
    signed: Option<MeasurementList>,
    own: Option<Build>,
}

impl TrustedList {
    /// The builds compiled into this image ([`COMPILED_BUILDS`]) and nothing
    /// else. Should the constant not parse, the list is empty (refuses all).
    pub fn compiled_in() -> TrustedList {
        TrustedList {
            compiled: MeasurementList::parse(COMPILED_BUILDS).unwrap_or_default(),
            signed: None,
            own: None,
        }
    }

    /// Takes a signed list: it must carry a signature that verifies under
    /// `key` (in an enclave, [`ReleaseKey::compiled_in`]) and extend the
    /// signed list already held, if any: every build held stays, with the
    /// same name and PCRs, and every revoked build stays revoked. Refused,
    /// the held list is unchanged.
    pub fn install_signed(&mut self, text: &str, key: &ReleaseKey) -> Result<(), ListError> {
        let list = MeasurementList::parse_signed(text, key)?;
        if let Some(held) = &self.signed {
            for old in held.builds() {
                let new = list
                    .builds()
                    .iter()
                    .find(|b| b.name == old.name)
                    .ok_or_else(|| ListError::Rollback(format!("build {} is missing", old.name)))?;
                if new.pcrs != old.pcrs || new.released != old.released {
                    return Err(ListError::Rollback(format!("build {} changed", old.name)));
                }
                if old.status == BuildStatus::Revoked && new.status != BuildStatus::Revoked {
                    return Err(ListError::Rollback(format!("build {} is revoked and stays revoked", old.name)));
                }
            }
        }
        self.signed = Some(list);
        Ok(())
    }

    /// Trusts the enclave's own build: asks `source` (the enclave's own NSM)
    /// for a document, verifies it with `verifier`, and takes its PCRs. A
    /// copy of the very same image runs the same code that already holds M.
    pub fn trust_own_build(
        &mut self,
        source: &mut dyn AttestationSource,
        verifier: &dyn AttestationVerifier,
        now_unix: u64,
    ) -> Result<Pcrs, OwnBuildError> {
        let binding = crate::primitives::sha3_256(&[OWN_BUILD_LABEL]);
        let document = source.attest(&binding, &binding).map_err(OwnBuildError::Attestation)?;
        let attested = verifier.verify(&document, now_unix).map_err(OwnBuildError::Rejected)?;
        let pcrs = attested.pcrs;
        if is_zero(&pcrs.pcr0) || is_zero(&pcrs.pcr1) || is_zero(&pcrs.pcr2) {
            return Err(OwnBuildError::DebugMode);
        }
        self.own =
            Some(Build { name: OWN_BUILD_NAME.into(), released: String::new(), pcrs, status: BuildStatus::Allowed });
        Ok(pcrs)
    }

    /// Whether a signed list is held.
    pub fn has_signed_list(&self) -> bool {
        self.signed.is_some()
    }

    /// Accepts `pcrs` only when all three equal a build compiled in, on the
    /// signed list or the enclave's own, and none of the lists marks that
    /// build revoked.
    pub fn check(&self, pcrs: &Pcrs) -> Result<&Build, MeasurementRefused> {
        if is_zero(&pcrs.pcr0) || is_zero(&pcrs.pcr1) || is_zero(&pcrs.pcr2) {
            return Err(MeasurementRefused::DebugMode);
        }
        let mut allowed = None;
        for list in [Some(&self.compiled), self.signed.as_ref()].into_iter().flatten() {
            if let Some(build) = list.builds().iter().find(|b| &b.pcrs == pcrs) {
                match build.status {
                    BuildStatus::Revoked => return Err(MeasurementRefused::Revoked { name: build.name.clone() }),
                    BuildStatus::Allowed => {
                        allowed.get_or_insert(build);
                    }
                }
            }
        }
        if let Some(build) = allowed {
            return Ok(build);
        }
        match &self.own {
            Some(own) if &own.pcrs == pcrs => Ok(own),
            _ => Err(MeasurementRefused::NotListed),
        }
    }
}

/// Reads lowercase hex.
fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    bytes.chunks(2).map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?)).collect()
}

fn format_error(what: String) -> ListError {
    ListError::Format(what)
}

fn is_zero(pcr: &Pcr) -> bool {
    pcr.iter().all(|b| *b == 0)
}

/// PCR0 measures the whole image, so two entries with one PCR0 are one
/// build listed twice (perhaps with two statuses). Builds may share PCR1 (the
/// same kernel).
fn shares_pcr(a: &Pcrs, b: &Pcrs) -> bool {
    a.pcr0 == b.pcr0
}

fn read_build(entry: &json::Value, index: usize) -> Result<Build, ListError> {
    let what = format!("build {index}");
    let object = entry.object(&what)?;
    json::only_keys(object, &["name", "released", "pcr0", "pcr1", "pcr2", "status"], &what)?;
    let name = json::field(object, "name", &what)?.string("name")?.to_owned();
    if name.is_empty()
        || name.len() > MAX_NAME_BYTES
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return Err(format_error(format!("{what}: a name is 1 to {MAX_NAME_BYTES} of a-z, A-Z, 0-9, '-', '.', '_'")));
    }
    let released = json::field(object, "released", &what)?.string("released")?.to_owned();
    if !is_date(&released) {
        return Err(format_error(format!("{what}: released is not a YYYY-MM-DD date")));
    }
    let pcr = |key: &str| -> Result<Pcr, ListError> {
        let text = json::field(object, key, &what)?.string(key)?;
        let pcr = parse_pcr(text).ok_or_else(|| format_error(format!("{what}: {key} is not 96 lowercase hex digits")))?;
        if is_zero(&pcr) {
            return Err(format_error(format!("{what}: {key} is all zeros (a debug-mode enclave)")));
        }
        Ok(pcr)
    };
    let pcrs = Pcrs { pcr0: pcr("pcr0")?, pcr1: pcr("pcr1")?, pcr2: pcr("pcr2")? };
    let status = match json::field(object, "status", &what)?.string("status")? {
        "allowed" => BuildStatus::Allowed,
        "revoked" => BuildStatus::Revoked,
        other => return Err(format_error(format!("{what}: status {other:?} is not allowed or revoked"))),
    };
    Ok(Build { name, released, pcrs, status })
}

/// Reads 96 lowercase hex digits.
pub fn parse_pcr(text: &str) -> Option<Pcr> {
    let bytes = text.as_bytes();
    if bytes.len() != 2 * MEASUREMENT_BYTES {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; MEASUREMENT_BYTES];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = digit(bytes[2 * i])? << 4 | digit(bytes[2 * i + 1])?;
    }
    Some(out)
}

/// A PCR as 96 lowercase hex digits.
pub fn pcr_hex(pcr: &Pcr) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 * MEASUREMENT_BYTES);
    for byte in pcr {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn is_date(text: &str) -> bool {
    let b = text.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let number = |range: core::ops::Range<usize>| -> Option<u32> {
        let mut n = 0u32;
        for &c in &b[range] {
            if !c.is_ascii_digit() {
                return None;
            }
            n = n * 10 + u32::from(c - b'0');
        }
        Some(n)
    };
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(5..7), number(8..10)) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    year >= 2000 && (1..=days).contains(&day)
}

/// A small strict JSON reader (RFC 8259) for the measurements list: no
/// duplicate keys, no trailing data, nesting at most 16 deep.
mod json {
    use super::ListError;

    const MAX_DEPTH: usize = 16;

    /// A JSON value; booleans and null are read (so a list holding one is
    /// refused by its field checks, not by the reader) but never used.
    #[allow(dead_code)]
    pub(super) enum Value {
        Null,
        Bool(bool),
        Number(String),
        String(String),
        Array(Vec<Value>),
        Object(Vec<(String, Value)>),
    }

    impl Value {
        pub(super) fn object(&self, what: &str) -> Result<&[(String, Value)], ListError> {
            match self {
                Value::Object(fields) => Ok(fields),
                _ => Err(ListError::Format(format!("{what} is not an object"))),
            }
        }

        pub(super) fn array(&self, what: &str) -> Result<&[Value], ListError> {
            match self {
                Value::Array(items) => Ok(items),
                _ => Err(ListError::Format(format!("{what} is not an array"))),
            }
        }

        pub(super) fn string(&self, what: &str) -> Result<&str, ListError> {
            match self {
                Value::String(text) => Ok(text),
                _ => Err(ListError::Format(format!("{what} is not a string"))),
            }
        }

        pub(super) fn integer(&self, what: &str) -> Result<u64, ListError> {
            match self {
                Value::Number(text) if !text.is_empty() && text.bytes().all(|c| c.is_ascii_digit()) => {
                    text.parse().map_err(|_| ListError::Format(format!("{what} is too large")))
                }
                _ => Err(ListError::Format(format!("{what} is not a whole number"))),
            }
        }
    }

    pub(super) fn field<'a>(fields: &'a [(String, Value)], key: &str, what: &str) -> Result<&'a Value, ListError> {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .ok_or_else(|| ListError::Format(format!("{what} has no {key}")))
    }

    pub(super) fn only_keys(fields: &[(String, Value)], keys: &[&str], what: &str) -> Result<(), ListError> {
        for (key, _) in fields {
            if !keys.contains(&key.as_str()) {
                return Err(ListError::Format(format!("{what} has an unknown field {key:?}")));
            }
        }
        Ok(())
    }

    pub(super) fn parse(text: &str) -> Result<Value, ListError> {
        let mut reader = Reader { bytes: text.as_bytes(), at: 0 };
        let value = reader.value(0)?;
        reader.space();
        if reader.at != reader.bytes.len() {
            return Err(ListError::Syntax("data after the end"));
        }
        Ok(value)
    }

    struct Reader<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl Reader<'_> {
        fn space(&mut self) {
            while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.bytes.get(self.at) {
                self.at += 1;
            }
        }

        fn peek(&self) -> Option<u8> {
            self.bytes.get(self.at).copied()
        }

        fn expect(&mut self, byte: u8) -> Result<(), ListError> {
            if self.peek() == Some(byte) {
                self.at += 1;
                Ok(())
            } else {
                Err(ListError::Syntax("unexpected character"))
            }
        }

        fn literal(&mut self, word: &[u8], value: Value) -> Result<Value, ListError> {
            if self.bytes[self.at..].starts_with(word) {
                self.at += word.len();
                Ok(value)
            } else {
                Err(ListError::Syntax("unknown literal"))
            }
        }

        fn value(&mut self, depth: usize) -> Result<Value, ListError> {
            if depth > MAX_DEPTH {
                return Err(ListError::Syntax("nested too deep"));
            }
            self.space();
            match self.peek() {
                Some(b'{') => self.object(depth),
                Some(b'[') => self.array(depth),
                Some(b'"') => Ok(Value::String(self.string()?)),
                Some(b't') => self.literal(b"true", Value::Bool(true)),
                Some(b'f') => self.literal(b"false", Value::Bool(false)),
                Some(b'n') => self.literal(b"null", Value::Null),
                Some(b'-' | b'0'..=b'9') => self.number(),
                _ => Err(ListError::Syntax("expected a value")),
            }
        }

        fn object(&mut self, depth: usize) -> Result<Value, ListError> {
            self.expect(b'{')?;
            let mut fields: Vec<(String, Value)> = Vec::new();
            self.space();
            if self.peek() == Some(b'}') {
                self.at += 1;
                return Ok(Value::Object(fields));
            }
            loop {
                self.space();
                let key = self.string()?;
                if fields.iter().any(|(k, _)| *k == key) {
                    return Err(ListError::Syntax("a key appears twice in one object"));
                }
                self.space();
                self.expect(b':')?;
                let value = self.value(depth + 1)?;
                fields.push((key, value));
                self.space();
                match self.peek() {
                    Some(b',') => self.at += 1,
                    Some(b'}') => {
                        self.at += 1;
                        return Ok(Value::Object(fields));
                    }
                    _ => return Err(ListError::Syntax("expected , or }")),
                }
            }
        }

        fn array(&mut self, depth: usize) -> Result<Value, ListError> {
            self.expect(b'[')?;
            let mut items = Vec::new();
            self.space();
            if self.peek() == Some(b']') {
                self.at += 1;
                return Ok(Value::Array(items));
            }
            loop {
                items.push(self.value(depth + 1)?);
                self.space();
                match self.peek() {
                    Some(b',') => self.at += 1,
                    Some(b']') => {
                        self.at += 1;
                        return Ok(Value::Array(items));
                    }
                    _ => return Err(ListError::Syntax("expected , or ]")),
                }
            }
        }

        fn number(&mut self) -> Result<Value, ListError> {
            let start = self.at;
            if self.peek() == Some(b'-') {
                self.at += 1;
            }
            match self.peek() {
                Some(b'0') => self.at += 1,
                Some(b'1'..=b'9') => self.digits(),
                _ => return Err(ListError::Syntax("bad number")),
            }
            if self.peek() == Some(b'.') {
                self.at += 1;
                self.digits_required()?;
            }
            if let Some(b'e' | b'E') = self.peek() {
                self.at += 1;
                if let Some(b'+' | b'-') = self.peek() {
                    self.at += 1;
                }
                self.digits_required()?;
            }
            let text = core::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| ListError::Syntax("bad number"))?;
            Ok(Value::Number(text.to_owned()))
        }

        fn digits(&mut self) {
            while let Some(b'0'..=b'9') = self.peek() {
                self.at += 1;
            }
        }

        fn digits_required(&mut self) -> Result<(), ListError> {
            let start = self.at;
            self.digits();
            if self.at == start { Err(ListError::Syntax("bad number")) } else { Ok(()) }
        }

        fn hex4(&mut self) -> Result<u32, ListError> {
            let end = self.at + 4;
            let digits = self.bytes.get(self.at..end).ok_or(ListError::Syntax("bad escape"))?;
            let text = core::str::from_utf8(digits).map_err(|_| ListError::Syntax("bad escape"))?;
            if !text.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(ListError::Syntax("bad escape"));
            }
            self.at = end;
            u32::from_str_radix(text, 16).map_err(|_| ListError::Syntax("bad escape"))
        }

        fn string(&mut self) -> Result<String, ListError> {
            self.expect(b'"')?;
            let mut out = String::new();
            loop {
                let start = self.at;
                while let Some(c) = self.peek() {
                    if c == b'"' || c == b'\\' || c < 0x20 {
                        break;
                    }
                    self.at += 1;
                }
                let run = core::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| ListError::Syntax("not UTF-8"))?;
                out.push_str(run);
                match self.peek() {
                    Some(b'"') => {
                        self.at += 1;
                        return Ok(out);
                    }
                    Some(b'\\') => {
                        self.at += 1;
                        let escape = self.peek().ok_or(ListError::Syntax("bad escape"))?;
                        self.at += 1;
                        let c = match escape {
                            b'"' => '"',
                            b'\\' => '\\',
                            b'/' => '/',
                            b'b' => '\u{8}',
                            b'f' => '\u{c}',
                            b'n' => '\n',
                            b'r' => '\r',
                            b't' => '\t',
                            b'u' => {
                                let first = self.hex4()?;
                                let code = if (0xd800..0xdc00).contains(&first) {
                                    self.expect(b'\\')?;
                                    self.expect(b'u')?;
                                    let second = self.hex4()?;
                                    if !(0xdc00..0xe000).contains(&second) {
                                        return Err(ListError::Syntax("bad surrogate pair"));
                                    }
                                    0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                                } else {
                                    first
                                };
                                char::from_u32(code).ok_or(ListError::Syntax("bad escape"))?
                            }
                            _ => return Err(ListError::Syntax("bad escape")),
                        };
                        out.push(c);
                    }
                    _ => return Err(ListError::Syntax("unterminated string")),
                }
            }
        }
    }
}
