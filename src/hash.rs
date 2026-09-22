// a witness is written by one run and checked by another, so the function that
// produced it has to travel with it. without the tag an upgrade that changes
// the preferred function silently reinterprets every recorded value as a
// mismatch, which for a writable destination means reporting an edit that never
// happened.
//
// schema 2 predates the tag. every hash it holds is sha-256 by construction, so
// a bare hex string is read as sha-256 and the v3 migration writes the name in.
const SHA256_TAG: &str = "sha256:";
const BLAKE3_TAG: &str = "blake3:";
const HEX_DIGEST_LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Algorithm {
    Sha256,
    Blake3,
}

impl Algorithm {
    fn tag(self) -> &'static str {
        match self {
            Self::Sha256 => SHA256_TAG,
            Self::Blake3 => BLAKE3_TAG,
        }
    }

    fn hex(self, bytes: &[u8]) -> String {
        match self {
            Self::Sha256 => {
                use sha2::Digest;
                sha2::Sha256::digest(bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect()
            }
            Self::Blake3 => blake3::hash(bytes).to_hex().to_string(),
        }
    }
}

// the one function that produces new witnesses. nothing else picks an
// algorithm, so there is no path by which a fresh record acquires a legacy one.
pub(crate) fn witness(bytes: &[u8]) -> String {
    witness_in(Algorithm::Blake3, bytes)
}

pub(crate) fn witness_in(algorithm: Algorithm, bytes: &[u8]) -> String {
    format!("{}{}", algorithm.tag(), algorithm.hex(bytes))
}

// an unreadable witness is not a mismatch, it is a ledger this build cannot
// reason about, and the caller has to be able to refuse rather than conclude.
pub(crate) fn split(recorded: &str) -> Option<(Algorithm, &str)> {
    for algorithm in [Algorithm::Sha256, Algorithm::Blake3] {
        if let Some(hex) = recorded.strip_prefix(algorithm.tag()) {
            return is_hex_digest(hex).then_some((algorithm, hex));
        }
    }
    is_hex_digest(recorded).then_some((Algorithm::Sha256, recorded))
}

pub(crate) fn algorithm_of(recorded: &str) -> Option<Algorithm> {
    split(recorded).map(|(algorithm, _)| algorithm)
}

// verification re-runs the function named by the record rather than the one
// this build prefers. that asymmetry is the point of the tag, and it is what
// lets a schema 2 baseline stay checkable while every witness written from here
// on is blake3.
pub(crate) fn matches(recorded: &str, bytes: &[u8]) -> bool {
    split(recorded).is_some_and(|(algorithm, hex)| algorithm.hex(bytes) == hex)
}

// the v3 migration writes the name into a value that already has an algorithm,
// it does not measure anything. recomputing instead would look tidier and would
// be wrong: a writable baseline says what furnish last wrote, and re-deriving
// it from whatever is at the destination now would quietly turn an edit into a
// pristine file.
pub(crate) fn name_untagged(recorded: &mut Option<String>) {
    if let Some(value) = recorded.as_deref()
        && is_hex_digest(value)
    {
        *recorded = Some(format!("{SHA256_TAG}{value}"));
    }
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == HEX_DIGEST_LENGTH && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    // pinned to reference digests rather than to this crate's own output, so a
    // wiring mistake that is self-consistent still fails.
    #[test]
    fn sha256_reproduces_known_answers() {
        assert_eq!(
            Algorithm::Sha256.hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            Algorithm::Sha256.hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            Algorithm::Sha256.hex(&[b'a'; 119]),
            "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb"
        );
    }

    #[test]
    fn blake3_reproduces_known_answers() {
        assert_eq!(
            Algorithm::Blake3.hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            Algorithm::Blake3.hex(b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn a_new_witness_names_blake3() {
        assert_eq!(
            witness(b"abc"),
            "blake3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    // the compatibility rule schema 2 depends on. an untagged digest is sha-256
    // because nothing else could have written one.
    #[test]
    fn an_untagged_digest_reads_as_sha256() {
        let bare = Algorithm::Sha256.hex(b"abc");
        assert_eq!(algorithm_of(&bare), Some(Algorithm::Sha256));
        assert!(matches(&bare, b"abc"));
        assert!(!matches(&bare, b"abd"));
    }

    #[test]
    fn verification_follows_the_recorded_algorithm_not_the_preferred_one() {
        // the same bytes under both names, each verifying only against its own
        // digest. a check that reached for the preferred function instead would
        // pass the blake3 case and fail the sha-256 one.
        for algorithm in [Algorithm::Sha256, Algorithm::Blake3] {
            let recorded = witness_in(algorithm, b"payload\n");
            assert_eq!(algorithm_of(&recorded), Some(algorithm));
            assert!(matches(&recorded, b"payload\n"));
            assert!(!matches(&recorded, b"payload"));
        }
    }

    #[test]
    fn an_unreadable_witness_is_refused_rather_than_read_as_a_mismatch() {
        for recorded in [
            "",
            "sha256:",
            "blake3:short",
            "md5:0123456789abcdef0123456789abcdef",
            "not-hex-not-hex-not-hex-not-hex-not-hex-not-hex-not-hex-not-hex-",
            &"a".repeat(63),
            &"a".repeat(65),
        ] {
            assert_eq!(algorithm_of(recorded), None, "{recorded}");
            assert!(!matches(recorded, b"anything"), "{recorded}");
        }
    }
}
