//! End-to-end tests of the `tessera` binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, missing_docs)]

use assert_cmd::Command;

const ENVELOPE: &str = include_str!("../../tessera-core/tests/fixtures/payment.xdr");
const POLICY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/policy.toml");

fn tessera() -> Command {
    Command::cargo_bin("tessera").unwrap()
}

fn out(cmd: &mut Command) -> String {
    String::from_utf8(cmd.output().unwrap().stdout).unwrap()
}

#[test]
fn keygen_writes_encrypted_shares_that_agree_on_the_account() {
    let dir = tempfile::tempdir().unwrap();
    let account = out(tessera()
        .args(["keygen", "--threshold", "2", "--signers", "3", "--insecure-fast-kdf", "--out"])
        .arg(dir.path())
        .env("TESSERA_PASSPHRASE", "pw"))
    .trim()
    .to_owned();
    assert!(account.starts_with('G') && account.len() == 56, "{account}");
    for i in 1..=3 {
        let path = dir.path().join(format!("share-{i}.json"));
        let info = out(tessera().arg("share").arg(&path));
        assert!(info.contains(&account) && info.contains("2 of 3"), "{info}");
    }
    // Refuses to overwrite existing shares.
    tessera()
        .args(["keygen", "--threshold", "2", "--signers", "3", "--insecure-fast-kdf", "--out"])
        .arg(dir.path())
        .env("TESSERA_PASSPHRASE", "pw")
        .assert()
        .code(2);
}

#[test]
fn keygen_requires_passphrases() {
    let dir = tempfile::tempdir().unwrap();
    tessera()
        .args(["keygen", "--threshold", "2", "--signers", "2", "--out"])
        .arg(dir.path())
        .env_remove("TESSERA_PASSPHRASE")
        .assert()
        .code(2);
}

#[test]
fn inspect_shows_the_intent_and_hash() {
    let s = out(tessera().args(["inspect", "--network", "testnet", ENVELOPE.trim()]));
    assert!(s.contains("pay 1 native to G"), "{s}");
    assert!(s.lines().next().unwrap().starts_with("hash        "), "{s}");
}

#[test]
fn check_refuses_with_reasons() {
    // The fixture's source is not this account, and its expiry has long passed.
    let other = "GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR";
    let output =
        tessera().args(["check", "--policy", POLICY, "--account", other, "-"]).write_stdin(ENVELOPE).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let s = String::from_utf8(output.stdout).unwrap();
    assert!(s.starts_with("REFUSED") && s.contains("not the group account"), "{s}");
}

#[test]
fn check_judges_authorization_entries() {
    let t: serde_json::Value =
        serde_json::from_str(include_str!("../../tessera-signer/tests/fixtures/transcript.json")).unwrap();
    let (entry, account) = (t["auth"]["entry"].as_str().unwrap(), t["account"].as_str().unwrap());
    let dir = tempfile::tempdir().unwrap();
    let with_auth = dir.path().join("policy.toml");
    let token = "[[token]]\ncontract = \"CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC\"";
    let extra =
        format!("\n[auth]\nmax_validity_ledgers = 120\n{token}\nper_transaction = \"100\"\nper_day = \"500\"\n");
    std::fs::write(&with_auth, std::fs::read_to_string(POLICY).unwrap() + &extra).unwrap();

    let run = |policy: &std::path::Path, latest: &str| {
        let o = tessera()
            .args(["check", "--account", account, "--latest-ledger", latest, "--policy"])
            .arg(policy)
            .arg("-")
            .write_stdin(entry)
            .output()
            .unwrap();
        (o.status.code(), String::from_utf8(o.stdout).unwrap(), String::from_utf8(o.stderr).unwrap())
    };

    let (code, stdout, stderr) = run(&with_auth, "1000");
    assert_eq!(code, Some(0), "{stdout}");
    assert!(stderr.contains("transfer 50000000 units of token CDLZFC3S"), "{stderr}");

    // Too far ahead of the given ledger.
    let (code, stdout, _) = run(&with_auth, "900");
    assert_eq!(code, Some(1));
    assert!(stdout.contains("max_validity_ledgers"), "{stdout}");

    // The shipped example has no [auth] section, so it refuses all entries.
    let (code, stdout, _) = run(std::path::Path::new(POLICY), "1000");
    assert_eq!(code, Some(1));
    assert!(stdout.contains("[auth]"), "{stdout}");
}
