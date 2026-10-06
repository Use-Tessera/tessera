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
