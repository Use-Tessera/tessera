//! A whole `tessera dkg` ceremony, three participants in separate directories.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, missing_docs)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn tessera(pass: &str) -> Command {
    let mut c = Command::cargo_bin("tessera").unwrap();
    c.env("TESSERA_PASSPHRASE", pass);
    c
}

fn stdout(c: &mut Command) -> String {
    let o = c.output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap().trim().to_owned()
}

fn files(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(prefix))
        .collect();
    v.sort();
    v
}

#[test]
fn three_participants_agree_on_one_account() {
    let tmp = tempfile::tempdir().unwrap();
    let board = tmp.path().join("board"); // what the participants share
    std::fs::create_dir(&board).unwrap();
    let home: Vec<PathBuf> = (1..=3).map(|i| tmp.path().join(format!("p{i}"))).collect();
    let pass = ["one", "two", "three"];

    for i in 0..3 {
        std::fs::create_dir(&home[i]).unwrap();
        let state = home[i].join("dkg.state");
        let msg = stdout(
            tessera(pass[i])
                .args(["dkg", "start", "--insecure-fast-kdf", "--threshold", "2", "--signers", "3", "--index"])
                .arg((i + 1).to_string())
                .arg("--state")
                .arg(&state),
        );
        std::fs::write(board.join(format!("round1-{}.json", i + 1)), msg).unwrap();
        // A second start would overwrite the secret state.
        tessera(pass[i])
            .args(["dkg", "start", "--threshold", "2", "--signers", "3", "--index", "1", "--state"])
            .arg(&state)
            .assert()
            .code(2);
    }

    let round1 = files(&board, "round1-");
    let fingerprint = stdout(tessera("").args(["dkg", "fingerprint"]).args(&round1));
    assert_eq!(fingerprint.len(), 64);

    // A wrong fingerprint stops the exchange before anything is sent.
    let wrong = format!("{}0", &fingerprint[..63]);
    let wrong = if wrong == fingerprint { format!("{}1", &fingerprint[..63]) } else { wrong };
    tessera(pass[0])
        .args(["dkg", "exchange", "--fingerprint", &wrong, "--state"])
        .arg(home[0].join("dkg.state"))
        .arg("--out")
        .arg(&board)
        .args(&round1)
        .assert()
        .code(2)
        .stderr(predicates::str::contains("a message was changed or is missing"));

    for i in 0..3 {
        stdout(
            tessera(pass[i])
                .args(["dkg", "exchange", "--fingerprint", &fingerprint, "--state"])
                .arg(home[i].join("dkg.state"))
                .arg("--out")
                .arg(&board)
                .args(&round1),
        );
    }
    let round2 = files(&board, "round2-");
    assert_eq!(round2.len(), 6);

    let mut accounts = Vec::new();
    for i in 0..3 {
        let share = home[i].join("share.json");
        accounts.push(stdout(
            tessera(pass[i])
                .args(["dkg", "finish", "--state"])
                .arg(home[i].join("dkg.state"))
                .arg("--out")
                .arg(&share)
                .args(&round2),
        ));
        assert!(!home[i].join("dkg.state").exists(), "state must be deleted once the share exists");
        let info = stdout(Command::cargo_bin("tessera").unwrap().arg("share").arg(&share));
        assert!(info.contains(&accounts[i]) && info.contains("2 of 3"), "{info}");
    }
    assert!(accounts[0].starts_with('G') && accounts.iter().all(|a| *a == accounts[0]), "{accounts:?}");
}

#[test]
fn wrong_passphrase_cannot_continue() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("dkg.state");
    let msg = stdout(
        tessera("right")
            .args([
                "dkg",
                "start",
                "--insecure-fast-kdf",
                "--index",
                "1",
                "--threshold",
                "2",
                "--signers",
                "2",
                "--state",
            ])
            .arg(&state),
    );
    let r1 = tmp.path().join("r1.json");
    std::fs::write(&r1, msg).unwrap();
    tessera("wrong")
        .args(["dkg", "exchange", "--fingerprint", "00", "--out"])
        .arg(tmp.path())
        .arg("--state")
        .arg(&state)
        .arg(&r1)
        .assert()
        .code(2)
        .stderr(predicates::str::contains("wrong passphrase"));
}
