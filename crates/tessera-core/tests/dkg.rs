//! Distributed key generation, end to end and under a hostile relay.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]

use tessera_core::Error;
use tessera_core::dkg::{self, Round1Message, Round2Message, State};
use tessera_core::keys::{KdfParams, KeyShare};
use tessera_core::signing;

const FAST: KdfParams = KdfParams { m_cost: 64, t_cost: 1, p_cost: 1 };

/// Runs a whole ceremony, letting `relay` rewrite the round-2 traffic.
fn ceremony(
    threshold: u16,
    signers: u16,
    relay: impl Fn(Vec<Round2Message>) -> Vec<Round2Message>,
) -> Result<Vec<KeyShare>, Error> {
    let (states, round1): (Vec<_>, Vec<_>) = (1..=signers).map(|i| dkg::start(i, threshold, signers).unwrap()).unzip();
    let mut round2 = Vec::new();
    let mut next = Vec::new();
    for s in states {
        let (state, out) = dkg::exchange(s, &round1)?;
        next.push(state);
        round2.extend(out);
    }
    let round2 = relay(round2);
    next.into_iter().map(|s| dkg::finish(s, &round2)).collect()
}

fn signs(shares: &[KeyShare]) {
    let hash = [9u8; 32];
    let sig = signing::sign_message_locally(&hash, shares).unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(&shares[0].group_public_key()).unwrap();
    key.verify_strict(&hash, &ed25519_dalek::Signature::from_bytes(&sig)).unwrap();
}

#[test]
fn every_participant_derives_the_same_group_key() {
    for (t, n) in [(2, 2), (2, 3), (3, 5)] {
        let shares = ceremony(t, n, |m| m).unwrap();
        assert_eq!(shares.len(), usize::from(n));
        assert!(shares.iter().all(|s| s.account() == shares[0].account() && s.threshold() == t));
        // Any threshold-sized subset signs for the group.
        signs(&shares[..usize::from(t)]);
        signs(&shares[usize::from(n - t)..]);
    }
}

#[test]
fn fewer_than_threshold_cannot_sign() {
    let shares = ceremony(3, 5, |m| m).unwrap();
    assert!(signing::sign_message_locally(&[1; 32], &shares[..2]).is_err());
}

#[test]
fn the_relay_cannot_read_or_alter_round_two() {
    // Flip one ciphertext bit.
    let err = ceremony(2, 3, |mut m| {
        let c = &mut m[0].ciphertext;
        let flipped = if c.ends_with('0') { "1" } else { "0" };
        c.replace_range(c.len() - 1.., flipped);
        m
    });
    assert!(matches!(err, Err(Error::Dkg(ref e)) if e.contains("does not decrypt")), "{err:?}");

    // Re-address a package to a different recipient: the AAD no longer matches.
    let err = ceremony(2, 3, |mut m| {
        let sender = m[0].from.clone();
        let other = m.iter().find(|x| x.from == sender && x.to != m[0].to).unwrap().to.clone();
        let original = m[0].to.clone();
        for x in m.iter_mut().filter(|x| x.from == sender) {
            x.to = if x.to == original { other.clone() } else { original.clone() };
        }
        m
    });
    assert!(matches!(err, Err(Error::Dkg(ref e)) if e.contains("does not decrypt")), "{err:?}");

    // Drop a message.
    let err = ceremony(2, 3, |mut m| {
        m.pop();
        m
    });
    assert!(matches!(err, Err(Error::Dkg(ref e)) if e.contains("expected 2 round-2 messages")), "{err:?}");

    // Replay a message twice.
    let err = ceremony(2, 3, |mut m| {
        m.push(m[0].clone());
        m
    });
    assert!(matches!(err, Err(Error::Dkg(ref e)) if e.contains("two round-2 messages")), "{err:?}");
}

#[test]
fn round_one_must_be_complete_and_consistent() {
    let (s1, m1) = dkg::start(1, 2, 3).unwrap();
    let (_, m2) = dkg::start(2, 2, 3).unwrap();
    let (_, m3) = dkg::start(3, 2, 3).unwrap();
    let (_, other_group) = dkg::start(3, 3, 3).unwrap();
    let (_, impostor) = dkg::start(1, 2, 3).unwrap();
    let try_with = |set: Vec<Round1Message>| match dkg::exchange(clone_state(&s1), &set) {
        Err(Error::Dkg(e)) => e,
        other => panic!("{:?}", other.map(|_| ())),
    };
    assert!(try_with(vec![m2.clone()]).contains("expected 3 round-1 messages"));
    assert!(try_with(vec![m2.clone(), other_group]).contains("running 3-of-3"));
    assert!(try_with(vec![m2.clone(), m2.clone(), m3.clone()]).contains("two round-1 messages"));
    assert!(try_with(vec![impostor, m2.clone(), m3.clone()]).contains("different message under this participant"));
    // Including one's own message is fine.
    assert!(dkg::exchange(clone_state(&s1), &[m1, m2, m3]).is_ok());
}

#[test]
fn bad_parameters_are_rejected() {
    assert!(matches!(dkg::start(1, 1, 3), Err(Error::Threshold { .. })));
    assert!(matches!(dkg::start(1, 4, 3), Err(Error::Threshold { .. })));
    assert!(matches!(dkg::start(0, 2, 3), Err(Error::Dkg(_))));
    assert!(matches!(dkg::start(4, 2, 3), Err(Error::Dkg(_))));
}

#[test]
fn fingerprints_ignore_order_and_catch_substitution() {
    let msgs: Vec<_> = (1..=3).map(|i| dkg::start(i, 2, 3).unwrap().1).collect();
    let mut reversed = msgs.clone();
    reversed.reverse();
    assert_eq!(dkg::fingerprint(&msgs).unwrap(), dkg::fingerprint(&reversed).unwrap());

    let mut swapped = msgs.clone();
    swapped[1].encryption_key = dkg::start(2, 2, 3).unwrap().1.encryption_key;
    assert_ne!(dkg::fingerprint(&msgs).unwrap(), dkg::fingerprint(&swapped).unwrap());
}

#[test]
fn state_survives_sealing_between_steps() {
    let (states, round1): (Vec<_>, Vec<_>) = (1..=3).map(|i| dkg::start(i, 2, 3).unwrap()).unzip();

    // Step 1 → disk → step 2 → disk → step 3, for every participant.
    let mut sealed = Vec::new();
    for s in &states {
        let f = s.seal(b"pass", FAST).unwrap();
        let f = dkg::StateFile::from_json(&f.to_json().unwrap()).unwrap();
        assert_eq!(f.step, 1);
        assert!(matches!(f.open(b"wrong"), Err(Error::Decrypt)));
        sealed.push(f);
    }
    let mut round2 = Vec::new();
    let mut after = Vec::new();
    for f in sealed {
        let State::Round1(s) = f.open(b"pass").unwrap() else { panic!("step 1") };
        let (s, out) = dkg::exchange(s, &round1).unwrap();
        round2.extend(out);
        after.push(dkg::StateFile::from_json(&s.seal(b"pass", FAST).unwrap().to_json().unwrap()).unwrap());
    }
    let shares: Vec<_> = after
        .into_iter()
        .map(|f| {
            let State::Round2(s) = f.open(b"pass").unwrap() else { panic!("step 2") };
            dkg::finish(s, &round2).unwrap()
        })
        .collect();
    signs(&shares[1..]);

    // The header is authenticated: relabelling the step breaks decryption.
    let mut f = states[0].seal(b"pass", FAST).unwrap();
    f.step = 2;
    assert!(matches!(f.open(b"pass"), Err(Error::Decrypt)));
}

/// Round-trips a state through sealing, since states are deliberately not `Clone`.
fn clone_state(s: &dkg::Round1State) -> dkg::Round1State {
    match s.seal(b"x", FAST).unwrap().open(b"x").unwrap() {
        State::Round1(s) => s,
        State::Round2(_) => unreachable!(),
    }
}

/// Refreshes `shares`, sealing and reopening each state between steps as the CLI does.
fn refresh(shares: &[KeyShare]) -> Result<Vec<KeyShare>, Error> {
    let n = u16::try_from(shares.len()).unwrap();
    let (states, round1): (Vec<_>, Vec<_>) = shares.iter().map(|s| dkg::start_refresh(s, n).unwrap()).unzip();
    let mut round2 = Vec::new();
    let mut next = Vec::new();
    for s in &states {
        let (state, out) = dkg::exchange(clone_state(s), &round1)?;
        let State::Round2(state) = state.seal(b"x", FAST)?.open(b"x")? else { unreachable!() };
        next.push(state);
        round2.extend(out);
    }
    next.into_iter().map(|s| dkg::finish(s, &round2)).collect()
}

fn cannot_sign(shares: &[KeyShare]) {
    let hash = [5u8; 32];
    if let Ok(sig) = signing::sign_message_locally(&hash, shares) {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&shares[0].group_public_key()).unwrap();
        assert!(key.verify_strict(&hash, &ed25519_dalek::Signature::from_bytes(&sig)).is_err());
    }
}

#[test]
fn refresh_keeps_the_account_and_retires_old_shares() {
    let old = keys_from_dealer(2, 3);
    let new = refresh(&old).unwrap();
    assert!(new.iter().all(|s| s.account() == old[0].account() && s.threshold() == 2));
    signs(&new[..2]);
    signs(&new[1..]);
    // A share that leaked before the refresh is useless with one from after it.
    cannot_sign(&[old[0].clone(), new[1].clone()]);
    cannot_sign(&[new[0].clone(), old[2].clone()]);
}

#[test]
fn refresh_can_drop_a_participant() {
    let old = ceremony(2, 3, |m| m).unwrap();
    let kept = refresh(&old[..2]).unwrap();
    signs(&kept);
    assert_eq!(kept[0].account(), old[0].account());
    // The dropped participant's share no longer combines with anyone's.
    cannot_sign(&[kept[0].clone(), old[2].clone()]);
    cannot_sign(&[old[2].clone(), kept[1].clone()]);
}

#[test]
fn refresh_and_new_key_messages_do_not_mix() {
    let old = keys_from_dealer(2, 2);
    let (s, _) = dkg::start_refresh(&old[0], 2).unwrap();
    let (_, fresh) = dkg::start(2, 2, 2).unwrap();
    assert!(matches!(dkg::exchange(s, &[fresh]), Err(Error::Dkg(ref e)) if e.contains("generating a new key")));

    let other = keys_from_dealer(2, 2);
    let (s, _) = dkg::start_refresh(&old[0], 2).unwrap();
    let (_, foreign) = dkg::start_refresh(&other[1], 2).unwrap();
    assert!(matches!(dkg::exchange(s, &[foreign]), Err(Error::Dkg(ref e)) if e.contains("refreshing")));

    assert!(matches!(dkg::start_refresh(&old[0], 1), Err(Error::Dkg(_))));
    assert!(matches!(dkg::start_refresh(&old[0], 3), Err(Error::Dkg(_))));
}

fn keys_from_dealer(t: u16, n: u16) -> Vec<KeyShare> {
    tessera_core::keys::deal(t, n).unwrap()
}
