//! Fuzzing of the pre-key handshake link layer (HsLink): arbitrary and mutated 23-byte superframes
//! fed to the receive side, plus two links talking over a lossy, duplicating, reordering and
//! corrupting channel.
//!
//! Invariants asserted:
//!  * nothing panics, whatever the frame bytes;
//!  * memory is bounded by the declared message sizes: the number of fragments the receiver stores
//!    never exceeds the sum of fragment_count(t) over the seven message types, a fragment index at or
//!    beyond fragment_count(t) is rejected (BadIndex), and send() accepts only message_len(t) bytes,
//!    each type once;
//!  * frames damaged by up to 3 flipped bits are always dropped as BadCrc, and honest-channel faults
//!    (loss, duplication, reordering, foreign tags, corruption) never change a delivered message: it is
//!    byte-for-byte what the sender queued, delivered at most once;
//!  * frames that are forged with a valid CRC can only be told apart by the layer above (a CRC is not
//!    a MAC), so for them the receiver is checked against an independent reassembly model and a
//!    completed message may differ from the sender's only if a forged fragment was accepted into it;
//!  * after set_established / close the link never delivers anything and stops emitting frames.
//!
//! Knobs: AEGIS_FUZZ_ITERS, AEGIS_FUZZ_SEED.

use aegiscall_chat::hs_link::{
    fragment_count, message_len, HsLink, HsLinkError, FRAME_ABORT, FRAME_ACK, HS_DATA_LEN, HS_FRAME_LEN, HS_MAGIC,
    POST_ESTABLISH_MAX_FRAMES,
};
use aegiscall_modem::crc16_ccitt;
use std::collections::HashMap;

const DEFAULT_SEED: u64 = 0x0AE6_15C4_411C_2611;

struct Rng(u64);

impl Rng {
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.step() % n as u64) as usize
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.step() % 100 < pct
    }
    fn byte(&mut self) -> u8 {
        self.step() as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
}

fn env_u64(name: &str) -> Option<u64> {
    let v = std::env::var(name).ok()?;
    let v = v.trim();
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

fn iters() -> u64 {
    env_u64("AEGIS_FUZZ_ITERS").unwrap_or(if cfg!(debug_assertions) { 40 } else { 10_000 })
}

fn base_seed() -> u64 {
    env_u64("AEGIS_FUZZ_SEED").unwrap_or(DEFAULT_SEED)
}

type Frame = [u8; HS_FRAME_LEN];

fn total_fragments() -> u64 {
    (1..=7u8).map(|t| fragment_count(t).expect("type 1-7") as u64).sum()
}

fn fix_crc(f: &mut Frame) {
    let c = crc16_ccitt(&f[..21]);
    f[21..23].copy_from_slice(&c.to_be_bytes());
}

fn crc_ok(f: &Frame) -> bool {
    crc16_ccitt(&f[..21]) == u16::from_be_bytes([f[21], f[22]])
}

fn hex(f: &Frame) -> String {
    f.iter().map(|b| format!("{b:02x}")).collect()
}

/// A frame emitted by our own link must always be well formed for an honest peer.
fn check_emitted(f: &Frame, tag: u8) {
    assert!(crc_ok(f), "emitted frame has a bad CRC: {}", hex(f));
    assert_eq!(f[0] & 0xF0, HS_MAGIC, "emitted frame lacks the magic: {}", hex(f));
    assert_eq!(f[2], tag, "emitted frame carries a foreign tag: {}", hex(f));
    match f[0] & 0x0F {
        k @ 1..=7 => {
            let n = fragment_count(k).expect("type");
            assert!(usize::from(f[1]) < n, "emitted fragment index {} out of range for type {k}: {}", f[1], hex(f));
        }
        FRAME_ACK => assert!(f[1] <= 7, "ACK for unknown type: {}", hex(f)),
        FRAME_ABORT => {}
        k => panic!("emitted frame of unknown kind {k}: {}", hex(f)),
    }
}

/// Queues a random non-empty subset of the seven message types; returns type -> body.
fn queue_messages(link: &mut HsLink, rng: &mut Rng, all: bool) -> HashMap<u8, Vec<u8>> {
    let mut m = HashMap::new();
    while m.is_empty() {
        for t in 1..=7u8 {
            if all || rng.chance(50) {
                let body = rng.bytes(message_len(t).expect("type"));
                link.send(t, body.clone()).expect("queue message");
                m.insert(t, body);
            }
        }
    }
    m
}

struct Honest {
    tag: u8,
    frames: Vec<Frame>,
    bodies: HashMap<u8, Vec<u8>>,
    frag: HashMap<(u8, usize), [u8; HS_DATA_LEN]>,
}

/// Runs an honest sender until every fragment of every queued message has been emitted once.
fn honest_sender(rng: &mut Rng, all: bool) -> Honest {
    let tag = rng.byte();
    let mut link = HsLink::new(tag);
    let bodies = queue_messages(&mut link, rng, all);
    let mut frag = HashMap::new();
    for (t, b) in &bodies {
        for (i, c) in b.chunks(HS_DATA_LEN).enumerate() {
            let mut d = [0u8; HS_DATA_LEN];
            d[..c.len()].copy_from_slice(c);
            frag.insert((*t, i), d);
        }
    }
    let mut frames: Vec<Frame> = Vec::new();
    let mut seen: HashMap<(u8, u8), ()> = HashMap::new();
    for _ in 0..20_000 {
        let f = link.next_frame();
        check_emitted(&f, tag);
        let k = f[0] & 0x0F;
        if (1..=7).contains(&k) && seen.insert((k, f[1]), ()).is_none() {
            frames.push(f);
        }
        if frames.len() == frag.len() {
            break;
        }
    }
    assert_eq!(frames.len(), frag.len(), "sender never emitted every fragment");
    Honest { tag, frames, bodies, frag }
}

/// Flips 1 to 3 distinct bits (CRC-16/CCITT always detects that few).
fn flip_bits(rng: &mut Rng, f: &mut Frame) {
    let n = 1 + rng.below(3);
    let mut picked: Vec<usize> = Vec::new();
    while picked.len() < n {
        let b = rng.below(HS_FRAME_LEN * 8);
        if !picked.contains(&b) {
            picked.push(b);
        }
    }
    for b in picked {
        f[b / 8] ^= 1 << (b % 8);
    }
}

// ---------------------------------------------------------------------------------------------
// 1. Honest-channel faults never change a delivered message.
// ---------------------------------------------------------------------------------------------

#[test]
fn honest_channel_faults_never_change_a_delivered_message() {
    let base = base_seed();
    for it in 0..iters() {
        let mut rng = Rng(base ^ it.wrapping_mul(0xD6E8_FEB8_6659_FD93));
        let h = honest_sender(&mut rng, it % 3 == 0);
        let foreign = honest_sender(&mut rng, false);
        // A stream that starts with an honest frame (the receiver locks its tag on the first frame it
        // sees) followed by every honest frame in random order, duplicates, damaged copies and frames
        // of an unrelated sender.
        let mut stream: Vec<(Frame, u8)> = Vec::new(); // (frame, 0 honest | 1 damaged | 2 foreign)
        let mut order: Vec<usize> = (0..h.frames.len()).collect();
        for i in (1..order.len()).rev() {
            order.swap(i, rng.below(i + 1));
        }
        for &i in &order {
            stream.push((h.frames[i], 0));
            while rng.chance(35) {
                stream.push((h.frames[rng.below(h.frames.len())], 0));
            }
            if rng.chance(25) {
                let mut d = h.frames[rng.below(h.frames.len())];
                flip_bits(&mut rng, &mut d);
                stream.push((d, 1));
            }
            if rng.chance(25) && foreign.tag != h.tag {
                stream.push((foreign.frames[rng.below(foreign.frames.len())], 2));
            }
        }
        let mut link = HsLink::new(h.tag.wrapping_add(1));
        let mut got: HashMap<u8, Vec<u8>> = HashMap::new();
        for (n, (f, kind)) in stream.iter().enumerate() {
            let r = link.on_frame(f);
            match (kind, &r) {
                (0, Ok(None)) => {}
                (0, Ok(Some((t, body)))) => {
                    assert_eq!(Some(body), h.bodies.get(t), "delivered message of type {t} differs from the sent one (frame {n})");
                    assert!(got.insert(*t, body.clone()).is_none(), "type {t} delivered twice");
                }
                (1, Err(HsLinkError::BadCrc)) => {}
                (2, Err(HsLinkError::ForeignTag)) => {}
                _ => panic!("frame {n} (class {kind}) produced {r:?}: {}", hex(f)),
            }
            assert!(link.received_fragments() <= total_fragments(), "fragment store exceeds the declared bound");
            if rng.chance(10) {
                check_emitted(&link.next_frame(), link.tag());
            }
        }
        assert_eq!(got.len(), h.bodies.len(), "not every message was delivered");
        assert_eq!(link.received_fragments(), h.frag.len() as u64, "stored fragment count differs from the fragments sent");
        for (t, b) in &h.bodies {
            assert_eq!(got.get(t), Some(b), "message {t} corrupted");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 2. CRC-valid forgeries against an independent reassembly model.
// ---------------------------------------------------------------------------------------------

type Out = Result<Option<(u8, Vec<u8>)>, HsLinkError>;

struct Slot {
    frags: Vec<Option<[u8; HS_DATA_LEN]>>,
    done: bool,
    tainted: bool,
}

struct Model {
    peer_tag: Option<u8>,
    slots: HashMap<u8, Slot>,
    stored: u64,
}

impl Model {
    fn step(&mut self, f: &Frame, h: &Honest) -> Out {
        if !crc_ok(f) {
            return Err(HsLinkError::BadCrc);
        }
        if f[0] & 0xF0 != HS_MAGIC {
            return Err(HsLinkError::NotHandshake);
        }
        match self.peer_tag {
            Some(t) if t != f[2] => return Err(HsLinkError::ForeignTag),
            _ => {}
        }
        let kind = f[0] & 0x0F;
        // The link under test never sends, so only the empty idle ACK (type 0) can be genuine;
        // any other ACK is dropped before it can lock the tag.
        if kind == FRAME_ACK && (f[1] != 0 || f[3..21].iter().any(|b| *b != 0)) {
            return Err(HsLinkError::UnexpectedAck);
        }
        self.peer_tag.get_or_insert(f[2]);
        match kind {
            FRAME_ABORT => return Err(HsLinkError::PeerAbort(f[1])),
            FRAME_ACK => return Ok(None),
            1..=7 => {}
            _ => return Err(HsLinkError::UnknownType),
        }
        let len = message_len(kind).expect("type");
        let n = len.div_ceil(HS_DATA_LEN);
        let idx = usize::from(f[1]);
        if idx >= n {
            return Err(HsLinkError::BadIndex);
        }
        let mut data = [0u8; HS_DATA_LEN];
        data.copy_from_slice(&f[3..21]);
        let slot = self.slots.entry(kind).or_insert_with(|| Slot { frags: vec![None; n], done: false, tainted: false });
        if slot.done {
            return Ok(None);
        }
        if let Some(old) = slot.frags[idx] {
            return if old == data { Ok(None) } else { Err(HsLinkError::Conflict) };
        }
        slot.frags[idx] = Some(data);
        self.stored += 1;
        if h.frag.get(&(kind, idx)) != Some(&data) {
            slot.tainted = true;
        }
        if slot.frags.iter().any(Option::is_none) {
            return Ok(None);
        }
        slot.done = true;
        let full: Vec<u8> = slot.frags.iter().flat_map(|d| d.expect("complete").to_vec()).collect();
        if full[len..].iter().any(|b| *b != 0) {
            return Err(HsLinkError::BadLength);
        }
        let body = full[..len].to_vec();
        if !slot.tainted {
            assert_eq!(Some(&body), h.bodies.get(&kind), "an untainted message of type {kind} differs from the sent one");
        }
        Ok(Some((kind, body)))
    }
}

fn forge(rng: &mut Rng, h: &Honest) -> Frame {
    let mut f = h.frames[rng.below(h.frames.len())];
    let kind = f[0] & 0x0F;
    let n = fragment_count(kind).unwrap_or(1);
    match rng.below(14) {
        0 => {
            let b = rng.below(21 * 8);
            f[b / 8] ^= 1 << (b % 8);
            fix_crc(&mut f);
        }
        1 => {
            f[0] = HS_MAGIC | (rng.byte() & 0x0F); // any kind incl. 0, 8-0xD, ACK, ABORT
            fix_crc(&mut f);
        }
        2 => {
            f[1] = rng.byte();
            fix_crc(&mut f);
        }
        3 => {
            f[1] = [n as u8, (n - 1) as u8, (n + 1) as u8, 255, 0][rng.below(5)];
            fix_crc(&mut f);
        }
        4 => {
            let p = 3 + rng.below(18);
            for b in &mut f[p..21] {
                *b = 0;
            }
            fix_crc(&mut f);
        }
        5 => {
            f[2] = rng.byte();
            fix_crc(&mut f);
        }
        6 => {
            for b in &mut f[3..21] {
                *b = rng.byte();
            }
            fix_crc(&mut f);
        }
        7 => {
            for b in f.iter_mut() {
                *b = rng.byte();
            }
            f[0] = HS_MAGIC | (f[0] & 0x0F);
            fix_crc(&mut f);
        }
        8 => {
            for b in f.iter_mut() {
                *b = rng.byte();
            }
        }
        9 => {
            // Poison the zero padding of a final fragment (or any byte of a data frame).
            f[0] = HS_MAGIC | kind;
            f[1] = (n - 1) as u8;
            f[3 + rng.below(18)] = 1 + rng.byte() % 255;
            fix_crc(&mut f);
        }
        10 => {
            f[0] = HS_MAGIC | FRAME_ABORT;
            f[1] = rng.byte();
            fix_crc(&mut f);
        }
        11 => {
            f[0] = HS_MAGIC | FRAME_ACK;
            f[1] = rng.byte();
            for b in &mut f[3..21] {
                *b = rng.byte();
            }
            fix_crc(&mut f);
        }
        12 => {
            // High nibble other than the magic, valid CRC.
            f[0] = (f[0] & 0x0F) | (rng.byte() & 0xF0);
            fix_crc(&mut f);
        }
        _ => {
            // Right header, data from another type's fragment (type confusion).
            let other = h.frames[rng.below(h.frames.len())];
            f[3..21].copy_from_slice(&other[3..21]);
            fix_crc(&mut f);
        }
    }
    f
}

#[test]
fn crc_valid_forgeries_match_the_reassembly_model_and_stay_bounded() {
    let base = base_seed() ^ 0x1111;
    for it in 0..iters() {
        let mut rng = Rng(base ^ it.wrapping_mul(0xD6E8_FEB8_6659_FD93));
        let h = honest_sender(&mut rng, it % 3 == 0);
        let mut link = HsLink::new(h.tag.wrapping_add(7));
        let mut model = Model { peer_tag: None, slots: HashMap::new(), stored: 0 };
        let count = 200 + rng.below(400);
        let mut all_frames: Vec<Frame> = Vec::new();
        for n in 0..count {
            let f = if n == 0 || rng.chance(45) { h.frames[rng.below(h.frames.len())] } else { forge(&mut rng, &h) };
            all_frames.push(f);
            let want = model.step(&f, &h);
            let got = link.on_frame(&f);
            assert_eq!(got, want, "iteration {it}, frame {n}: {}", hex(&f));
            if let Ok(Some((t, b))) = &got {
                assert_eq!(b.len(), message_len(*t).expect("type"), "delivered body has the wrong length");
            }
            assert!(link.received_fragments() <= total_fragments(), "fragment store exceeds the declared bound");
            assert_eq!(link.received_fragments(), model.stored, "stored fragment count diverged from the model");
            if rng.chance(8) {
                check_emitted(&link.next_frame(), link.tag());
            }
        }
        // After the keys exist the link delivers nothing and acknowledges nothing.
        link.set_established(rng.chance(50));
        for f in &all_frames {
            match link.on_frame(f) {
                Ok(None) | Err(HsLinkError::BadCrc | HsLinkError::NotHandshake | HsLinkError::ForeignTag) => {}
                other => panic!("established link answered {other:?} to {}", hex(f)),
            }
        }
        let mut wants = 0u32;
        for _ in 0..(POST_ESTABLISH_MAX_FRAMES * 3) {
            if link.post_wants_tx() {
                wants += 1;
            }
            check_emitted(&link.next_frame(), link.tag());
        }
        assert!(wants <= POST_ESTABLISH_MAX_FRAMES, "established link wants to transmit more than the cap ({wants})");
        assert!(!link.post_wants_tx(), "established link still wants to transmit after the cap");
        link.close();
        for f in &all_frames {
            assert_eq!(link.on_frame(f), Ok(None), "closed link reacted to {}", hex(f));
        }
    }
}

#[test]
fn arbitrary_frames_never_panic_and_garbage_is_not_delivered() {
    let mut rng = Rng(base_seed() ^ 0x2222);
    let mut link = HsLink::new(0x5A);
    for i in 0..(iters() * 500) {
        let mut f = [0u8; HS_FRAME_LEN];
        for b in f.iter_mut() {
            *b = rng.byte();
        }
        if i % 2 == 0 {
            f[0] = HS_MAGIC | (f[0] & 0x0F);
            // Mostly one tag so frames get past the tag lock; small indexes so data frames get stored.
            f[2] = 0x33 + u8::from(rng.chance(10));
            if rng.chance(50) {
                f[1] %= 8;
            }
            fix_crc(&mut f);
        }
        if let Ok(Some((t, b))) = link.on_frame(&f) {
            // Possible only after 18-byte-aligned random fragments completed a message; the length
            // must still match the type.
            assert_eq!(b.len(), message_len(t).expect("type"));
        }
        assert!(link.received_fragments() <= total_fragments());
        if i % 64 == 0 {
            check_emitted(&link.next_frame(), link.tag());
        }
        if i % 4096 == 4095 {
            link = HsLink::new(rng.byte());
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 3. Two links over a hostile channel.
// ---------------------------------------------------------------------------------------------

#[test]
fn two_links_over_a_lossy_duplicating_reordering_corrupting_channel_deliver_exactly() {
    let base = base_seed() ^ 0x3333;
    for it in 0..(iters() / 4).max(2) {
        let mut rng = Rng(base ^ it.wrapping_mul(0xD6E8_FEB8_6659_FD93));
        let (ta, tb) = (rng.byte(), rng.byte().wrapping_add(1));
        let (mut a, mut b) = (HsLink::new(ta), HsLink::new(if tb == ta { tb.wrapping_add(1) } else { tb }));
        let (tag_a, tag_b) = (a.tag(), b.tag());
        let sent_a = queue_messages(&mut a, &mut rng, it % 2 == 0);
        let sent_b = queue_messages(&mut b, &mut rng, it % 2 == 1);
        let mut got_a: HashMap<u8, Vec<u8>> = HashMap::new(); // received by a (sent by b)
        let mut got_b: HashMap<u8, Vec<u8>> = HashMap::new();
        let mut queue: Vec<(u64, usize, Frame, bool)> = Vec::new(); // (due, to, frame, damaged)
        let mut finished = false;
        for tick in 0..20_000u64 {
            for side in 0..2usize {
                let (link, tag) = if side == 0 { (&mut a, tag_a) } else { (&mut b, tag_b) };
                let f = link.next_frame();
                check_emitted(&f, tag);
                if rng.chance(25) {
                    continue; // lost
                }
                let copies = if rng.chance(15) { 2 } else { 1 };
                for _ in 0..copies {
                    let mut g = f;
                    let damaged = rng.chance(5);
                    if damaged {
                        flip_bits(&mut rng, &mut g);
                    }
                    queue.push((tick + rng.below(7) as u64, 1 - side, g, damaged));
                }
            }
            let mut i = 0;
            while i < queue.len() {
                if queue[i].0 > tick {
                    i += 1;
                    continue;
                }
                let (_, to, f, damaged) = queue.swap_remove(i);
                let (link, expect, got) = if to == 0 { (&mut a, &sent_b, &mut got_a) } else { (&mut b, &sent_a, &mut got_b) };
                let r = link.on_frame(&f);
                if damaged {
                    assert_eq!(r, Err(HsLinkError::BadCrc), "damaged frame not dropped: {}", hex(&f));
                    continue;
                }
                match r {
                    Ok(None) => {}
                    Ok(Some((t, body))) => {
                        assert_eq!(Some(&body), expect.get(&t), "link {to} delivered a message of type {t} that was not sent");
                        assert!(got.insert(t, body).is_none(), "link {to} delivered type {t} twice");
                    }
                    Err(e) => panic!("link {to} failed on an honest frame: {e:?}"),
                }
            }
            if got_a.len() == sent_b.len() && got_b.len() == sent_a.len() && a.all_acked() && b.all_acked() {
                finished = true;
                break;
            }
        }
        assert!(finished, "iteration {it}: links did not converge (a got {}/{}, b got {}/{})", got_a.len(), sent_b.len(), got_b.len(), sent_a.len());
        assert!(a.received_fragments() <= total_fragments() && b.received_fragments() <= total_fragments());
    }
}

// ---------------------------------------------------------------------------------------------
// 4. Send side bounds.
// ---------------------------------------------------------------------------------------------

#[test]
fn send_accepts_only_declared_sizes_once_per_type() {
    let mut rng = Rng(base_seed() ^ 0x4444);
    for _ in 0..iters() {
        let mut link = HsLink::new(rng.byte());
        let mut accepted = 0;
        for _ in 0..40 {
            let t = rng.byte() % 12;
            let want = message_len(t);
            let len = if rng.chance(50) { want.unwrap_or(rng.below(2100)) } else { rng.below(2100) };
            let r = link.send(t, rng.bytes(len));
            match (want, r) {
                (None, Err(HsLinkError::UnknownType)) => {}
                (Some(w), Err(HsLinkError::BadLength)) => assert_ne!(w, len),
                (Some(w), Err(HsLinkError::DuplicateSend)) => assert_eq!(w, len),
                (Some(w), Ok(())) => {
                    assert_eq!(w, len);
                    accepted += 1;
                }
                (w, r) => panic!("send(type {t}, {len} bytes) with declared length {w:?} gave {r:?}"),
            }
        }
        assert!(accepted <= 7, "more than one message per type was queued");
        for _ in 0..200 {
            check_emitted(&link.next_frame(), link.tag());
        }
        link.set_established(false);
        assert_eq!(link.send(1, rng.bytes(message_len(1).expect("type"))), Err(HsLinkError::DuplicateSend));
    }
}
