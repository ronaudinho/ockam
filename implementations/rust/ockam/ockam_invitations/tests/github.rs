use minicbor::{Decode, Encode};
use ockam_invitations::ed25519::ED25519;
use ockam_invitations::github::{self, GitHub, GITHUB};
use ockam_invitations::{ed25519, ssh};
use ockam_invitations::{Acceptance, Envelope, Invitation, Meta, Tag, Verifier};

#[rustfmt::skip]
const SEC_KEY_A: &str =
    r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDykFN/AqYgHYjhPIYmeO23Y3mcuhGz+ASIEotI+tKs5AAAAIhWN/x+Vjf8
fgAAAAtzc2gtZWQyNTUxOQAAACDykFN/AqYgHYjhPIYmeO23Y3mcuhGz+ASIEotI+tKs5A
AAAEAWXFi5q/hByoJzlW/86VyOu1s29YbubkPM6EGSCbLnUPKQU38CpiAdiOE8hiZ47bdj
eZy6EbP4BIgSi0j60qzkAAAAAWEBAgME
-----END OPENSSH PRIVATE KEY-----"#;

#[rustfmt::skip]
const SEC_KEY_B: &str =
    r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAAQrlcFLE1f0cJb7kvx/Rq00yKKEfv+Ok6jjwFTgLidwAAAIjWt/Uj1rf1
IwAAAAtzc2gtZWQyNTUxOQAAACAAQrlcFLE1f0cJb7kvx/Rq00yKKEfv+Ok6jjwFTgLidw
AAAEAK63SdDCywZ+AyA4ZxT7vgzc3DIXmawI4jwhvUGnnyOQBCuVwUsTV/RwlvuS/H9GrT
TIooR+/46TqOPAVOAuJ3AAAAAWIBAgME
-----END OPENSSH PRIVATE KEY-----"#;

const PUB_KEY_A: &str =
    r#"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPKQU38CpiAdiOE8hiZ47bdjeZy6EbP4BIgSi0j60qzk a"#;

const PUB_KEY_B: &str =
    r#"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIABCuVwUsTV/RwlvuS/H9GrTTIooR+/46TqOPAVOAuJ3 b"#;

const TEST: Tag = Tag(78979);

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
struct TestInvitation<'a>(#[b(0)] &'a str);

impl Meta for TestInvitation<'_> {
    const TAG: Tag = TEST;
}

#[test]
fn github() {
    // prelude

    // identity keys
    let ida = ed25519::SecKey::new();
    let idb = ed25519::SecKey::new();

    // github keys
    let sa = ssh::SecKey::new(SEC_KEY_A).unwrap();
    let pa = ssh::PubKey::new(PUB_KEY_A).unwrap();
    let sb = ssh::SecKey::new(SEC_KEY_B).unwrap();
    let pb = ssh::PubKey::new(PUB_KEY_B).unwrap();

    // initiator

    let i = {
        let ga = GitHub::new("a".to_string(), pa.clone());
        let gb = GitHub::new("b".to_string(), pb.clone());
        github::invite(ida.pubkey(), ga, gb, TestInvitation("hello"))
    };
    let mut e = Envelope::invite(&i).unwrap();
    e.sign(&ida).unwrap();
    e.sign(&sa).unwrap();
    let cbor = minicbor::to_vec(&e).unwrap();

    // recipient

    let cbor = {
        let e: Envelope = minicbor::decode(&cbor).unwrap();
        let (hdr, body) = e.read_data().unwrap();
        assert!(hdr.is_invite());
        assert_eq!(hdr.identity(), ED25519);
        assert_eq!(hdr.initiator(), Some(GITHUB));
        assert_eq!(hdr.recipient(), Some(GITHUB));
        assert_eq!(hdr.data(), Some(TEST));
        let msg: Invitation<ed25519::PubKey, GitHub, GitHub, TestInvitation> =
            minicbor::decode(body).unwrap();
        assert_eq!("a", msg.initiator_info().user());
        assert_eq!("b", msg.recipient_info().user());
        assert_eq!(&pb, msg.recipient_info().key());

        // Assume here we fetch the public key for user "a" from GitHub and check it
        // equals `msg.initiator_info.key()`.

        assert_eq!(2, e.signatures().len());
        assert!(msg.initiator().is_valid(e.data(), &e.signatures()[0]));
        assert!(msg
            .initiator_info()
            .key()
            .is_valid(e.data(), &e.signatures()[1]));
        assert_eq!("hello", msg.data().0);
        let mut e = Envelope::accept(&Acceptance::new(idb.pubkey(), e)).unwrap();
        e.sign(&idb).unwrap();
        e.sign(&sb).unwrap();
        minicbor::to_vec(&e).unwrap()
    };

    // initiator

    let outer: Envelope = minicbor::decode(&cbor).unwrap();
    let (hdr, body) = outer.read_data().unwrap();
    assert!(hdr.is_accept());
    assert_eq!(hdr.identity(), ED25519);
    let acc: Acceptance<ed25519::PubKey> = minicbor::decode(body).unwrap();
    let inner = acc.envelope();
    let (hdr, body) = inner.read_data().unwrap();
    assert!(hdr.is_invite());
    assert_eq!(hdr.identity(), ED25519);
    assert_eq!(hdr.initiator(), Some(GITHUB));
    assert_eq!(hdr.recipient(), Some(GITHUB));
    assert_eq!(hdr.data(), Some(TEST));
    let inv: Invitation<ed25519::PubKey, GitHub, GitHub, TestInvitation> =
        minicbor::decode(body).unwrap();
    assert_eq!(&ida.pubkey(), inv.initiator());
    assert_eq!("a", inv.initiator_info().user());
    assert_eq!(&pa, inv.initiator_info().key());
    assert_eq!("b", inv.recipient_info().user());
    assert_eq!(&pb, inv.recipient_info().key());
    assert_eq!(2, inner.signatures().len());
    assert!(inv
        .initiator()
        .is_valid(inner.data(), &inner.signatures()[0]));
    assert!(inv
        .initiator_info()
        .key()
        .is_valid(inner.data(), &inner.signatures()[1]));
    assert!(acc
        .recipient()
        .is_valid(outer.data(), &outer.signatures()[0]));
    assert!(inv
        .recipient_info()
        .key()
        .is_valid(outer.data(), &outer.signatures()[1]));
}
