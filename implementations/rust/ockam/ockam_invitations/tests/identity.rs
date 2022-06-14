use minicbor::{Decode, Encode};
use ockam_invitations::ed25519::{PubKey, SecKey, ED25519};
use ockam_invitations::identity;
use ockam_invitations::{Acceptance, Envelope, Invitation, Meta, Tag, Verifier};

const TEST: Tag = Tag(236784);

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
struct TestInvitation<'a>(#[b(0)] &'a str);

impl Meta for TestInvitation<'_> {
    const TAG: Tag = TEST;
}

#[test]
fn direct() {
    // prelude

    let sa: SecKey = SecKey::new();
    let sb: SecKey = SecKey::new();
    let pa: PubKey = sa.pubkey();
    let pb: PubKey = sb.pubkey();

    // initiator

    let i = identity::invite(&pa, &pb, &TestInvitation("hello"));
    let mut e = Envelope::invite(&i).unwrap();
    e.sign(&sa).unwrap();
    let cbor = minicbor::to_vec(&e).unwrap();

    // recipient

    let cbor = {
        let e: Envelope = minicbor::decode(&cbor).unwrap();
        let (hdr, body) = e.read_data().unwrap();
        assert!(hdr.is_invite());
        assert_eq!(hdr.identity(), ED25519);
        assert_eq!(hdr.initiator(), Some(ED25519));
        assert_eq!(hdr.recipient(), Some(ED25519));
        assert_eq!(hdr.data(), Some(TEST));
        let msg: Invitation<PubKey, PubKey, PubKey, TestInvitation> =
            minicbor::decode(body).unwrap();
        assert_eq!(&pa, msg.initiator());
        assert_eq!(&pb, msg.recipient_info());
        assert_eq!(1, e.signatures().len());
        assert!(msg.initiator().is_valid(e.data(), &e.signatures()[0]));
        assert_eq!("hello", msg.data().0);
        let mut e = Envelope::accept(&Acceptance::new(&pb, e)).unwrap();
        e.sign(&sb).unwrap();
        minicbor::to_vec(&e).unwrap()
    };

    // initiator

    let outer: Envelope = minicbor::decode(&cbor).unwrap();
    let (hdr, body) = outer.read_data().unwrap();
    assert!(hdr.is_accept());
    assert_eq!(hdr.identity(), ED25519);
    let acc: Acceptance<PubKey> = minicbor::decode(body).unwrap();
    let inner = acc.envelope();
    let (hdr, body) = inner.read_data().unwrap();
    assert!(hdr.is_invite());
    assert_eq!(hdr.identity(), ED25519);
    assert_eq!(hdr.initiator(), Some(ED25519));
    assert_eq!(hdr.recipient(), Some(ED25519));
    assert_eq!(hdr.data(), Some(TEST));
    assert_eq!(Some(TEST), hdr.data());
    let inv: Invitation<PubKey, PubKey, PubKey, TestInvitation> = minicbor::decode(body).unwrap();
    assert_eq!(&pa, inv.initiator());
    assert_eq!(&pb, inv.recipient_info());
    assert!(pb.is_valid(outer.data(), &outer.signatures()[0]));
}
