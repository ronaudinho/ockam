use super::{Invitation, Meta, Verifier};

pub fn invite<P, T, D>(a: P, b: T, d: D) -> Invitation<P, P, T, D>
where
    P: Verifier + minicbor::Encode<()> + Meta + Clone,
    T: Verifier + minicbor::Encode<()> + Meta,
{
    Invitation::new(a.clone(), a, b, d)
}
