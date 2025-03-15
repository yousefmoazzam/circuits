use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, PrimeGroup};

/// Evaluate the polynomial `0x^3 + 4x^2 + 7x + 8` at an encrypted version of the element `tau`,
/// and verify that successive powers of `tau` were indeed used.
fn main() {
    let tau: u32 = 88;
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    let srs = [
        g1,
        g1 * Fr::from(tau),
        g1 * Fr::from(tau.pow(2)),
        g1 * Fr::from(tau.pow(3)),
    ];
    let omega = g2 * Fr::from(tau);
    let coeffs = [8, 7, 4, 0];
    let _poly_at_tau = std::iter::zip(srs, coeffs)
        .map(|(power, coeff)| power * Fr::from(coeff))
        .reduce(|acc, val| acc + val)
        .unwrap();

    assert_eq!(Bn254::pairing(srs[0], omega), Bn254::pairing(srs[1], g2));
    assert_eq!(Bn254::pairing(srs[1], omega), Bn254::pairing(srs[2], g2));
    assert_eq!(Bn254::pairing(srs[2], omega), Bn254::pairing(srs[3], g2));
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        main()
    }
}
