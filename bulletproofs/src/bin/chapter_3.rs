use ark_bn254::{Fr, G1Projective};
use ark_ff::Field;
use ark_std::{test_rng, UniformRand};

fn main() {
    let mut rng = test_rng();

    // Step zero: prover and verifier agree on elliptic curve group elements `g` and `b`
    let g = G1Projective::rand(&mut rng);
    let b = G1Projective::rand(&mut rng);

    // Step one: prover creates commitments to the cofficients of its secret polynomial
    let f_0 = Fr::from(123);
    let f_1 = Fr::from(456);
    let f_2 = Fr::from(789);

    // Define blinding terms to be used in the polynomial coefficient commitments
    let gamma_0 = Fr::rand(&mut rng);
    let gamma_1 = Fr::rand(&mut rng);
    let gamma_2 = Fr::rand(&mut rng);

    // Create commitments
    let (c0, c1, c2) = commit(f_0, f_1, f_2, gamma_0, gamma_1, gamma_2, g, b);

    // Step two: verifier picks value for `u`
    let u = Fr::rand(&mut rng);

    // Step three: prover evaluates their secret polynomial at `u`, and the inner-product between
    // the blinding terms and powers of `u`
    let f_u = evaluate(f_0, f_1, f_2, u);
    let pi = prove(gamma_0, gamma_1, gamma_2, u);

    // Step four: verifier accepts or rejects prover's alleged proof
    assert!(verify(c0, c1, c2, g, b, f_u, pi, u));
}

#[allow(clippy::too_many_arguments)]
fn commit(
    f_0: Fr,
    f_1: Fr,
    f_2: Fr,
    gamma_0: Fr,
    gamma_1: Fr,
    gamma_2: Fr,
    g: G1Projective,
    b: G1Projective,
) -> (G1Projective, G1Projective, G1Projective) {
    (
        g * f_0 + b * gamma_0,
        g * f_1 + b * gamma_1,
        g * f_2 + b * gamma_2,
    )
}

/// Params are the coefficients of the prover's polynomial, and the field element to evaluate it at
/// (whose value was decided by verifier)
fn evaluate(f_0: Fr, f_1: Fr, f_2: Fr, u: Fr) -> Fr {
    f_0 + f_1 * u + f_2 * u.pow([2])
}

/// Create proof of secret polynomial evaluation at the verifier's choice of `u`
fn prove(gamma_0: Fr, gamma_1: Fr, gamma_2: Fr, u: Fr) -> Fr {
    gamma_0 + gamma_1 * u + gamma_2 * u.pow([2])
}

/// Parameters are:
/// - commitments to coefficients of the prover's secret polynomial
/// - the two elliptic curve group elements used in the commitments
/// - the output of the prover's secrete polynomial evaluated at the verifier's value `u`
/// - the output of the "inner product" between blinding terms in polynomial commitment and powers
/// of `u`
#[allow(clippy::too_many_arguments)]
fn verify(
    c0: G1Projective,
    c1: G1Projective,
    c2: G1Projective,
    g: G1Projective,
    b: G1Projective,
    f_u: Fr,
    pi: Fr,
    u: Fr,
) -> bool {
    g * f_u + b * pi == c0 + c1 * u + c2 * u.pow([2])
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        main()
    }
}
