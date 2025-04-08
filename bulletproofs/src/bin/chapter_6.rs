use ark_bn254::{Fr, G1Projective};
use ark_ff::Field;
use ark_std::{test_rng, UniformRand};

/// Prove knowledge of inner product of a vector of field elements and a vector of elliptic curve
/// group elements (both length `n = 4`) by sending only `n/2 = 2` elements
///
/// Note that the focus in general is on proving knowledge of the inner product of two vectors, but
/// when one vector is made to contain elliptic curve group elements, the inner product between the
/// two vectors becomes a commitment to the non-elliptic curve group element vector. So an
/// equivalent way of looking at this is that it's a proof of knowing the opening to a Pedersen
/// vector commitment with a proof size that is half the size of the committed vector.
fn main() {
    let mut rng = test_rng();

    // Define set of elliptic curve group elements for making commitments to coefficients of the
    // vector `a`, via outer product between it and `a`
    let g = [
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
    ];

    // Define secret `a` vector to be computing the inner product with the set of elliptic cuvre
    // groups points `g`
    let a = [Fr::from(9), Fr::from(45), Fr::from(23), Fr::from(42)];

    // Commit to vector `a` by computing inner product of `a` and `g`
    let a_comm = std::iter::zip(a, g)
        .map(|(elem, elliptic_curve_elem)| elliptic_curve_elem * elem)
        .reduce(|acc, val| acc + val)
        .unwrap();

    // Commit to the sum of:
    // - the two off-diagonal terms to the right of the first term in the inner product of the
    // partitioned-pairs of `a` and `g` (ie, `a_2 G_1` and `a_4 G_3`)
    // - the two off-diagonal terms to the left of the second term in the inner product of the
    // partitioned-pairs of `a` and `g` (ie, `a_1 G_2` and `a_3 G_4`)
    let r = g[0] * a[1] + g[2] * a[3];
    let l = g[1] * a[0] + g[3] * a[2];

    // Verifier chooses random `u` field element
    let u = Fr::rand(&mut rng);

    // Prover computes:
    // - the folding of the vector `a` and the value `u` to get a vector of half the length of `a`
    // (ie, a vector of length 2)
    // - the folding of the vector of elliptic curve group elements `g` to get a vector of half the
    // length of `g`
    let u_inv = u.inverse().unwrap();
    let a_prime = [a[0] * u + a[1] * u_inv, a[2] * u + a[3] * u_inv];
    let g_prime = [g[0] * u_inv + g[1] * u, g[2] * u_inv + g[3] * u];

    // Verification check
    //
    // Check that the commitment to the folded vector `a_prime` (which will be an inner product
    // between `a_prime` and `g_prime`) is equivalent to a particular sum of the commitments to:
    // - the "lower" off-diagonal terms
    // - the "upper" off-diagonal terms
    // - the inner product between the original `a` and the original `g`
    //
    // where there are coefficients of each term of the sum involving a power of `u`.
    //
    // Note that this is considering the situation where the prover is sending the `a_prime` vector
    // to the verifier (ie, sending the result of just one fold operation), so a vector of length 2
    // is sent (the folded vector `a_prime`) rather than a vector of length 4 (the original vector
    // `a`), which means that the number of elements to send has been halved.
    let a_prime_comm = std::iter::zip(a_prime, g_prime)
        .map(|(elem, elliptic_curve_elem)| elliptic_curve_elem * elem)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let inner_product_and_initial_off_diagonal_terms_comm =
        l * u.pow([2]) + a_comm + r * u_inv.pow([2]);
    assert_eq!(
        a_prime_comm,
        inner_product_and_initial_off_diagonal_terms_comm
    );
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        main()
    }
}
