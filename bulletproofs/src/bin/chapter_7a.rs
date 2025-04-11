use ark_bn254::{Fr, G1Projective};
use ark_ff::Field;
use ark_std::{test_rng, UniformRand};

/// Proving commitment to single vector `a` with proof size that scales logarithmically with the
/// length of the vector `a`, via recursive folding algorithm in Bulletproofs paper
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
    let a = [Fr::from(4), Fr::from(2), Fr::from(42), Fr::from(420)];

    // Commit to vector `a` by computing inner product of `a` and `g`
    //
    // Can also be viewed as the main diagonal of the outer-product between `a` and `g`
    let a_comm = std::iter::zip(a, g)
        .map(|(elem, elliptic_curve_elem)| elliptic_curve_elem * elem)
        .reduce(|acc, val| acc + val)
        .unwrap();

    // First round of "fold and commit" algorithm
    //
    // `n = 4` goes to `n = 2` in this step, so not the base case
    //
    // For the 4 pairs of 2-element partions of `a` and `g`, commit to the sum of:
    // - the two off-diagonal terms to the right of the first term in the inner product of the
    // partitioned-pairs of `a` and `g` (ie, `a_2 G_1` and `a_4 G_3`)
    // - the two off-diagonal terms to the left of the second term in the inner product of the
    let l_1 = g[1] * a[0] + g[3] * a[2];
    let r_1 = g[0] * a[1] + g[2] * a[3];

    // Prover computes:
    // - the folding of the vector `a` and the value `u_1` to get a vector of half the length of
    // `a` (ie, a vector of length 2)
    // - the folding of the vector of elliptic curve group elements `g` to get a vector of half the
    // length of `g` (ie, a vector of length 2)
    let u_1 = Fr::rand(&mut rng);
    let u_1_inv = u_1.inverse().unwrap();
    let a_prime = [a[0] * u_1 + a[1] * u_1_inv, a[2] * u_1 + a[3] * u_1_inv];
    let g_prime = [g[0] * u_1_inv + g[1] * u_1, g[2] * u_1_inv + g[3] * u_1];

    // Define value to pass into the next recursion iteration
    let p = l_1 * u_1.pow([2]) + a_comm + r_1 * u_1_inv.pow([2]);

    // Sanity check that the folding operations of `a` into `a_prime` and `g` into `g_prime` were
    // done correctly
    assert_eq!(g_prime[0] * a_prime[0] + g_prime[1] * a_prime[1], p);

    // Second round of "fold and commit" algorithm
    //
    // `n = 2` goes to `n = 1` in this step, so still not the base case yet, but next step will be
    //
    // Note that there is only one term for both off-diagonal "types" (upper and lower) for the
    // `n = 2` case
    let l_2 = g_prime[1] * a_prime[0];
    let r_2 = g_prime[0] * a_prime[1];

    // Apply fold operations once more, now to `a_prime` and `g_prime`
    let u_2 = Fr::rand(&mut rng);
    let u_2_inv = u_2.inverse().unwrap();
    let a_double_prime = [a_prime[0] * u_2 + a_prime[1] * u_2_inv];
    let g_double_prime = [g_prime[0] * u_2_inv + g_prime[1] * u_2];

    // Define value to pass into the next recursion iteration
    let p_prime = l_2 * u_2.pow([2]) + p + r_2 * u_2_inv.pow([2]);

    // Third round of "fold and commit" algorithm
    //
    // `n = 1`, so this is the base case now at which recursion will terminate and verification can
    // be done (on smaller size data than if the recursion algorithm weren't used)
    let a_double_prime_comm = g_double_prime[0] * a_double_prime[0];
    assert_eq!(a_double_prime_comm, p_prime);
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        main()
    }
}
