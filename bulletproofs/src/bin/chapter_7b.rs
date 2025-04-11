use ark_bn254::{Fr, G1Projective};
use ark_ff::Field;
use ark_std::{test_rng, UniformRand};

/// Proving commitment to two vectors `a` and `b` and their inner product with proof size that
/// scales logarithmically with the length of the vectors, via recursive folding algorithm in
/// Bulletproofs paper
fn main() {
    let mut rng = test_rng();

    // Define set of elliptic curve group elements for making commitments to coefficients of the
    // vector `a`
    let g = [
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
    ];

    // Define set of elliptic curve group elements for making commitments to coefficients of the
    // vector `b`
    let h = [
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
    ];

    // Define elliptic curve group element for making commitment to inner product of `a` and `b`
    let q = G1Projective::rand(&mut rng);

    // Define secret `a` and `b` vectors to be computing the inner product of
    let a = [Fr::from(4), Fr::from(2), Fr::from(42), Fr::from(420)];
    let b = [Fr::from(2), Fr::from(3), Fr::from(5), Fr::from(8)];

    // Create commitment to vectors `a` and `b` by computing inner product of:
    // - `a` and `g`
    // - `b` and `h`
    let a_comm = std::iter::zip(a, g)
        .map(|(elem, elliptic_curve_elem)| elliptic_curve_elem * elem)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let b_comm = std::iter::zip(b, h)
        .map(|(elem, elliptic_curve_elem)| elliptic_curve_elem * elem)
        .reduce(|acc, val| acc + val)
        .unwrap();

    // Create commitment to inner product of `a` and `b`, by taking inner product of:
    // - the `a` vector
    // - the Hadamard product of the `b` vector and the vector of `n` copies of the `q` elliptic
    // curve group element
    let a_b_inner_product_comm =
        q * a[0] * b[0] + q * a[1] * b[1] + q * a[2] * b[2] + q * a[3] * b[3];

    // Combine the above three commitments into a single commitment
    let initial_concatenated_inner_product = a_comm + a_b_inner_product_comm + b_comm;

    // Recursive algorithm begins
    //
    // Note that, due to the figurative concatenation of:
    // - `a`
    // - `a` again
    // - `b`
    //
    // being done to form two longer vectors which we use to compute the outer product, there will
    // be two extra folding operations (one extra for folding the vector of elliptic curve group
    // elements `h`, and another extra for folding the vector `b`)

    // First round of "fold and commit" algorithm
    //
    // `n = 4` goes to `n = 2` in this iteration (we don't actually concatenate the vectors, we
    // only compute the off-diagonal terms as if the vectors were concatenated - so we still
    // consider starting with `n = 2`)
    //
    // For the 6 pairs of 2-element partions of `a + a + b` and `g + h + [q, q, q, q]`, commit to
    // the sum of:
    // - the six off-diagonal terms to the right of the first term in the inner product of the
    // partitioned-pairs
    // - the two off-diagonal terms to the left of the second term in the inner product of the
    // partitioned-pairs
    //let r_1 =
    //    g[0] * a[1] + g[2] * a[3] + q * a[1] * b[0] + q * a[3] * b[2] + h[0] * b[1] + h[2] * b[3];
    //let l_1 =
    //    g[1] * a[0] + g[3] * a[2] + q * a[0] * b[1] + q * a[2] * b[3] + h[1] * b[0] + h[3] * b[2];
    let r_1 =
        g[0] * a[1] + g[2] * a[3] + q * a[1] * b[0] + q * a[3] * b[2] + h[1] * b[0] + h[3] * b[2];
    let l_1 =
        g[1] * a[0] + g[3] * a[2] + q * a[0] * b[1] + q * a[2] * b[3] + h[0] * b[1] + h[2] * b[3];

    // Prover computes:
    // - the folding of the vector `a` and the value `u_1`
    // - the folding of the vector `b` and the value `u_1_inv`
    // - the folding of the vector of elliptic curve group elements `g` and the value `u_1_inv`
    // - the folding of the vector of elliptic curve group elements `h` and the value `u_1`
    let u_1 = Fr::rand(&mut rng);
    let u_1_inv = u_1.inverse().unwrap();
    let a_prime = [a[0] * u_1 + a[1] * u_1_inv, a[2] * u_1 + a[3] * u_1_inv];
    let b_prime = [b[0] * u_1_inv + b[1] * u_1, b[2] * u_1_inv + b[3] * u_1];
    let g_prime = [g[0] * u_1_inv + g[1] * u_1, g[2] * u_1_inv + g[3] * u_1];
    let h_prime = [h[0] * u_1 + h[1] * u_1_inv, h[2] * u_1 + h[3] * u_1_inv];

    // Commit to off-diagonal terms of the 6 pairs of 2-element partitions
    //
    // The first iteration of the algorithm uses the commitment to the inner product of `a` and `b`
    // as the term with no randomness factor (`u_1` in the first iteration)
    let a_prime_comm = g_prime[0] * a_prime[0] + g_prime[1] * a_prime[1];
    let b_prime_comm = h_prime[0] * b_prime[0] + h_prime[1] * b_prime[1];
    let a_prime_b_prime_inner_product_comm = std::iter::zip(a_prime, b_prime)
        .map(|(a_prime_elem, b_prime_elem)| q * a_prime_elem * b_prime_elem)
        .reduce(|acc, val| acc + val)
        .unwrap();

    // Define value to pass into the next recursion iteration
    let p = l_1 * u_1.pow([2]) + initial_concatenated_inner_product + r_1 * u_1_inv.pow([2]);

    // Sanity check that the folding operations of:
    // - `a` into `a_prime`
    // - `b` into `b_prime`
    // - `g` into `g_prime`
    // - `h` into `h_prime`
    //
    // were done correctly
    assert_eq!(
        a_prime_comm + b_prime_comm + a_prime_b_prime_inner_product_comm,
        p
    );

    // Second round of "fold and commit" algorithm
    //
    // `n = 2` goes to `n = 1` in this step
    let r_2 = g_prime[0] * a_prime[1] + q * a_prime[1] * b_prime[0] + h_prime[1] * b_prime[0];
    let l_2 = g_prime[1] * a_prime[0] + q * a_prime[0] * b_prime[1] + h_prime[0] * b_prime[1];

    // Apply fold operation once more, now to the "prime" versions
    let u_2 = Fr::rand(&mut rng);
    let u_2_inv = u_2.inverse().unwrap();
    let a_double_prime = [a_prime[0] * u_2 + a_prime[1] * u_2_inv];
    let b_double_prime = [b_prime[0] * u_2_inv + b_prime[1] * u_2];
    let g_double_prime = [g_prime[0] * u_2_inv + g_prime[1] * u_2];
    let h_double_prime = [h_prime[0] * u_2 + h_prime[1] * u_2_inv];

    // Define value to pass into the next recursion iteration
    let p_prime = l_2 * u_2.pow([2]) + p + r_2 * u_2_inv.pow([2]);

    // Third round of "fold and commit" algorithm
    //
    // `n = 1`, so this is the base case now at which recursion would terminate
    //
    // Create commitments to inner products of:
    // - `a_double_prime` and `g_double_prime` (both of length 1, so essentially a commitment to a
    // single field element)
    // - `b_double_prime` and `h_double_prime` (both of length 1, so essentially a commitment to a
    // single field element)
    let a_double_prime_comm = g_double_prime[0] * a_double_prime[0];
    let b_double_prime_comm = h_double_prime[0] * b_double_prime[0];
    let a_double_prime_b_double_prime_inner_product_comm =
        q * a_double_prime[0] * b_double_prime[0];
    assert_eq!(
        a_double_prime_comm
            + b_double_prime_comm
            + a_double_prime_b_double_prime_inner_product_comm,
        p_prime
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
