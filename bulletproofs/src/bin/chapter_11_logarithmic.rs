use ark_bn254::{Fr, G1Projective};
use ark_ff::Field;
use ark_std::{test_rng, UniformRand};

/// Zero-knowledge interactive range proof that vector `a_l` is within the range 0 to `2^4 = 16`
/// using Bulletproofs algorithm, with a proof size that scales logarithmically with the length of
/// vector `a_l`
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

    // Define elliptic curve group element for making commitment to inner product of vectors
    let g_curve_point = G1Projective::rand(&mut rng);

    // Define elliptic curve group element for creating blinding terms
    let b_curve_point = G1Projective::rand(&mut rng);

    // Define:
    // - secret vector `a_l` whose values are zeros or ones to correspond to a sequence of bits that
    // are an unsigned 16-bit integer
    // - vector `a_r`, which is the vector `a_l` with the `n` dimensional one-vector subtracted
    // from it
    //
    // Note that these will be the constant coefficients of the `l` and `r` vector polynomials
    // respectively
    //
    // Also note that the bits in the vector `a_l` are stored starting with the *least* significant
    // bit at index 0, but defining the value in `unsigned_int_val` has the bits from left to right
    // starting with the *most* significant bit
    let unsigned_int_val = 0b1101;
    let a_l = [Fr::from(1), Fr::from(0), Fr::from(1), Fr::from(1)];
    let a_r = [
        a_l[0] - Fr::from(1),
        a_l[1] - Fr::from(1),
        a_l[2] - Fr::from(1),
        a_l[3] - Fr::from(1),
    ];

    // Create random vectors to act as the linear coefficients of the `l` and `r` vector
    // polynomials
    let s_l = [
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
    ];
    let s_r = [
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
    ];

    // Define blinding terms to be used when creating commitments to:
    // - coefficients of vector polynomials `l` and `r`
    // - coefficients of scalar polynomial `t`
    // - inner product of vectors `a` and `b`
    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let gamma = Fr::rand(&mut rng);
    let tau_1 = Fr::rand(&mut rng);
    let tau_2 = Fr::rand(&mut rng);

    // Create commitment to:
    // - constant coefficients of `l` and `r` vector polynomials *without* the vectors `j` and `k`
    // added to them (where `j` is `-z . 1^n` and `k` is `z . y^n + z^2 . 2^n`)
    // - linear coefficients of `l` and `r` vector polynomials (random vectors `s_l` and `s_r`)
    // - inner product of `a_l` and `a_r` (which will be the constant coefficient of the scalar
    // polynomial `t`)
    let l_r_constant_comm = field_element_group_element_inner_product(&a_l, &g)
        + field_element_group_element_inner_product(&a_r, &h)
        + b_curve_point * alpha;
    let l_r_linear_comm = field_element_group_element_inner_product(&s_l, &g)
        + field_element_group_element_inner_product(&s_r, &h)
        + b_curve_point * beta;
    let t_constant_comm = g_curve_point * Fr::from(unsigned_int_val) + b_curve_point * gamma;

    // Prover sends the commitments to:
    // - the constant coefficients of `l` and `r` vector polynomials
    // - the linear coefficients of `l` and `r` vector polynomials
    // - the inner product of `a_l` and `a_r` (which will be the constant coefficient of the `t`
    // polynomila later)
    //
    // to the verifier

    // The verifier responds with two random finite field values:
    // - `y`, to form the vector of length `n` that will be used in Hadamard products which are
    // required to be the zero vector
    // - `z`, to take linear combinations of the three inner products needed to form the entire
    // range proof as one inner product
    let y = Fr::rand(&mut rng);
    let z = Fr::rand(&mut rng);

    // Prover constructs `l` and `r` vector polynomials
    //
    // The constant coefficients of them will include the `j` and `k` vectors now (in contrast to
    // the commitments, which didn't contain information about `j` and `k`)
    let two_vector = [
        Fr::from(2).pow([0]),
        Fr::from(2),
        Fr::from(2).pow([2]),
        Fr::from(2).pow([3]),
    ];
    let y_vector = [y.pow([0]), y, y.pow([2]), y.pow([3])];
    let l_constant_coeff = [a_l[0] - z, a_l[1] - z, a_l[2] - z, a_l[3] - z];
    let r_constant_coeff = [
        y_vector[0] * a_r[0] + y_vector[0] * z + z.pow([2]) * two_vector[0],
        y_vector[1] * a_r[1] + y_vector[1] * z + z.pow([2]) * two_vector[1],
        y_vector[2] * a_r[2] + y_vector[2] * z + z.pow([2]) * two_vector[2],
        y_vector[3] * a_r[3] + y_vector[3] * z + z.pow([2]) * two_vector[3],
    ];

    // Define coefficients of the scalar polynomial `t` (which is the inner product of the vector
    // polynomials `l` and `r`), where:
    // - the constant coefficient is the inner product of the vectors `a_l` and `a_r`
    // - the linear coefficient is the sum of inner products of various (vector) coefficients of
    // `l` and `r`
    // - the quadratic coefficient is the inner product of the linear coefficients of the `l` and
    // `r` vector polynomials
    let t_constant =
        field_element_field_element_inner_product(&l_constant_coeff, &r_constant_coeff);
    let t_linear = field_element_field_element_inner_product(
        &l_constant_coeff,
        &hadamard_product(&y_vector, &s_r),
    ) + field_element_field_element_inner_product(&r_constant_coeff, &s_l);
    let t_quadratic =
        field_element_field_element_inner_product(&s_l, &hadamard_product(&y_vector, &s_r));

    // Create commitments to linear and quadratic coefficients of `t` scalar polynomial
    let t_linear_comm = g_curve_point * t_linear + b_curve_point * tau_1;
    let t_quadratic_comm = g_curve_point * t_quadratic + b_curve_point * tau_2;

    // Verifier sends random `u` value for evaluation of `l`, `r`, and `t` polynomials
    let u = Fr::rand(&mut rng);

    // Prover evaluates vector polynomials `l` and `r`, and scalar polynomial `t`, at the field
    // element `u`
    let l_eval = evaluate_vector_polynomial(
        &l_constant_coeff,
        &s_l,
        &[Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        u,
    );
    let r_eval = evaluate_vector_polynomial(
        &r_constant_coeff,
        &hadamard_product(&y_vector, &s_r),
        &[Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        u,
    );
    let t_eval = evaluate_scalar_polynomial(t_constant, t_linear, t_quadratic, u);

    // Prover creates proof of evaluations for:
    // - the `l` and `r` polynomials (merging the blinding terms used for committing to the
    // constant and linear coefficients of both)
    // - the `t` polynomial
    let l_r_eval_proof = alpha + beta * u;
    let t_eval_proof = z.pow([2]) * gamma + tau_1 * u + tau_2 * u.pow([2]);

    // We want the size of the total data that is sent from the prover to the verifier to be better
    // than linearly scaling with the size of the vector `a_l`, so sending `l_u` and `r_u` to the
    // verifier won't be acceptable
    //
    // Instead, the recursive algorithm to compress the data to send to the verifier needs to be
    // used, which will ultimately result in sending the verifier data which, in total when summed
    // across all iterations in the recursion, will scale logarithmically with the vectors rather
    // than linearly, which is acceptable

    // Begin algorithm for compressing the vectors `l_eval` and `r_eval`

    // Create commitment to vectors `l_eval` and `r_eval`
    let l_eval_comm = std::iter::zip(l_eval, g)
        .map(|(elem, elliptic_curve_elem)| elliptic_curve_elem * elem)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let r_eval_comm = std::iter::zip(r_eval, h)
        .map(|(elem, elliptic_curve_elem)| elliptic_curve_elem * elem)
        .reduce(|acc, val| acc + val)
        .unwrap();

    // Create commitment to inner product of `l_eval` and `r_eval`
    //
    // This is needed purely for the recursive compression algorithm, it's unrelated to the
    // overarching goal of the range proof, it's a detail in getting from linearly scaling to
    // lagarithmically scaling data size
    let l_eval_r_eval_inner_product_comm = g_curve_point * l_eval[0] * r_eval[0]
        + g_curve_point * l_eval[1] * r_eval[1]
        + g_curve_point * l_eval[2] * r_eval[2]
        + g_curve_point * l_eval[3] * r_eval[3];

    // Combine the above three commitments into a single commitment
    let initial_concatenated_inner_product =
        l_eval_comm + l_eval_r_eval_inner_product_comm + r_eval_comm;

    // First round of "fold and commit" algorithm
    //
    // `n = 4` goes to `n = 2` in this iteration
    let r_1 = g[0] * l_eval[1]
        + g[2] * l_eval[3]
        + g_curve_point * l_eval[1] * r_eval[0]
        + g_curve_point * l_eval[3] * r_eval[2]
        + h[1] * r_eval[0]
        + h[3] * r_eval[2];
    let l_1 = g[1] * l_eval[0]
        + g[3] * l_eval[2]
        + g_curve_point * l_eval[0] * r_eval[1]
        + g_curve_point * l_eval[2] * r_eval[3]
        + h[0] * r_eval[1]
        + h[2] * r_eval[3];

    // Prover computes:
    // - the folding of the vector `l_eval` and the value `u_1`
    // - the folding of the vector `r_eval` and the value `u_1_inv`
    // - the folding of the vector of elliptic curve group elements `g` and the value `u_1_inv`
    // - the folding of the vector of elliptic curve group elements `h` and the value `u_1`
    let u_1 = Fr::rand(&mut rng);
    let u_1_inv = u_1.inverse().unwrap();
    let l_eval_prime = [
        l_eval[0] * u_1 + l_eval[1] * u_1_inv,
        l_eval[2] * u_1 + l_eval[3] * u_1_inv,
    ];
    let r_eval_prime = [
        r_eval[0] * u_1_inv + r_eval[1] * u_1,
        r_eval[2] * u_1_inv + r_eval[3] * u_1,
    ];
    let g_prime = [g[0] * u_1_inv + g[1] * u_1, g[2] * u_1_inv + g[3] * u_1];
    let h_prime = [h[0] * u_1 + h[1] * u_1_inv, h[2] * u_1 + h[3] * u_1_inv];

    // Define the sum of all the off-diagonal terms computed up until this point, and the inner
    // product of the concatenated vector containing the vectors being folded
    //
    // This value is the main thing being passed across iterations that is being "built up"
    let p = l_1 * u_1.pow([2]) + initial_concatenated_inner_product + r_1 * u_1_inv.pow([2]);

    // Sanity check, to make sure that the folding of the vectors has been done correctly
    let l_eval_prime_comm = g_prime[0] * l_eval_prime[0] + g_prime[1] * l_eval_prime[1];
    let r_eval_prime_comm = h_prime[0] * r_eval_prime[0] + h_prime[1] * r_eval_prime[1];
    let l_eval_prime_r_eval_prime_inner_product_comm = std::iter::zip(l_eval_prime, r_eval_prime)
        .map(|(a_prime_elem, b_prime_elem)| g_curve_point * a_prime_elem * b_prime_elem)
        .reduce(|acc, val| acc + val)
        .unwrap();
    assert_eq!(
        l_eval_prime_comm + r_eval_prime_comm + l_eval_prime_r_eval_prime_inner_product_comm,
        p
    );

    // Second round of "fold and commit" algorithm
    //
    // `n = 2` goes to `n = 1` in this iteration
    let r_2 = g_prime[0] * l_eval_prime[1]
        + g_curve_point * l_eval_prime[1] * r_eval_prime[0]
        + h_prime[1] * r_eval_prime[0];
    let l_2 = g_prime[1] * l_eval_prime[0]
        + g_curve_point * l_eval_prime[0] * r_eval_prime[1]
        + h_prime[0] * r_eval_prime[1];

    // Apply fold operation once more, now to `l_eval_prime`, `r_eval_prime`, `g_prime`, and
    // `h_prime`
    let u_2 = Fr::rand(&mut rng);
    let u_2_inv = u_2.inverse().unwrap();
    let l_eval_double_prime = [l_eval_prime[0] * u_2 + l_eval_prime[1] * u_2_inv];
    let r_eval_double_prime = [r_eval_prime[0] * u_2_inv + r_eval_prime[1] * u_2];
    let g_double_prime = [g_prime[0] * u_2_inv + g_prime[1] * u_2];
    let h_double_prime = [h_prime[0] * u_2 + h_prime[1] * u_2_inv];
    let p_prime = l_2 * u_2.pow([2]) + p + r_2 * u_2_inv.pow([2]);

    // Third round of "fold and commit" algorithm
    //
    // `n = 1`, so this is the base case now at which recursion would terminate
    let l_eval_double_prime_comm = g_double_prime[0] * l_eval_double_prime[0];
    let r_eval_double_prime_comm = h_double_prime[0] * r_eval_double_prime[0];
    let l_eval_double_prime_r_eval_double_prime_inner_product_comm =
        g_curve_point * l_eval_double_prime[0] * r_eval_double_prime[0];

    // Compression of the vectors `l_eval` and `r_eval` is complete, and it can now be checked that
    // the inner product of `l_eval` and `r_eval` is indeed equal to the evaluation of the `t`
    // polynomial
    //
    // Ie, a "correctness" check.
    //
    // Note that the `l_u` and `r_u` vectors are *not* needed to be sent to the verifier in order
    // to verify that the inner product of them is equal to `t_u`. This is how the total size of
    // the data sent to the verifier is kept below linearly scaling with the vector whose value
    // being within a range is being proven
    assert_eq!(
        l_eval_double_prime_comm
            + r_eval_double_prime_comm
            + l_eval_double_prime_r_eval_double_prime_inner_product_comm,
        p_prime
    );

    // Prover sends to the verifier:
    // - proof of evalaution of the polynomials `l` and `r` combined into one expression
    // - proof of evaluation of the polynomial `t`

    // Verifier has all the necessary information to check the alleged proof, and to accept or
    // reject it

    // Check commitments to constant and linear coefficients of vector polynomials `l` and `r` are
    // consistent with:
    // - the evaluation of the vector polynomial `l` at `u`
    // - the evaluation of the vector polynomial `r` at `u`
    // - the evaluation proofs of `l` and `r`
    //
    // Ie, a "consistency" check of the `l` and `r` commitments and evaluation proofs

    // Verifier constructs parts of the eqn that involve the vectors `j` and `k`
    let y_inv = y.inverse().unwrap();
    let y_inv_vector = [Fr::from(1), y_inv, y_inv.pow([2]), y_inv.pow([3])];
    let j_vector_part_comm = field_element_group_element_inner_product(&[-z, -z, -z, -z], &g);
    let h_y_inv_hadamard_product = [
        h[0] * y_inv_vector[0],
        h[1] * y_inv_vector[1],
        h[2] * y_inv_vector[2],
        h[3] * y_inv_vector[3],
    ];
    let k_vector_part = [
        z * y_vector[0] + z.pow([2]) * two_vector[0],
        z * y_vector[1] + z.pow([2]) * two_vector[1],
        z * y_vector[2] + z.pow([2]) * two_vector[2],
        z * y_vector[3] + z.pow([2]) * two_vector[3],
    ];
    let k_vector_part_comm =
        field_element_group_element_inner_product(&k_vector_part, &h_y_inv_hadamard_product);

    // Compute commitments to `l_u` (using vector of elliptic curve group elements `g`), and `r_u`
    // (using Hadamard product of `y^{-1}` vector and `h` vector of elliptic curve group elements)
    let l_eval_comm = field_element_group_element_inner_product(&l_eval, &g);
    let r_eval_comm = field_element_group_element_inner_product(&r_eval, &h_y_inv_hadamard_product);

    // Note how the proof of evaluation of the `l` and `r` polynomials has been shifted to the LHS
    // (in comparison to the linearly scaling proof size algorithm in `chapter_11.rs`). This is
    // analogous to the rearrangement done in the associated verification equation when going from
    // chapter 7 to 8
    assert_eq!(
        l_r_constant_comm + l_r_linear_comm * u + j_vector_part_comm + k_vector_part_comm
            - b_curve_point * l_r_eval_proof,
        l_eval_comm + r_eval_comm
    );

    // Check commitments to constant, linear, and quadratic coefficients of scalar polynomial `t`
    // are consistent with:
    // - the evaluation of scalar polynomial `t` at `u
    // - the evaluation proof of `t`
    //
    // Ie, a "consistency" check of the `t` commitment and evaluation proof
    let one_vector = [Fr::from(1), Fr::from(1), Fr::from(1), Fr::from(1)];
    let delta_y_z = (z - z.pow([2]))
        * field_element_field_element_inner_product(&one_vector, &y_vector)
        - z.pow([3]) * field_element_field_element_inner_product(&one_vector, &two_vector);
    assert_eq!(
        g_curve_point * t_eval + b_curve_point * t_eval_proof,
        t_constant_comm * z.pow([2])
            + g_curve_point * delta_y_z
            + t_linear_comm * u
            + t_quadratic_comm * u.pow([2])
    );
}

fn hadamard_product(a: &[Fr; 4], b: &[Fr; 4]) -> [Fr; 4] {
    [a[0] * b[0], a[1] * b[1], a[2] * b[2], a[3] * b[3]]
}

fn evaluate_scalar_polynomial(constant: Fr, linear: Fr, quadratic: Fr, u: Fr) -> Fr {
    constant + linear * u + quadratic * u.pow([2])
}

fn evaluate_vector_polynomial(
    constant: &[Fr; 4],
    linear: &[Fr; 4],
    quadratic: &[Fr; 4],
    u: Fr,
) -> [Fr; 4] {
    [
        constant[0] + linear[0] * u + quadratic[0] * u.pow([2]),
        constant[1] + linear[1] * u + quadratic[1] * u.pow([2]),
        constant[2] + linear[2] * u + quadratic[2] * u.pow([2]),
        constant[3] + linear[3] * u + quadratic[3] * u.pow([2]),
    ]
}

fn field_element_group_element_inner_product(x: &[Fr; 4], g: &[G1Projective; 4]) -> G1Projective {
    std::iter::zip(x, g)
        .map(|(field_elem, group_elem)| *group_elem * field_elem)
        .reduce(|acc, e| acc + e)
        .unwrap()
}

fn field_element_field_element_inner_product(x: &[Fr; 4], y: &[Fr; 4]) -> Fr {
    std::iter::zip(x, y)
        .map(|(a, b)| a * b)
        .reduce(|acc, e| acc + e)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        main()
    }
}
