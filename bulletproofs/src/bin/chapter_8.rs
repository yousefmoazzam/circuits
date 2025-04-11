use ark_bn254::{Fr, G1Projective};
use ark_ff::Field;
use ark_std::{rand::Rng, test_rng, UniformRand};

/// Zero-knowledge interactive proof of two vectors `a` and `b` and their inner product that scales
/// logarithmically with the length of the vectors
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
    let q_curve_point = G1Projective::rand(&mut rng);

    // Define elliptic curve group element for creating blinding terms
    let b_curve_point = G1Projective::rand(&mut rng);

    // Define secret `a` and `b` vectors to be computing the inner product of (and these will be
    // the constant coefficients of the `l` and `r` vector polynomials respectively)
    let a = [Fr::from(4), Fr::from(2), Fr::from(42), Fr::from(420)];
    let b = [Fr::from(2), Fr::from(3), Fr::from(5), Fr::from(8)];

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

    // Define coefficients of the scalar polynomial `t` (which is the inner product of the vector
    // polynomials `l` and `r`), where:
    // - the constant coefficient is the inner product of the vectors `a` and `b`
    // - the linear coefficient is the sum of inner products of various (vector) coefficients of
    // `l` and `r`
    // - the quadratic coefficient is the inner product of the linear coefficients of the `l` and
    // `r` vector polynomials
    let t_constant = field_element_field_element_inner_product(&a, &b);
    let t_linear = field_element_field_element_inner_product(&a, &s_r)
        + field_element_field_element_inner_product(&b, &s_l);
    let t_quadratic = field_element_field_element_inner_product(&s_l, &s_r);

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
    // - constant coefficients of `l` and `r` vector polynomials (vectors `a` and `b`)
    // - linear coefficients of `l` and `r` vector polynomials (random vectors `s_l` and `s_r`)
    // - inner product of `a` and `b` (which will be the constant coefficient of the scalar
    // polynomial `t`)
    // - linear and quadratic coefficients of `t` scalar polynomial
    let l_r_constant_comm = field_element_group_element_inner_product(&a, &g)
        + field_element_group_element_inner_product(&b, &h)
        + b_curve_point * alpha;
    let l_r_linear_comm = field_element_group_element_inner_product(&s_l, &g)
        + field_element_group_element_inner_product(&s_r, &h)
        + b_curve_point * beta;
    let t_constant_comm = q_curve_point * t_constant + b_curve_point * gamma;
    let t_linear_comm = q_curve_point * t_linear + b_curve_point * tau_1;
    let t_quadratic_comm = q_curve_point * t_quadratic + b_curve_point * tau_2;

    // Verifier sends random `u` value for evaluation of `l`, `r`, and `t` polynomials
    let u = send_random_field_element(&mut rng);

    // Prover evaluates vector polynomials `l` and `r`, and scalar polynomial `t`
    let l_eval = evaluate_vector_polynomial(
        &a,
        &s_l,
        &[Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        u,
    );
    let r_eval = evaluate_vector_polynomial(
        &b,
        &s_r,
        &[Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        u,
    );
    let t_eval = evaluate_scalar_polynomial(t_constant, t_linear, t_quadratic, u);

    // Prover creates proof of evaluations for:
    // - the `l` and `r` polynomials (merging the blinding terms used for committing to the
    // constant and linear coefficients of both)
    // - the `t` polynomial
    let l_r_eval_proof = alpha + beta * u;
    let t_eval_proof = gamma + tau_1 * u + tau_2 * u.pow([2]);

    // Begin algorithm for compressing the vectors outputted by evaluating `l` and `r` at `u` to be
    // of size `log(n)` (where `n` is the length of the vectors ouputted by the evaluations).
    //
    // Note that this is without zero-knowledge, because the vectors `l_eval` and `r_eval` that
    // would be sent to the verifier are not secret, we only wish to reduce their size to make the
    // size of the data that would be sent to the verifier smaller (ie, to reduce the size of the
    // proof)

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
    let l_eval_r_eval_inner_product_comm = q_curve_point * l_eval[0] * r_eval[0]
        + q_curve_point * l_eval[1] * r_eval[1]
        + q_curve_point * l_eval[2] * r_eval[2]
        + q_curve_point * l_eval[3] * r_eval[3];

    // Combine the above three commitments into a single commitment
    let initial_concatenated_inner_product =
        l_eval_comm + l_eval_r_eval_inner_product_comm + r_eval_comm;

    // First round of "fold and commit" algorithm
    //
    // `n = 4` goes to `n = 2` in this iteration
    let r_1 = g[0] * l_eval[1]
        + g[2] * l_eval[3]
        + q_curve_point * l_eval[1] * r_eval[0]
        + q_curve_point * l_eval[3] * r_eval[2]
        + h[1] * r_eval[0]
        + h[3] * r_eval[2];
    let l_1 = g[1] * l_eval[0]
        + g[3] * l_eval[2]
        + q_curve_point * l_eval[0] * r_eval[1]
        + q_curve_point * l_eval[2] * r_eval[3]
        + h[0] * r_eval[1]
        + h[2] * r_eval[3];

    // Prover computes:
    // - the folding of the vector `l_eval` and the value `u_1`
    // - the folding of the vector `r_eval` and the value `u_1_inv`
    // - the folding of the vector of elliptic curve group elements `g` and the value `u_1_inv`
    // - the folding of the vector of elliptic curve group elements `h` and the value `u_1`
    let u_1 = send_random_field_element(&mut rng);
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
        .map(|(a_prime_elem, b_prime_elem)| q_curve_point * a_prime_elem * b_prime_elem)
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
        + q_curve_point * l_eval_prime[1] * r_eval_prime[0]
        + h_prime[1] * r_eval_prime[0];
    let l_2 = g_prime[1] * l_eval_prime[0]
        + q_curve_point * l_eval_prime[0] * r_eval_prime[1]
        + h_prime[0] * r_eval_prime[1];

    // Apply fold operation once more, now to `l_eval_prime`, `r_eval_prime`, `g_prime`, and
    // `h_prime`
    let u_2 = send_random_field_element(&mut rng);
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
        q_curve_point * l_eval_double_prime[0] * r_eval_double_prime[0];

    // Compression of the vectors `l_eval` and `r_eval` is complete, and it can now be checked that
    // the inner product of `l_eval` and `r_eval` is indeed equal to the evaluation of the `t`
    // polynomial
    assert_eq!(
        l_eval_double_prime_comm
            + r_eval_double_prime_comm
            + l_eval_double_prime_r_eval_double_prime_inner_product_comm,
        p_prime
    );

    // Verifier has all the necessary information to check the alleged proof, and to accept or
    // reject it

    // Check commitments to constant and linear coefficients of vector polynomials `l` and `r` are
    // consistent with:
    // - the evaluation of the vector polynomial `l` at `u`
    // - the evaluation of the vector polynomial `r` at `u`
    // - the evaluation proofs of `l` and `r`
    //
    // Ie, a "consistency" check of the `l` and `r` commitments and evaluation proofs
    //
    // Prover sends the sum of the commitments to the evaluation of `l` at `u` and the evaluation
    // of `r` at `u`
    let c = l_eval_comm + r_eval_comm;
    assert_eq!(
        c,
        l_r_constant_comm + l_r_linear_comm * u - b_curve_point * l_r_eval_proof
    );

    // Check commitments to constant, linear, and quadratic coefficients of scalar polynomial `t`
    // are consistent with:
    // - the evaluation of scalar polynomial `t` at `u
    // - the evaluation proof of `t`
    //
    // Ie, a "consistency" check of the `t` commitment and evaluation proof
    assert_eq!(
        q_curve_point * t_eval,
        t_constant_comm + t_linear_comm * u + t_quadratic_comm * u.pow([2])
            - b_curve_point * t_eval_proof
    );
}

/// Verifier sends prover a random field element
fn send_random_field_element(rng: &mut impl Rng) -> Fr {
    Fr::rand(rng)
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
