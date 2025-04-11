use ark_bn254::{Fr, G1Projective};
use ark_ff::Field;
use ark_std::{test_rng, UniformRand};

/// Zero-knowledge interactive range proof that vector `a_l` is within the range 0 to `2^4 = 16`
/// using Bulletproofs algorithm, with a proof size that scales linearly with the length of vector
/// `a_l`
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

    // Prover sends to the verifier:
    // - the evaluation of the polynomials `l`, `r`, and `t` at the field element `u` (which are
    // vectors of length `n`; hence, why the proof size scales linearly with the vector which is
    // being proven to be within range)
    // - proof of evalaution of the polynomials `l` and `r` combined into one expression
    // - proof of evaluation of the polynomial `t`

    // Verifier has all the necessary information to check the alleged proof, and to accept or
    // reject it

    // Check evaluation of scalar polynomial `t` at `u` is equal to the inner product of:
    // - the evaluation of the vector polynomial `l` at `u`
    // - the evaluation of the vector polynomial `r` at `u`
    //
    // Ie, a "correctness" check.
    assert_eq!(
        t_eval,
        field_element_field_element_inner_product(&l_eval, &r_eval)
    );

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

    assert_eq!(
        l_r_constant_comm + l_r_linear_comm * u + j_vector_part_comm + k_vector_part_comm,
        l_eval_comm + r_eval_comm + b_curve_point * l_r_eval_proof
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
