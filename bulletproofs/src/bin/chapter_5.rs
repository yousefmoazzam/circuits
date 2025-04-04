use ark_bn254::{Fr, G1Projective};
use ark_ff::Field;
use ark_std::{test_rng, UniformRand};

/// Zero-knowledge interactive proof of two vectors `a` and `b` and their inner product, that
/// scales linearly with the length of the vectors
fn main() {
    let mut rng = test_rng();

    // Step zero: prover and verifier agree on:
    // - two vectors of elliptic curve group elements `g` and `h`
    // - a single elliptic curve group element `b_curve_point, for creating blinding terms
    // - a single elliptic curve group element `g_curve_point, for creating commitments to the
    // coefficients of a scalar polynomial
    let g = [
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
    ];
    let h = [
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
        G1Projective::rand(&mut rng),
    ];
    let b_curve_point = G1Projective::rand(&mut rng);
    let g_curve_point = G1Projective::rand(&mut rng);

    // Step one: prover creates commitments to the two secret vectors `a` and `b`, and the inner
    // product of these two vectors `v`

    // Define coefficients of the *vector* polynomials `l` and `r`, where the `l_constant` and
    // `r_constant` vectors are:
    // - the constant coefficients of the `l` and `r` polynomials respectively
    // - and playing the role of the `a` and `b` vectors whose inner product is being computed
    let l_constant = [Fr::from(89), Fr::from(15), Fr::from(90), Fr::from(22)];
    let r_constant = [Fr::from(16), Fr::from(18), Fr::from(54), Fr::from(12)];
    let l_linear = [Fr::from(3), Fr::from(21), Fr::from(8), Fr::from(4)];
    let r_linear = [Fr::from(89), Fr::from(7), Fr::from(31), Fr::from(9)];

    // Define coefficients of *scalar* polynomial `t` (which is the inner product of the *vector*
    // polynomials `l` and `r`), where:
    // - the constant coefficient is the inner product of the vectors `a` and `b`
    // - the linear coefficient is the sum of inner products of various (vector) coefficients of
    // `l` and `r`
    // - the quadratic coefficient is the inner product of the linear coefficients of the `l` and
    // `r` vector polynomials
    let t_constant = field_element_field_element_inner_product(&l_constant, &r_constant);
    let t_linear = field_element_field_element_inner_product(&l_constant, &r_linear)
        + field_element_field_element_inner_product(&r_constant, &l_linear);
    let t_quadratic = field_element_field_element_inner_product(&l_linear, &r_linear);

    // Define field elements for use in blinding terms to be used when creating commitments to the
    // coefficients in polynomials
    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let gamma = Fr::rand(&mut rng);
    let tau_1 = Fr::rand(&mut rng);
    let tau_2 = Fr::rand(&mut rng);

    let l_r_constant_comm = field_element_group_element_inner_product(&l_constant, &g)
        + field_element_group_element_inner_product(&r_constant, &h)
        + b_curve_point * alpha;
    let l_r_linear_comm = field_element_group_element_inner_product(&l_linear, &g)
        + field_element_group_element_inner_product(&r_linear, &h)
        + b_curve_point * beta;
    let t_constant_comm = g_curve_point * t_constant + b_curve_point * gamma;
    let t_linear_comm = g_curve_point
        * (field_element_field_element_inner_product(&l_constant, &r_linear)
            + field_element_field_element_inner_product(&r_constant, &l_linear))
        + b_curve_point * tau_1;
    let t_quadratic_comm = g_curve_point
        * field_element_field_element_inner_product(&l_linear, &r_linear)
        + b_curve_point * tau_2;

    // Step two: verifier picks `u` value
    let u = Fr::rand(&mut rng);

    // Step three: prover evaluates:
    // - vector polynomial `l`
    // - vector polynomial `r`
    // - scalar polynomial `t`
    //
    // and creates proof of evalautions for all three polynomials
    let l_eval = evaluate_vector_polynomial(
        &l_constant,
        &l_linear,
        &[Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        u,
    );
    let r_eval = evaluate_vector_polynomial(
        &r_constant,
        &r_linear,
        &[Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        u,
    );
    let t_eval = evaluate_scalar_polynomial(t_constant, t_linear, t_quadratic, u);
    let l_r_eval_proof = alpha + beta * u;
    let t_eval_proof = gamma + tau_1 * u + tau_2 * u.pow([2]);

    // Step four: verifier accepts or rejects the prover's alleged proof

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
    assert_eq!(
        l_r_constant_comm + l_r_linear_comm * u,
        field_element_group_element_inner_product(&l_eval, &g)
            + field_element_group_element_inner_product(&r_eval, &h)
            + b_curve_point * l_r_eval_proof
    );

    // Check commitments to constant, linear, and quadratic coefficients of scalar polynomial `t`
    // are consistent with:
    // - the evaluation of scalar polynomial `t` at `u
    // - the evaluation proof of `t`
    //
    // Ie, a "consistency" check of the `t` commitment and evaluation proof
    assert_eq!(
        g_curve_point * t_eval + b_curve_point * t_eval_proof,
        t_constant_comm + t_linear_comm * u + t_quadratic_comm * u.pow([2])
    );
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
