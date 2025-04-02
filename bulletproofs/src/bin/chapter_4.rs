use ark_bn254::{Fr, G1Projective};
use ark_ff::Field;
use ark_std::{test_rng, UniformRand};

/// Zero-knowledge proof of multiplication of two polynomials using Pedersen commitments
fn main() {
    let mut rng = test_rng();
    let g = G1Projective::rand(&mut rng);
    let h = G1Projective::rand(&mut rng);
    let b = G1Projective::rand(&mut rng);

    // Define coefficients of `l` and `r` polynomials
    let l_constant = Fr::from(3);
    let l_linear = Fr::from(6);
    let r_constant = Fr::from(8);
    let r_linear = Fr::from(9);

    // Define coefficients of product polynomial `t`
    let t_constant = l_constant * r_constant;
    let t_linear = l_constant * r_linear + r_constant * l_linear;
    let t_quadratic = l_linear * r_linear;

    // Define blinding terms to be used when creating commitments to the coefficients in
    // polynomials
    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let gamma = Fr::rand(&mut rng);
    let tau_1 = Fr::rand(&mut rng);
    let tau_2 = Fr::rand(&mut rng);

    // Step one: prover creates commitments to polynomials `l`, `r`. and `t`
    let l_r_constant_comm = g * l_constant + h * r_constant + b * alpha;
    let l_r_linear_comm = g * l_linear + h * r_linear + b * beta;
    let t_constant_comm = g * t_constant + b * gamma;
    let t_linear_comm = g * t_linear + b * tau_1;
    let t_quadratic_comm = g * t_quadratic + b * tau_2;

    // Step two: verifier picks a value `u`
    let u = Fr::rand(&mut rng);

    // Step three: prover evaluates polynomials `l`, `r`, `t` with the field element `u`, and
    // creates proofs of evaluation
    let l_eval = evaluate(l_constant, l_linear, Fr::from(0), u);
    let r_eval = evaluate(r_constant, r_linear, Fr::from(0), u);
    let t_eval = evaluate(t_constant, t_linear, t_quadratic, u);
    let l_r_eval_proof = alpha + beta * u;
    let t_eval_proof = gamma + tau_1 * u + tau_2 * u.pow([2]);

    // Step four: verifier accepts or rejects the prover's alleged proof

    // Check evaluation of `t` at `u` is equal to the product of the evaluation of `l` at `u` and
    // the evaluation of `r` at `u` (ie, a "correctness" check)
    assert_eq!(t_eval, l_eval * r_eval);

    // Check commitments to constant and linear coefficients of `l` and `r` are consistent with:
    // - the evaluation of `l` at `u` and the evaluation of `r` at `u`
    // - the evaluation proofs of `l` and `r`
    //
    // Ie, a "consistency" check of the `l` and `r` commitments and evaluation proofs
    assert_eq!(
        l_r_constant_comm * u.pow([0]) + l_r_linear_comm * u.pow([1]),
        g * l_eval + h * r_eval + b * l_r_eval_proof
    );

    // Check commitments to constant, linear, and quadratic coefficients of `t` are consistent
    // with:
    // - the evaluation of `t` at `u
    // - the evaluation proof of `t`
    //
    // Ie, a "consistency" check of the `t` commitment and evaluation proof
    assert_eq!(
        t_constant_comm * u.pow([0]) + t_linear_comm * u.pow([1]) + t_quadratic_comm * u.pow([2]),
        g * t_eval + b * t_eval_proof
    );
}

fn evaluate(f_0: Fr, f_1: Fr, f_2: Fr, u: Fr) -> Fr {
    f_0 + f_1 * u + f_2 * u.pow([2])
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        main()
    }
}
