use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::{Field, UniformRand};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use ark_std::test_rng;

/// Zero-knowledge proof using the groth16 protocol
///
/// Taking a QAP derived from an arithmetic circuit `z = x^4 - 5y^2x^2` in the form of an R1CS with
/// the following constraints:
/// - v_1 = x * x
/// - v_2 = v_1 * v_1
/// - v_3 = -5y * y
/// - -v_2 + z = v_3 * v_1
///
/// and evaluating it using a trusted setup.
///
/// Additionally:
/// - enforcing that QAP eqn can be satisfied only when constraints are satisfied (protecting
/// against prover providing two elliptic curve group elements of `G1` and one elliptic curve group
/// element of `G2` that satisfy the QAP but wasn't necessarily derived from having a valid witness)
/// - supporting public inputs by treating the public and private parts of the witness differently,
/// but also enforcing that values in `phis` (which now has public and private portions) can't be
/// used to satisfy the QAP eqn without satisfying the constraints
/// - guarding against a prover simply guessing a valid witness, by adding in "salt" values which
/// would also need to be guessed correctly in order for a prover to guess a correct witness (which
/// is incredibly unlikely to happen)
fn main() {
    const NO_OF_POLY_COEFFS: usize = 4;
    let small_domain = GeneralEvaluationDomain::<Fr>::new(NO_OF_POLY_COEFFS).unwrap();
    let l_columns = [
        [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        [Fr::from(1), Fr::from(0), Fr::from(0), Fr::from(0)],
        [Fr::from(0), Fr::from(0), Fr::from(-5), Fr::from(0)],
        [Fr::from(0), Fr::from(1), Fr::from(0), Fr::from(0)],
        [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(1)],
    ];
    let r_columns = [
        [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        [Fr::from(1), Fr::from(0), Fr::from(0), Fr::from(0)],
        [Fr::from(0), Fr::from(0), Fr::from(1), Fr::from(0)],
        [Fr::from(0), Fr::from(1), Fr::from(0), Fr::from(1)],
        [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
    ];
    let o_columns = [
        [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(1)],
        [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(0)],
        [Fr::from(1), Fr::from(0), Fr::from(0), Fr::from(0)],
        [Fr::from(0), Fr::from(1), Fr::from(0), Fr::from(-1)],
        [Fr::from(0), Fr::from(0), Fr::from(1), Fr::from(0)],
    ];
    let x = Fr::from(4);
    let y = Fr::from(-2);
    let v1 = x * x;
    let v2 = v1 * v1;
    let v3 = Fr::from(-5) * y * y;
    let z = v3 * v1 + v2;
    let witness = [Fr::from(1), z, x, y, v1, v2, v3];
    const NO_OF_PUB_INPUTS: usize = 1;

    // Sanity check that the matrices `L`, `R`, `O`, and the witness vector are correctly defined
    let l_mult_witness = (0..=3)
        .map(|row_idx| {
            l_columns[0][row_idx] * witness[0]
                + l_columns[1][row_idx] * witness[1]
                + l_columns[2][row_idx] * witness[2]
                + l_columns[3][row_idx] * witness[3]
                + l_columns[4][row_idx] * witness[4]
                + l_columns[5][row_idx] * witness[5]
                + l_columns[6][row_idx] * witness[6]
        })
        .collect::<Vec<_>>();
    let r_mult_witness = (0..=3)
        .map(|row_idx| {
            r_columns[0][row_idx] * witness[0]
                + r_columns[1][row_idx] * witness[1]
                + r_columns[2][row_idx] * witness[2]
                + r_columns[3][row_idx] * witness[3]
                + r_columns[4][row_idx] * witness[4]
                + r_columns[5][row_idx] * witness[5]
                + r_columns[6][row_idx] * witness[6]
        })
        .collect::<Vec<_>>();
    let o_mult_witness = (0..=3)
        .map(|row_idx| {
            o_columns[0][row_idx] * witness[0]
                + o_columns[1][row_idx] * witness[1]
                + o_columns[2][row_idx] * witness[2]
                + o_columns[3][row_idx] * witness[3]
                + o_columns[4][row_idx] * witness[4]
                + o_columns[5][row_idx] * witness[5]
                + o_columns[6][row_idx] * witness[6]
        })
        .collect::<Vec<_>>();
    let l_mult_r = std::iter::zip(l_mult_witness, r_mult_witness)
        .map(|(left, right)| left * right)
        .collect::<Vec<_>>();
    assert_eq!(l_mult_r, o_mult_witness);

    // Interpolate columns of matrices `L`, `R`, and `O`, and take appropriate linear combinations
    // of the interpolated polynomials (getting the coefficients of the linear combination from the
    // witness vector).
    let l_columns_polys = l_columns
        .iter()
        .map(|col| DensePolynomial::from_coefficients_vec(small_domain.ifft(col)))
        .collect::<Vec<_>>();
    let l_linear_combination_poly = std::iter::zip(l_columns_polys.clone(), witness)
        .map(|(poly, scalar)| poly * scalar)
        .reduce(|acc, poly| acc + poly)
        .unwrap();
    let r_columns_polys = r_columns
        .iter()
        .map(|col| DensePolynomial::from_coefficients_vec(small_domain.ifft(col)))
        .collect::<Vec<_>>();
    let r_linear_combination_poly = std::iter::zip(r_columns_polys.clone(), witness)
        .map(|(poly, scalar)| poly * scalar)
        .reduce(|acc, poly| acc + poly)
        .unwrap();
    let o_columns_polys = o_columns
        .iter()
        .map(|col| DensePolynomial::from_coefficients_vec(small_domain.ifft(col)))
        .collect::<Vec<_>>();
    let o_linear_combination_poly = std::iter::zip(o_columns_polys.clone(), witness)
        .map(|(poly, scalar)| poly * scalar)
        .reduce(|acc, poly| acc + poly)
        .unwrap();

    // Derive polynomial to balance out the RHS of the QAP eqn in terms of the degree of the
    // polynomials on each side of the eqn
    let roots_of_unity = small_domain.elements().collect::<Vec<_>>();
    let t_poly = DensePolynomial::from_coefficients_vec(vec![roots_of_unity[0], Fr::from(1)])
        * DensePolynomial::from_coefficients_vec(vec![roots_of_unity[1], Fr::from(1)])
        * DensePolynomial::from_coefficients_vec(vec![roots_of_unity[2], Fr::from(1)])
        * DensePolynomial::from_coefficients_vec(vec![roots_of_unity[3], Fr::from(1)]);
    let h_poly = (l_linear_combination_poly.clone() * r_linear_combination_poly.clone()
        - o_linear_combination_poly.clone())
        / t_poly.clone();

    // Check that there's no remainder from the polynomial division operation above
    assert_eq!(
        l_linear_combination_poly.clone() * r_linear_combination_poly.clone(),
        o_linear_combination_poly.clone() + h_poly.clone() * t_poly.clone()
    );

    // Define SRS for evaluating interpolated polynomials originating from `L` and `R` matrices
    let mut rng = test_rng();
    let tau = Fr::rand(&mut rng);
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    let srs_l = [g1, g1 * tau, g1 * tau.pow([2]), g1 * tau.pow([3])];
    let srs_r = [g2, g2 * tau, g2 * tau.pow([2]), g2 * tau.pow([3])];

    // Define values used for combining interpolated column polynomials of all three matrices `L`,
    // `R`, `O` (required for enforcing that QAP eqn can only be satisfied if a valid witness is
    // provided)
    let alpha = Fr::rand(&mut rng);
    let alpha_1 = g1 * alpha;
    let beta = Fr::rand(&mut rng);
    let beta_1 = g1 * beta;
    let beta_2 = g2 * beta;
    let gamma = Fr::rand(&mut rng);
    let gamma_2 = g2 * gamma;
    let delta = Fr::rand(&mut rng);
    let delta_1 = g1 * delta;
    let delta_2 = g2 * delta;
    let phis = std::iter::zip(
        l_columns_polys,
        std::iter::zip(r_columns_polys, o_columns_polys),
    )
    .enumerate()
    .map(|(idx, (l_poly, (r_poly, o_poly)))| {
        let divisor = if idx < NO_OF_PUB_INPUTS { gamma } else { delta };
        g1 * (alpha * r_poly.evaluate(&tau) + beta * l_poly.evaluate(&tau) + o_poly.evaluate(&tau))
            * divisor.inverse().unwrap()
    })
    .collect::<Vec<_>>();

    // Define SRS for `h(x)t(x)` term
    let srs_ht_product = [
        g1 * t_poly.evaluate(&tau),
        g1 * tau * t_poly.evaluate(&tau),
        g1 * tau.pow([2]) * t_poly.evaluate(&tau),
    ]
    .map(|val| val * delta.inverse().unwrap());

    // Define "salt" values which will be used to protect against a prover simply guessing a valid
    // witness
    let r_salt = Fr::rand(&mut rng);
    let s_salt = Fr::rand(&mut rng);

    // Evaluate polynomials on the SRS's, introducing encryption of the values via combining
    // generators of elliptic curve groups with themselves some number of times
    let eval_l = std::iter::zip(l_linear_combination_poly.coeffs(), srs_l)
        .map(|(coeff, term)| term * coeff)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let eval_r = std::iter::zip(r_linear_combination_poly.coeffs(), srs_r)
        .map(|(coeff, term)| term * coeff)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let eval_r_g1 = std::iter::zip(r_linear_combination_poly.coeffs(), srs_l)
        .map(|(coeff, term)| term * coeff)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let eval_pub_input = phis[0] * witness[0];
    let eval_o = std::iter::zip(&witness[NO_OF_PUB_INPUTS..], &phis[NO_OF_PUB_INPUTS..])
        .map(|(coeff, term)| *term * coeff)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let eval_ht = std::iter::zip(h_poly.coeffs(), srs_ht_product)
        .map(|(coeff, term)| term * coeff)
        .reduce(|acc, val| acc + val)
        .unwrap();

    // Verify that both sides of QAP eqn are equal
    let a_1 = alpha_1 + eval_l + delta_1 * r_salt;
    let b_1 = beta_1 + eval_r_g1 + delta_1 * s_salt;
    let b_2 = beta_2 + eval_r + delta_2 * s_salt;
    let c_1 = eval_o + eval_ht + a_1 * s_salt + b_1 * r_salt - delta_1 * r_salt * s_salt;
    assert_eq!(
        Bn254::pairing(a_1, b_2),
        Bn254::pairing(alpha_1, beta_2)
            + Bn254::pairing(eval_pub_input, gamma_2)
            + Bn254::pairing(c_1, delta_2)
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
