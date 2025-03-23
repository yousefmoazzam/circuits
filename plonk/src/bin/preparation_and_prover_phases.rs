use ark_bn254::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::{Field, UniformRand};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use ark_std::test_rng;
use std::hash::{DefaultHasher, Hash, Hasher};

/// For the eqn `2x^2 - x^2y^2 + 3 = 25` and a proof of having a solution `x = 2, y = 3`:
/// - the preparation phase
/// - round one of the prover phase
///
/// using the PLONK protocol.
fn main() {
    let x = 2;
    let y = 3;
    const NO_OF_POLY_COEFFS: usize = 8;
    let small_domain = GeneralEvaluationDomain::<Fr>::new(NO_OF_POLY_COEFFS).unwrap();
    let domain = small_domain.elements().collect::<Vec<_>>();

    // There are 7 gates in the circuit, but the column vector of wires values are padded to the
    // next highest power of two. In this case this is 2^3 = 8, so there's an extra zero value at
    // the end of each column to represent a "dummy gate" resulting from this padding.
    //
    // Wire column vectors
    let a = [
        Fr::from(x),
        Fr::from(x),
        Fr::from(y),
        Fr::from(4),
        Fr::from(4),
        Fr::from(8),
        Fr::from(-28),
        Fr::from(0),
    ];
    let b = [
        Fr::from(x),
        Fr::from(x),
        Fr::from(y),
        Fr::from(0),
        Fr::from(9),
        Fr::from(36),
        Fr::from(3),
        Fr::from(0),
    ];
    let c = [
        Fr::from(4),
        Fr::from(4),
        Fr::from(9),
        Fr::from(8),
        Fr::from(36),
        Fr::from(-28),
        Fr::from(-25),
        Fr::from(0),
    ];

    // Selector column vectors
    let ql = [
        Fr::from(0),
        Fr::from(0),
        Fr::from(0),
        Fr::from(2),
        Fr::from(0),
        Fr::from(1),
        Fr::from(1),
        Fr::from(0),
    ];
    let qr = [
        Fr::from(0),
        Fr::from(0),
        Fr::from(0),
        Fr::from(0),
        Fr::from(0),
        Fr::from(-1),
        Fr::from(0),
        Fr::from(0),
    ];
    let qm = [
        Fr::from(1),
        Fr::from(1),
        Fr::from(1),
        Fr::from(1),
        Fr::from(1),
        Fr::from(0),
        Fr::from(0),
        Fr::from(0),
    ];
    let qc = [
        Fr::from(0),
        Fr::from(0),
        Fr::from(0),
        Fr::from(0),
        Fr::from(0),
        Fr::from(0),
        Fr::from(3),
        Fr::from(0),
    ];
    let qo = [
        Fr::from(-1),
        Fr::from(-1),
        Fr::from(-1),
        Fr::from(-1),
        Fr::from(-1),
        Fr::from(-1),
        Fr::from(-1),
        Fr::from(0),
    ];

    // Two random field elements used in the index-mapping involved in the permutations
    let k1 = Fr::from(2);
    let k2 = Fr::from(4);

    // Define permutation evaluation values
    let sigma_a = [
        domain[0],
        domain[1],
        domain[2],
        k2,
        k2 * domain[1],
        k2 * domain[3],
        k2 * domain[5],
        domain[7],
    ];
    let sigma_b = [
        k1,
        k1 * domain[1],
        k1 * domain[2],
        k1 * domain[3],
        k2 * domain[2],
        k2 * domain[4],
        k1 * domain[6],
        k1 * domain[7],
    ];
    let sigma_c = [
        domain[3],
        domain[4],
        k1 * domain[4],
        domain[5],
        k1 * domain[5],
        domain[6],
        k2 * domain[6],
        k2 * domain[7],
    ];

    // Interpolate selector and permutation evaluation values at the 8th roots of unity to get
    // polynomial representations of column vectors
    let ql_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&ql));
    let qr_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&qr));
    let qm_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&qm));
    let qc_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&qc));
    let qo_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&qo));
    let sigma_a_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&sigma_a));
    let sigma_b_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&sigma_b));
    let sigma_c_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&sigma_c));

    // Define the polynomial which has roots at the eight 8th roots of unity, to be used as a
    // divisor to check if the polynomial being divided also has roots at all the 8th roots of
    // unity (ie, the "vanishing polynomial")
    let zh = small_domain.vanishing_polynomial();
    for elem in domain.clone() {
        assert_eq!(zh.evaluate(&elem), Fr::from(0));
    }

    // Define secret value `tau` for use in trusted setup
    let mut rng = test_rng();
    let tau = Fr::rand(&mut rng);
    let g1 = G1Projective::generator();
    let srs_g1 = [
        g1,
        g1 * tau,
        g1 * tau.pow([2]),
        g1 * tau.pow([3]),
        g1 * tau.pow([4]),
        g1 * tau.pow([5]),
        g1 * tau.pow([6]),
        g1 * tau.pow([7]),
    ];

    // Prover: round one
    //
    // Define random field elements to use with "blinding polynomials"
    let blinding_elements = [
        Fr::from(23),
        Fr::from(12),
        Fr::from(58),
        Fr::from(119),
        Fr::from(180),
        Fr::from(155),
        Fr::from(91),
        Fr::from(204),
        Fr::from(230),
    ];

    // Define "blinding" polynomials
    let blinding_poly_a = DensePolynomial::from_coefficients_slice(&blinding_elements[..2]);
    assert_eq!(blinding_poly_a.degree(), 1);
    let blinding_poly_b = DensePolynomial::from_coefficients_slice(&blinding_elements[2..4]);
    assert_eq!(blinding_poly_b.degree(), 1);
    let blinding_poly_c = DensePolynomial::from_coefficients_slice(&blinding_elements[4..6]);
    assert_eq!(blinding_poly_c.degree(), 1);

    // Define polynomials that interpolated the sets of wire values
    let a_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&a))
        + blinding_poly_a.mul_by_vanishing_poly(small_domain);
    let b_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&b))
        + blinding_poly_b.mul_by_vanishing_poly(small_domain);
    let c_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&c))
        + blinding_poly_c.mul_by_vanishing_poly(small_domain);

    // Define polynomial that puts together wire polynomials and selector polynomials, to represent
    // all gates in the cirucit with one polynomial
    let gate_poly = ql_poly * a_poly.clone()
        + qr_poly * b_poly.clone()
        + qm_poly * a_poly.clone() * b_poly.clone()
        + qc_poly
        + qo_poly * c_poly.clone();

    // Sanity check that the gate polynomial has roots at all the 8th roots of unity.
    //
    // The reason that this should be the case is that the gate equations that we started with were
    // all set to zero.
    //
    // The wire and selector polynomials were constructed from the gate equations by interpolation,
    // using the 8th roots of unity as the points at which the values in the column vectors were
    // assumed to be associated with. So, putting together the polynomials representations of the
    // wires and selectors should result in a polynomial that reproduces the original gate
    // equations.
    //
    // In particular, this means that evaluating the single gate poylnomial at any 8th root of
    // unity should represent a single gate equation. As all gate equations were set to zero, this
    // means that evaluating the single gate poylnomial at any 8th root of unity should produce
    // zero.
    for elem in domain.clone() {
        assert_eq!(gate_poly.evaluate(&elem), Fr::from(0));
    }
    assert_eq!(
        gate_poly.divide_by_vanishing_poly(small_domain).1,
        DensePolynomial::from_coefficients_slice(&[Fr::from(0)])
    );

    // Create commitments to the wire polynomials (ie, perform the inner-product evaluation between
    // the coefficients of a wire polynomial and the SRS generated in the trusted setup)
    let a_poly_commitment = std::iter::zip(a_poly.coeffs(), srs_g1)
        .map(|(coeff, term)| term * coeff)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let b_poly_commitment = std::iter::zip(b_poly.coeffs(), srs_g1)
        .map(|(coeff, term)| term * coeff)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let c_poly_commitment = std::iter::zip(c_poly.coeffs(), srs_g1)
        .map(|(coeff, term)| term * coeff)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let round_one = [a_poly_commitment, b_poly_commitment, c_poly_commitment];

    // Prover: round two
    //
    // Hash the polynomial commitments from round one in the context of applying the Fiat-Shamir
    // heuristic to make the KZG polynomial commitment scheme be non-interactive
    let mut hasher = DefaultHasher::new();
    (round_one[0] + round_one[1] + round_one[2] + G1Projective::rand(&mut rng)).hash(&mut hasher);
    let beta = hasher.finish();
    let beta_poly = DensePolynomial::from_coefficients_slice(&[Fr::from(beta)]);
    (round_one[0] + round_one[1] + round_one[2] + G1Projective::rand(&mut rng)).hash(&mut hasher);
    let gamma = hasher.finish();
    let gamma_poly = DensePolynomial::from_coefficients_slice(&[Fr::from(gamma)]);

    // Define polynomials to go in numerator and denominator of expression for "accumulator"
    //
    // This enforces the values in the circuit which are common to a pair of wires ("copy
    // constraints") (for example, `a_2 = o_1`), to ensure that the various gates are connected to
    // each other as the original circuit describes.
    let a_indices_mapping = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&domain));
    let b_indices_mapping = DensePolynomial::from_coefficients_slice(
        &small_domain.ifft(&domain.iter().map(|elem| k1 * elem).collect::<Vec<_>>()),
    );
    let c_indices_mapping = DensePolynomial::from_coefficients_slice(
        &small_domain.ifft(&domain.iter().map(|elem| k2 * elem).collect::<Vec<_>>()),
    );
    let f_poly =
        (gamma_poly.clone() + a_indices_mapping.clone() + a_poly.clone() * beta_poly.clone())
            * (gamma_poly.clone() + b_indices_mapping.clone() + b_poly.clone() * beta_poly.clone())
            * (gamma_poly.clone() + c_indices_mapping + c_poly.clone() * beta_poly.clone());
    let g_poly = (gamma_poly.clone() + sigma_a_poly.clone() + a_poly.clone() * beta_poly.clone())
        * (gamma_poly.clone() + sigma_b_poly.clone() + b_poly.clone() * beta_poly.clone())
        * (gamma_poly + sigma_c_poly + c_poly.clone() * beta_poly);
    let mut acc_evals = vec![Fr::from(1)];
    for (idx, elem) in domain.iter().enumerate() {
        acc_evals.push(acc_evals[idx] * (f_poly.evaluate(elem) / g_poly.evaluate(elem)));
    }

    // Sanity check that the final accumulator value is as expected
    assert_eq!(acc_evals.pop().unwrap(), Fr::from(1));
    let acc_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&acc_evals));

    // Define polynomial for enforcing permutations
    let blinding_poly_z = DensePolynomial::from_coefficients_slice(&blinding_elements[6..]);
    assert_eq!(blinding_poly_z.degree(), 2);
    let z_poly = blinding_poly_z.mul_by_vanishing_poly(small_domain) + acc_poly;

    // Sanity check that the permutation polynomial has correct start and end points
    assert_eq!(z_poly.evaluate(&domain[0]), Fr::from(1));
    assert_eq!(z_poly.evaluate(&domain[domain.len() - 1]), Fr::from(1));
    let z_poly_commitment = std::iter::zip(z_poly.coeffs(), srs_g1)
        .map(|(coeff, term)| term * coeff)
        .reduce(|acc, val| acc + val)
        .unwrap();

    // Prover: round three
    //
    // Hash polynomial commitments from round one and two
    (round_one[0] + round_one[1] + z_poly_commitment + G1Projective::rand(&mut rng))
        .hash(&mut hasher);
    let alpha = hasher.finish();
    let alpha_poly = DensePolynomial::from_coefficients_slice(&[Fr::from(alpha)]);

    // Define various pieces that are used in the defn of the quotient polynomial
    let z_poly_omega_shifted_coeffs = z_poly
        .coeffs()
        .iter()
        .enumerate()
        .map(|(idx, coeff)| *coeff * domain[1].pow([idx as u64]))
        .collect::<Vec<_>>();
    let z_poly_omega_shifted =
        DensePolynomial::from_coefficients_slice(&z_poly_omega_shifted_coeffs);
    let mut l1_poly_evals = [Fr::from(0); NO_OF_POLY_COEFFS];
    l1_poly_evals[0] = Fr::from(1);
    let l1_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&l1_poly_evals));

    // Sanity check that `l1_poly` indeed evaluates to 1 at the first 8th root of unity, and zero
    // at all the other 8th roots of unity
    assert_eq!(l1_poly.evaluate(&domain[0]), Fr::from(1));
    for elem in &domain[1..] {
        assert_eq!(l1_poly.evaluate(elem), Fr::from(0));
    }

    // Define the quotient polynomial
    let t1_poly =
        (f_poly * z_poly.clone() - g_poly * z_poly_omega_shifted.clone()) * alpha_poly.clone();
    assert_eq!(
        t1_poly.divide_by_vanishing_poly(small_domain).1,
        DensePolynomial::from_coefficients_slice(&[Fr::from(0)])
    );
    let t2_poly = (z_poly - DensePolynomial::from_coefficients_slice(&[Fr::from(1)]))
        * l1_poly
        * alpha_poly.clone()
        * alpha_poly;
    assert_eq!(
        t2_poly.divide_by_vanishing_poly(small_domain).1,
        DensePolynomial::from_coefficients_slice(&[Fr::from(0)])
    );
    let t_poly = gate_poly + t1_poly + t2_poly;

    // Sanity check that the quotient polynomial indeed has roots at all the 8th roots of unity
    assert_eq!(
        t_poly.divide_by_vanishing_poly(small_domain).1,
        DensePolynomial::from_coefficients_slice(&[Fr::from(0)])
    );
    for elem in domain {
        assert_eq!(t_poly.evaluate(&elem), Fr::from(0));
    }
    let t_poly = t_poly.divide_by_vanishing_poly(small_domain).0;

    // Define the splitting of the quotient polynomial into "low", "mid", and "high" parts
    let t_coeffs = t_poly.coeffs();
    let t_low_poly = DensePolynomial::from_coefficients_slice(&t_coeffs[..NO_OF_POLY_COEFFS]);
    let t_mid_poly = DensePolynomial::from_coefficients_slice(
        &t_coeffs[NO_OF_POLY_COEFFS..NO_OF_POLY_COEFFS * 2],
    );
    let t_high_poly = DensePolynomial::from_coefficients_slice(&t_coeffs[NO_OF_POLY_COEFFS * 2..]);
    let mut x_n_poly_coeffs = [Fr::from(0); NO_OF_POLY_COEFFS + 1];
    x_n_poly_coeffs[NO_OF_POLY_COEFFS] = Fr::from(1);
    let x_n_poly = DensePolynomial::from_coefficients_slice(&x_n_poly_coeffs);
    let mut x_2n_poly_coeffs = [Fr::from(0); 2 * NO_OF_POLY_COEFFS + 1];
    x_2n_poly_coeffs[2 * NO_OF_POLY_COEFFS] = Fr::from(1);
    let x_2n_poly = DensePolynomial::from_coefficients_slice(&x_2n_poly_coeffs);
    // Sanity checks that the quotient polynomial has been split correctly
    assert_eq!(t_poly.degree(), 3 * NO_OF_POLY_COEFFS + 5);
    assert_eq!(
        t_poly,
        t_low_poly.clone()
            + x_n_poly.clone() * t_mid_poly.clone()
            + x_2n_poly.clone() * t_high_poly.clone()
    );

    // Define final form of the "low", "mid", and "high" pieces that the quotient polynomial were
    // split into
    let b10 = Fr::rand(&mut rng);
    let b10_poly = DensePolynomial::from_coefficients_slice(&[b10]);
    let b11 = Fr::rand(&mut rng);
    let b11_poly = DensePolynomial::from_coefficients_slice(&[b11]);
    let t_low_poly = t_low_poly + b10_poly.clone() * x_n_poly.clone();
    let t_mid_poly = t_mid_poly - b10_poly + b11_poly.clone() * x_n_poly.clone();
    let t_high_poly = t_high_poly - b11_poly;
    assert_eq!(
        t_poly,
        t_low_poly.clone() + x_n_poly * t_mid_poly.clone() + x_2n_poly * t_high_poly.clone()
    );

    // Create commitments to the "low", "mid", and "high" polynomials that came from splitting-up
    // the quotient polynomial
    let t_low_poly_commitment = std::iter::zip(t_low_poly.coeffs(), srs_g1)
        .map(|(coeff, term)| term * coeff)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let t_mid_poly_commitment = std::iter::zip(t_mid_poly.coeffs(), srs_g1)
        .map(|(coeff, term)| term * coeff)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let t_high_poly_commitment = std::iter::zip(t_high_poly.coeffs(), srs_g1)
        .map(|(coeff, term)| term * coeff)
        .reduce(|acc, val| acc + val)
        .unwrap();
    let round_three = [
        t_low_poly_commitment,
        t_mid_poly_commitment,
        t_high_poly_commitment,
    ];

    // Prover phase: round four
    //
    // Hash polynomial commitments from rounds one, two, and three
    (round_one[0]
        + round_one[1]
        + round_one[2]
        + z_poly_commitment
        + round_three[0]
        + round_three[1]
        + round_three[2])
        .hash(&mut hasher);
    let zeta = Fr::from(hasher.finish());

    // Evaluate wire polynomials, index-mapping polynomials for wire sets A and B, and
    // omega-shifted permutation polynomial, at a random field element
    let a_zeta = a_poly.evaluate(&zeta);
    let b_zeta = b_poly.evaluate(&zeta);
    let c_zeta = c_poly.evaluate(&zeta);
    let sigma_a_zeta = sigma_a_poly.evaluate(&zeta);
    let sigma_b_zeta = sigma_b_poly.evaluate(&zeta);
    let z_omega_shifted_zeta = z_poly_omega_shifted.evaluate(&zeta);
    let _round_four = [
        a_zeta,
        b_zeta,
        c_zeta,
        sigma_a_zeta,
        sigma_b_zeta,
        z_omega_shifted_zeta,
    ];
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        main();
    }
}
