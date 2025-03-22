use ark_bn254::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::{Field, UniformRand};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use ark_std::test_rng;

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
    let _sigma_a_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&sigma_a));
    let _sigma_b_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&sigma_b));
    let _sigma_c_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&sigma_c));

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
    let blinding_poly_a =
        DensePolynomial::from_coefficients_slice(&small_domain.ifft(&blinding_elements[..2]));
    let blinding_poly_b =
        DensePolynomial::from_coefficients_slice(&small_domain.ifft(&blinding_elements[2..4]));
    let blinding_poly_c =
        DensePolynomial::from_coefficients_slice(&small_domain.ifft(&blinding_elements[4..6]));

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
    for elem in domain {
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
    let _round_one = [a_poly_commitment, b_poly_commitment, c_poly_commitment];
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        main();
    }
}
