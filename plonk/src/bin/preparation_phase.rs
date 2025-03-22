use ark_ff::{
    fields::{Fp64, MontBackend, MontConfig},
    UniformRand,
};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use ark_std::test_rng;

#[derive(MontConfig)]
#[modulus = "241"]
#[generator = "7"]
pub struct FqConfig;
pub type Fq = Fp64<MontBackend<FqConfig, 1>>;

/// For the eqn `2x^2 - x^2y^2 + 3 = 25`, the preparation phase for a proof of having a solution `x
/// = 2, y = 3` using the PLONK protocol.
fn main() {
    let x = 2;
    let y = 3;
    const NO_OF_POLY_COEFFS: usize = 8;
    let small_domain = GeneralEvaluationDomain::<Fq>::new(NO_OF_POLY_COEFFS).unwrap();
    let domain = small_domain.elements().collect::<Vec<_>>();

    // There are 7 gates in the circuit, but the column vector of wires values are padded to the
    // next highest power of two. In this case this is 2^3 = 8, so there's an extra zero value at
    // the end of each column to represent a "dummy gate" resulting from this padding.
    //
    // Wire column vectors
    let _a = [
        Fq::from(x),
        Fq::from(x),
        Fq::from(y),
        Fq::from(4),
        Fq::from(4),
        Fq::from(8),
        Fq::from(-28),
        Fq::from(0),
    ];
    let _b = [
        Fq::from(x),
        Fq::from(x),
        Fq::from(y),
        Fq::from(0),
        Fq::from(9),
        Fq::from(36),
        Fq::from(3),
        Fq::from(0),
    ];
    let _c = [
        Fq::from(4),
        Fq::from(4),
        Fq::from(9),
        Fq::from(8),
        Fq::from(36),
        Fq::from(-28),
        Fq::from(-25),
        Fq::from(0),
    ];

    // Selector column vectors
    let ql = [
        Fq::from(0),
        Fq::from(0),
        Fq::from(0),
        Fq::from(2),
        Fq::from(0),
        Fq::from(1),
        Fq::from(1),
        Fq::from(0),
    ];
    let qr = [
        Fq::from(0),
        Fq::from(0),
        Fq::from(0),
        Fq::from(0),
        Fq::from(0),
        Fq::from(-1),
        Fq::from(0),
        Fq::from(0),
    ];
    let qm = [
        Fq::from(1),
        Fq::from(1),
        Fq::from(1),
        Fq::from(1),
        Fq::from(1),
        Fq::from(0),
        Fq::from(0),
        Fq::from(0),
    ];
    let qc = [
        Fq::from(0),
        Fq::from(0),
        Fq::from(0),
        Fq::from(0),
        Fq::from(0),
        Fq::from(0),
        Fq::from(3),
        Fq::from(0),
    ];
    let qo = [
        Fq::from(-1),
        Fq::from(-1),
        Fq::from(-1),
        Fq::from(-1),
        Fq::from(-1),
        Fq::from(-1),
        Fq::from(-1),
        Fq::from(0),
    ];

    // Two random field elements used in the index-mapping involved in the permutations
    let k1 = Fq::from(2);
    let k2 = Fq::from(4);

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
    let _ql_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&ql));
    let _qr_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&qr));
    let _qm_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&qm));
    let _qc_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&qc));
    let _qo_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&qo));
    let _sigma_a_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&sigma_a));
    let _sigma_b_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&sigma_b));
    let _sigma_c_poly = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&sigma_c));

    // Define the polynomial which has roots at the eight 8th roots of unity, to be used as a
    // divisor to check if the polynomial being divided also has roots at all the 8th roots of
    // unity (ie, the "vanishing polynomial")
    let zh = small_domain.vanishing_polynomial();
    for elem in domain {
        assert_eq!(zh.evaluate(&elem), Fq::from(0));
    }

    // Define secret value `tau` for use in trusted setup
    let mut rng = test_rng();
    let _tau = Fq::rand(&mut rng);
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        main();
    }
}
