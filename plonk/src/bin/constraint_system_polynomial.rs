use ark_ff::fields::{Fp64, MontBackend, MontConfig};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};

#[derive(MontConfig)]
#[modulus = "17"]
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp64<MontBackend<FqConfig, 1>>;

/// Take the eqn `a^2 + 1 = b` where `b = 26` represented as a PLONK constraint system, interpolate
/// each set of terms in the PLONK constraint system eqns (ie, interpolate the `ql_i`'s, the
/// `qr_i`'s, etc) to get a single polynomial, and check that this single polynomial vanishes at
/// the elements in the finite field that the evaluation values were evaluated at during
/// interpolation (which will be the 2nd roots of unity)
fn main() {
    const NO_OF_POLY_COEFFS: usize = 2;
    let small_domain = GeneralEvaluationDomain::<Fq>::new(NO_OF_POLY_COEFFS).unwrap();
    let private_input = Fq::from(5);
    let public_input = Fq::from(26);

    let ql_column = [Fq::from(0), Fq::from(1)];
    let qr_column = [Fq::from(0), Fq::from(0)];
    let qo_column = [Fq::from(1), Fq::from(1)];
    let qc_column = [Fq::from(0), Fq::from(1)];
    let qm_column = [Fq::from(1), Fq::from(0)];
    let r_column = [private_input, Fq::from(0)];
    let o_column = [private_input * private_input, public_input];
    let l_column = [private_input, o_column[0]];

    let ql_poly = DensePolynomial::from_coefficients_vec(small_domain.ifft(&ql_column));
    let qr_poly = DensePolynomial::from_coefficients_vec(small_domain.ifft(&qr_column));
    let qo_poly = DensePolynomial::from_coefficients_vec(small_domain.ifft(&qo_column));
    let qc_poly = DensePolynomial::from_coefficients_vec(small_domain.ifft(&qc_column));
    let qm_poly = DensePolynomial::from_coefficients_vec(small_domain.ifft(&qm_column));
    let l_poly = DensePolynomial::from_coefficients_vec(small_domain.ifft(&l_column));
    let r_poly = DensePolynomial::from_coefficients_vec(small_domain.ifft(&r_column));
    let o_poly = DensePolynomial::from_coefficients_vec(small_domain.ifft(&o_column));

    let constraint_system_poly = ql_poly * l_poly.clone() + qr_poly * r_poly.clone()
        - qo_poly * o_poly
        + qc_poly
        + qm_poly * l_poly * r_poly;

    for root_of_unity in small_domain.elements() {
        assert_eq!(constraint_system_poly.evaluate(&root_of_unity), Fq::from(0))
    }
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        main();
    }
}
