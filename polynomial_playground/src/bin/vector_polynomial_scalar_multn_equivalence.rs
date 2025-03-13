use ark_ff::fields::{Fp64, MontBackend, MontConfig};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
};
use std::ops::Mul;

#[derive(MontConfig)]
#[modulus = "17"]
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp64<MontBackend<FqConfig, 1>>;

/// Verifies that the following two ways produce the same polynomial:
/// - combining a vector of evaluation values `n` times with itself, then interpolating
/// - interpolating a vector of evaluation values, and then combining this polynomial with itself
/// `n` times
fn main() {
    const NO_OF_POLY_COEFFS: usize = 4;
    let small_domain = GeneralEvaluationDomain::<Fq>::new(NO_OF_POLY_COEFFS).unwrap();
    let scalar = Fq::from(3);
    let evals = vec![Fq::from(2), Fq::from(5), Fq::from(7)];

    let multipled_evals = evals.iter().map(|a| scalar * a).collect::<Vec<_>>();
    let combined_then_interpolated_poly =
        DensePolynomial::from_coefficients_vec(small_domain.ifft(&multipled_evals));

    let interpolated_then_combined_poly =
        DensePolynomial::from_coefficients_vec(small_domain.ifft(&evals)).mul(scalar);

    assert_eq!(
        combined_then_interpolated_poly,
        interpolated_then_combined_poly
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
