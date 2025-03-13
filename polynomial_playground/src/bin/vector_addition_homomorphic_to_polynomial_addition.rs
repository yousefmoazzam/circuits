use ark_ff::fields::{Fp64, MontBackend, MontConfig};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
};

#[derive(MontConfig)]
#[modulus = "17"]
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp64<MontBackend<FqConfig, 1>>;

/// Verifies that the following two ways produce the same interpolated polynomial:
/// - summing the pairs of evaluation values in the two vectors, and then interpolating the summed
/// vector
/// - interpolating the two vectors of evaluation values individually, and then summing the
/// two interpolated polynomials
fn main() {
    const NO_OF_POLY_COEFFS: usize = 4;
    let small_domain = GeneralEvaluationDomain::<Fq>::new(NO_OF_POLY_COEFFS).unwrap();
    let evals_one = vec![Fq::from(2), Fq::from(5), Fq::from(7)];
    let evals_two = vec![Fq::from(3), Fq::from(6), Fq::from(8)];

    let sum_evals_then_interpolate = std::iter::zip(evals_one.clone(), evals_two.clone())
        .map(|(a, b)| a + b)
        .collect::<Vec<_>>();
    let sum_evals_then_interpolate_poly =
        DensePolynomial::from_coefficients_vec(small_domain.ifft(&sum_evals_then_interpolate));

    let coeffs_one = small_domain.ifft(&evals_one);
    let coeffs_two = small_domain.ifft(&evals_two);
    let poly_one = DensePolynomial::from_coefficients_vec(coeffs_one);
    let poly_two = DensePolynomial::from_coefficients_vec(coeffs_two);
    let interpolate_evals_then_sum_poly = poly_one + poly_two;

    assert_eq!(
        sum_evals_then_interpolate_poly,
        interpolate_evals_then_sum_poly
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
