use ark_ff::fields::{Fp64, MontBackend, MontConfig};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};

#[derive(MontConfig)]
#[modulus = "103"]
#[generator = "5"]
pub struct FqConfig;
pub type Fq = Fp64<MontBackend<FqConfig, 1>>;

/// Use Schwartz-Zippel lemma to check if two vectors of evaluation values are equal or not by:
/// - interpolating individual vectors of field elements into individual polynomials
/// - evaluating the polynomials at a random field element
/// - comparing the result of the polynomial evaluations (one check), rather than comparing the
/// vector of evaluations (`n` number of checks for vectors containing `n` evaluation values)
fn main() {
    const NO_OF_POLY_COEFFS: usize = 2;
    let small_domain = GeneralEvaluationDomain::<Fq>::new(NO_OF_POLY_COEFFS).unwrap();
    let evals = vec![Fq::from(4), Fq::from(8), Fq::from(19)];

    let poly_one = DensePolynomial::from_coefficients_vec(small_domain.ifft(&evals));
    let poly_two = DensePolynomial::from_coefficients_vec(small_domain.ifft(&evals));
    let random_element = Fq::from(42);
    assert_eq!(
        poly_one.evaluate(&random_element),
        poly_two.evaluate(&random_element)
    );

    let different_poly = DensePolynomial::from_coefficients_vec(small_domain.ifft(&[
        Fq::from(3),
        Fq::from(9),
        Fq::from(20),
    ]));
    assert_ne!(
        poly_one.evaluate(&random_element),
        different_poly.evaluate(&random_element)
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
