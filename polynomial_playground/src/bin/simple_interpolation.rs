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

/// Interpolate vector of 4 finite field elements and check resulting polynomial by evaluating at
/// the roots of unity
///
/// TODO: Should produce polynomial `11x^3 + 14x^2 + 4x + 9` but instead produces polynomial
/// `13x^3 + 14x^2 + 2x + 9`, and so two of the four evalutations performed when checking the
/// interpolated polynomail are incorrect (2 instead of 1, and 5 instead of 6)
fn main() {
    const NO_OF_POLY_COEFFS: usize = 4;
    let small_domain = GeneralEvaluationDomain::<Fq>::new(NO_OF_POLY_COEFFS).unwrap();
    let one = Fq::from(1);
    // Squares to 16 (which is equivalent to -1), so "4 squares to -1"; hence, equivalent to i
    let omega_zero = Fq::from(4);
    // Additive inverse of 1, so equivalent to -1
    let omega_one = Fq::from(16);
    // Additive inverse of 4, and 4 is equivalent to i; hence, equivalent to -i
    let omega_two = Fq::from(13);
    let x_values = [one, omega_zero, omega_one, omega_two];
    let y_values = vec![Fq::from(4), Fq::from(1), Fq::from(8), Fq::from(6)];
    let coeffs = small_domain.ifft(&y_values);
    let poly = DensePolynomial::from_coefficients_vec(coeffs);
    println!("poly is {:?}", poly);
    for root_of_unity in x_values {
        println!(
            "poly evaluated at root of unity {} is {}",
            root_of_unity,
            poly.evaluate(&root_of_unity)
        );
    }
    for (root_of_unity, y) in std::iter::zip(x_values, y_values) {
        assert_eq!(poly.evaluate(&root_of_unity), y);
    }
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        main()
    }
}
