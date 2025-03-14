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

/// Check that matrix-vector product `Av_1` is equal to matrix-vector product `Bv_2`, using
/// polynomial evaluation:
/// - let `A` and `B` be 2x2 matrices over the finite field with 17 elements
/// - let `v_1` and `v_2` be length 2 column vectors (ie, they have shape 2x1) over this finite
/// field
/// - interpolate each column of the matrices `A` and `B` to get four polynomials of at most degree
/// 1
/// - analagous to the linear combination in the matrix-vector product `Av_1`, take a linear
/// combination of the polynomials interpolating the columns of `A` using the finite field elements
/// in the vector `v_1` as the coefficients
/// - similarly as above, but for `B` and `v_2`
/// - evaluate the two polynomials resulting from the above linear combinations at a random field
/// element, and compare the result
fn main() {
    const NO_OF_POLY_COEFFS: usize = 2;
    let small_domain = GeneralEvaluationDomain::<Fq>::new(NO_OF_POLY_COEFFS).unwrap();
    let a_columns = [[Fq::from(6), Fq::from(4)], [Fq::from(3), Fq::from(7)]];
    let b_columns = [[Fq::from(3), Fq::from(12)], [Fq::from(9), Fq::from(6)]];
    let v_1 = [Fq::from(2), Fq::from(4)];
    let v_2 = [Fq::from(2), Fq::from(2)];

    let a_columns_polys = a_columns
        .iter()
        .map(|col| DensePolynomial::from_coefficients_vec(small_domain.ifft(col)))
        .collect::<Vec<_>>();
    let a_linear_combination_poly = std::iter::zip(a_columns_polys, v_1)
        .map(|(poly, scalar)| poly * scalar)
        .reduce(|acc, poly| acc + poly)
        .unwrap();

    let b_columns_polys = b_columns
        .iter()
        .map(|col| DensePolynomial::from_coefficients_vec(small_domain.ifft(col)))
        .collect::<Vec<_>>();
    let b_linear_combination_poly = std::iter::zip(b_columns_polys, v_2)
        .map(|(poly, scalar)| poly * scalar)
        .reduce(|acc, poly| acc + poly)
        .unwrap();

    let tau = Fq::from(12);
    assert_eq!(
        a_linear_combination_poly.evaluate(&tau),
        b_linear_combination_poly.evaluate(&tau)
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
