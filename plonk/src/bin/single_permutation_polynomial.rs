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

/// Define two coordinate accumulators:
/// - `x` and `y`, to form the accumulator `p`
/// - `x_prime` and `y`, to form the accumulator `p_prime`
///
/// where `y` is representing a polynomial interpolating a single set of wire values (ie, `a_i`) in
/// a PLONK arithmetic circuit that has a copy constraint within a single set of wires.
///
/// The repeated value 6 in the evaluation values which were interpolated to get `y` represent a
/// copy constraint between two wires in the same set (ie, `a_2` and `a_4`).
///
/// Asserting that the "start" and "end" values of the `p` and `p_prime` polynomials is analogous
/// to enforcing the single copy constraint.
fn main() {
    const NO_OF_POLY_COEFFS: usize = 4;
    let small_domain = GeneralEvaluationDomain::<Fq>::new(NO_OF_POLY_COEFFS).unwrap();
    let domain = small_domain.elements().collect::<Vec<_>>();

    // The identity permutation when acting on the 4th roots of unity (which are the domain
    // elements)
    let x = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&domain));
    // A non-trivial permutation of the 4th roots of unity where `omega` (13) and `omega^3` (4) are
    // swapped
    let x_prime = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&[
        Fq::from(1),
        Fq::from(4),
        Fq::from(16),
        Fq::from(13),
    ]));

    // Evaluations for which the values at `omega` and `omega^3` are the same, to match the
    // permutation defined by `x_prime`
    let evals = [Fq::from(5), Fq::from(6), Fq::from(3), Fq::from(6)];
    let y = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&evals));

    let alpha = Fq::from(11);
    let beta = Fq::from(15);
    let mut p_evals = vec![Fq::from(1)];
    for (idx, elem) in domain.iter().enumerate() {
        p_evals.push(p_evals[idx] * (alpha + x.evaluate(elem) + y.evaluate(elem) * beta));
    }
    let mut p_prime_evals = vec![Fq::from(1)];
    for (idx, elem) in domain.iter().enumerate() {
        p_prime_evals
            .push(p_prime_evals[idx] * (alpha + x_prime.evaluate(elem) + y.evaluate(elem) * beta));
    }
    let p =
        DensePolynomial::from_coefficients_slice(&small_domain.ifft(&p_evals[..p_evals.len() - 1]));
    let p_prime = DensePolynomial::from_coefficients_slice(
        &small_domain.ifft(&p_prime_evals[..p_prime_evals.len() - 1]),
    );

    // Verify polynomial accumulator starting and ending constraints are satisfied
    assert_eq!(p.evaluate(&Fq::from(1)), Fq::from(1));
    assert_eq!(p_prime.evaluate(&Fq::from(1)), Fq::from(1));
    assert_eq!(
        p_evals[p_evals.len() - 1],
        p_prime_evals[p_prime_evals.len() - 1]
    );
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        main();
    }
}
