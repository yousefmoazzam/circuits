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

/// Define six coordinate accumulators:
/// - `id_permutation` and `y_l`, to form the accumulator `p_l`
/// - `sigma_l` and `y_l`, to form the accumulator `p_l_prime`
/// - `id_permutation` and `y_r`, to form the accumulator `p_r`
/// - `sigma_o` and `y_r`, to form the accumulator `p_r_prime`
/// - `id_permutation` and `y_o`, to form the accumulator `p_o`
/// - `sigma_o` and `y_o`, to form the accumulator `p_o_prime`
///
/// `y_l` represents a polynomial interpolating a set of wire values `l_i`, `y_r` represents a
/// second polynomial interpolating another set of wire values `r_i`, and `y_o` represents a
/// polynomial interpolating a third set of wire values `o_i`.
///
/// The values 4 and 12 common across the set of evaluation values which were interpolated
/// represent two copy constraints between two pairs of wires among the three different sets:
/// - `l_2` and `o_1`
/// - `r_3` and `o_2`
///
/// In the context of the indices that "cover" all three sets of wires:
/// - `l(x)` is associated with 1, `omega`, `omega^2`, `omega^3`
/// - `r(x)` is associated with g, `g omega`, `g omega^2`, `g omega^3`
/// - `o(x)` is associated with g^2, `g^2 omega`, `g^2 omega^2`, `g^2 omega^3`
///
/// NOTE: For a number of attempts to change values that would violate the copy constraints, the
/// assertions also fail. However, there are also cases where the copy constraints are violated,
/// yet the assertions still pass (for example, swapping 6 and 4 in `y_l`). It's been observed that
/// whenever copy constraints are violated but the assertions pass, that there are *zero* values in
/// both `p_l_evals` and `p_l_prime_evals`. This makes the "end value" assertions trivially pass
/// due to having multiplication by zero on both sides of the eqn, and needs to be investigated.
fn main() {
    const NO_OF_POLY_COEFFS: usize = 4;
    let small_domain = GeneralEvaluationDomain::<Fq>::new(NO_OF_POLY_COEFFS).unwrap();
    let domain = small_domain.elements().collect::<Vec<_>>();
    let alpha = Fq::from(11);
    let beta = Fq::from(14);
    let g = Fq::from(14);
    let id_permutation = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&domain));

    // Accounts for the "permutation" that occurs which maps `omega` to `g^2` (rather than to
    // `omega`)
    let sigma_l = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&[
        domain[0],
        g * g,
        domain[2],
        domain[3],
    ]));
    let y_l = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&[
        Fq::from(6),
        Fq::from(4),
        Fq::from(1),
        Fq::from(8),
    ]));

    // Accounts for the "permutation" that occurs which maps `omega^2` to `g^2 omega` (rather than
    // to `omega^2`)
    let sigma_r = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&[
        g,
        g * domain[1],
        g * g * domain[1],
        g * domain[3],
    ]));
    let y_r = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&[
        Fq::from(9),
        Fq::from(3),
        Fq::from(12),
        Fq::from(2),
    ]));

    // Accounts for the "permutation" that occurs which maps:
    // - 1 to `omega` (rather than to `g^2`)
    // - `omega` to `g omega^2` (rather than to `g^2 omega`)
    let sigma_o = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&[
        domain[1],
        g * domain[2],
        g * g * domain[2],
        g * g * domain[3],
    ]));
    let y_o = DensePolynomial::from_coefficients_slice(&small_domain.ifft(&[
        Fq::from(4),
        Fq::from(12),
        Fq::from(13),
        Fq::from(7),
    ]));

    let mut p_l_evals = vec![Fq::from(1)];
    for (idx, elem) in domain.iter().enumerate() {
        p_l_evals.push(
            p_l_evals[idx] * (alpha + id_permutation.evaluate(elem) + y_l.evaluate(elem) * beta),
        );
    }
    let mut p_l_prime_evals = vec![Fq::from(1)];
    for (idx, elem) in domain.iter().enumerate() {
        p_l_prime_evals.push(
            p_l_prime_evals[idx] * (alpha + sigma_l.evaluate(elem) + y_l.evaluate(elem) * beta),
        );
    }
    let p_l = DensePolynomial::from_coefficients_slice(
        &small_domain.ifft(&p_l_evals[..p_l_evals.len() - 1]),
    );
    let p_l_prime = DensePolynomial::from_coefficients_slice(
        &small_domain.ifft(&p_l_prime_evals[..p_l_prime_evals.len() - 1]),
    );

    let mut p_r_evals = vec![Fq::from(1)];
    for (idx, elem) in domain.iter().enumerate() {
        p_r_evals.push(
            p_r_evals[idx]
                * (alpha + g * id_permutation.evaluate(elem) + y_r.evaluate(elem) * beta),
        );
    }
    let mut p_r_prime_evals = vec![Fq::from(1)];
    for (idx, elem) in domain.iter().enumerate() {
        p_r_prime_evals.push(
            p_r_prime_evals[idx] * (alpha + sigma_r.evaluate(elem) + y_r.evaluate(elem) * beta),
        );
    }
    let p_r = DensePolynomial::from_coefficients_slice(
        &small_domain.ifft(&p_r_evals[..p_r_evals.len() - 1]),
    );
    let p_r_prime = DensePolynomial::from_coefficients_slice(
        &small_domain.ifft(&p_r_prime_evals[..p_r_prime_evals.len() - 1]),
    );

    let mut p_o_evals = vec![Fq::from(1)];
    for (idx, elem) in domain.iter().enumerate() {
        p_o_evals.push(
            p_o_evals[idx]
                * (alpha + g * g * id_permutation.evaluate(elem) + y_o.evaluate(elem) * beta),
        );
    }
    let mut p_o_prime_evals = vec![Fq::from(1)];
    for (idx, elem) in domain.iter().enumerate() {
        p_o_prime_evals.push(
            p_o_prime_evals[idx] * (alpha + sigma_o.evaluate(elem) + y_o.evaluate(elem) * beta),
        );
    }
    let p_o = DensePolynomial::from_coefficients_slice(
        &small_domain.ifft(&p_o_evals[..p_o_evals.len() - 1]),
    );
    let p_o_prime = DensePolynomial::from_coefficients_slice(
        &small_domain.ifft(&p_o_prime_evals[..p_o_prime_evals.len() - 1]),
    );

    // Verify polynomial accumulator starting and ending constraints are satisfied
    assert_eq!(p_l.evaluate(&Fq::from(1)), Fq::from(1));
    assert_eq!(p_l_prime.evaluate(&Fq::from(1)), Fq::from(1));
    assert_eq!(p_r.evaluate(&Fq::from(1)), Fq::from(1));
    assert_eq!(p_r_prime.evaluate(&Fq::from(1)), Fq::from(1));
    assert_eq!(p_o.evaluate(&Fq::from(1)), Fq::from(1));
    assert_eq!(p_o_prime.evaluate(&Fq::from(1)), Fq::from(1));
    assert_eq!(
        p_l_evals[p_l_evals.len() - 1]
            * p_r_evals[p_r_evals.len() - 1]
            * p_o_evals[p_o_evals.len() - 1],
        p_l_prime_evals[p_l_prime_evals.len() - 1]
            * p_r_prime_evals[p_r_prime_evals.len() - 1]
            * p_o_prime_evals[p_o_prime_evals.len() - 1]
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
