use ark_bn254::{Fr, G1Projective};
use ark_ec::{AdditiveGroup, PrimeGroup};
use ark_std::ops::Mul;

/// Verify that prover has `x` and `y` values that solve the following system of linear equations:
/// - `2x + y = 5`
/// - `-x + y = 2`
fn main() -> Result<(), String> {
    let generator = G1Projective::generator();
    let x = Fr::from(1);
    let y = Fr::from(3);
    let encrypted_x = generator.mul(x);
    let encrypted_y = generator.mul(y);
    let eqn1_x_term = encrypted_x.double();
    let eqn2_x_term = -encrypted_x;
    let witness = [
        encrypted_x,
        encrypted_y,
        generator.mul(Fr::from(5)),
        generator.mul(Fr::from(2)),
    ];
    let is_eqn1_satisfied = eqn1_x_term + witness[1] == witness[2];
    let is_eqn2_satisfied = eqn2_x_term + witness[1] == witness[3];
    if !(is_eqn1_satisfied && is_eqn2_satisfied) {
        return Err("Provided values do not solve all equations".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify() {
        assert!(main().is_ok())
    }
}
