use ark_bn254::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_std::ops::Mul;

/// Verify that prover has `x` and `y` values that solve `x + y = 15`
fn main() -> Result<(), String> {
    let generator = G1Projective::generator();
    let x = Fr::from(5);
    let y = Fr::from(10);
    let encrypted_x = generator.mul(x);
    let encrypted_y = generator.mul(y);
    let witness = [encrypted_x, encrypted_y, generator.mul(Fr::from(15))];
    if witness[2] != witness[0] + witness[1] {
        return Err("Provided values do not solve equation".to_string());
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
