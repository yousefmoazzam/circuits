use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_std::ops::Mul;

/// Verify that prover has `x` and `z` values that solve the eqn `x^3 + 5x^2 - xz + 5 = 155`,
/// without them needing to reveal to the verifier their `x` and `z` values
fn main() -> Result<(), String> {
    let x = 5;
    let z = 20;
    let v1 = x * x;
    let v2 = x * z;
    let y = 155;
    let left_matrix = [[0, 0, 1, 0, 0, 0], [0, 0, 1, 0, 0, 0], [0, 0, 1, 0, 0, 0]];
    let right_matrix = [[0, 0, 1, 0, 0, 0], [0, 0, 0, 1, 0, 0], [0, 0, 0, 0, 1, 0]];
    let output_matrix = [[0, 0, 0, 0, 1, 0], [0, 0, 0, 0, 0, 1], [-5, 1, 0, 0, -5, 1]];
    let witness_vector = [1, y, x, z, v1, v2];

    // Prover steps
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    let g1_encrypted_witness = witness_vector.map(|val| g1.mul(Fr::from(val)));
    let g2_encrypted_witness = witness_vector.map(|val| g2.mul(Fr::from(val)));
    let left_mult = left_matrix
        .iter()
        .map(|constraint| {
            g1_encrypted_witness[0].mul(Fr::from(constraint[0]))
                + g1_encrypted_witness[1].mul(Fr::from(constraint[1]))
                + g1_encrypted_witness[2].mul(Fr::from(constraint[2]))
                + g1_encrypted_witness[3].mul(Fr::from(constraint[3]))
                + g1_encrypted_witness[4].mul(Fr::from(constraint[4]))
                + g1_encrypted_witness[5].mul(Fr::from(constraint[5]))
        })
        .collect::<Vec<_>>();
    let right_mult = right_matrix
        .iter()
        .map(|constraint| {
            g2_encrypted_witness[0].mul(Fr::from(constraint[0]))
                + g2_encrypted_witness[1].mul(Fr::from(constraint[1]))
                + g2_encrypted_witness[2].mul(Fr::from(constraint[2]))
                + g2_encrypted_witness[3].mul(Fr::from(constraint[3]))
                + g2_encrypted_witness[4].mul(Fr::from(constraint[4]))
                + g2_encrypted_witness[5].mul(Fr::from(constraint[5]))
        })
        .collect::<Vec<_>>();

    // Verifier steps
    let output_mult = output_matrix
        .iter()
        .map(|constraint| {
            g1_encrypted_witness[0].mul(Fr::from(constraint[0]))
                + g1_encrypted_witness[1].mul(Fr::from(constraint[1]))
                + g1_encrypted_witness[2].mul(Fr::from(constraint[2]))
                + g1_encrypted_witness[3].mul(Fr::from(constraint[3]))
                + g1_encrypted_witness[4].mul(Fr::from(constraint[4]))
                + g1_encrypted_witness[5].mul(Fr::from(constraint[5]))
        })
        .map(|point| Bn254::pairing(point, g2))
        .collect::<Vec<_>>();
    let paired_vectors = std::iter::zip(left_mult, right_mult)
        .map(|(left, right)| Bn254::pairing(left, right))
        .collect::<Vec<_>>();
    if paired_vectors != output_mult {
        return Err("Unsuccessful verification of solution".to_string());
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
