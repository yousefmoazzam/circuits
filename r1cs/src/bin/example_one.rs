use nalgebra::{SMatrix, Vector4};

type Matrix = SMatrix<u32, 1, 4>;

/// R1CS with single constraint: `z = xy`
///
/// Proving `4223 = 41 x 103`
fn main() -> Result<(), String> {
    let left_matrix = Matrix::new(0, 0, 1, 0);
    let right_matrix = Matrix::new(0, 0, 0, 1);
    let output_matrix = Matrix::new(0, 1, 0, 0);
    let witness_vector = Vector4::new(1, 4223, 41, 103);
    let res = output_matrix * witness_vector
        == left_matrix * witness_vector * right_matrix * witness_vector;
    if !res {
        return Err("Inequality in matrix equation".to_string());
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
