use nalgebra::{RowSVector, SMatrix, Vector4};
use rand::Rng;

type Matrix = SMatrix<i64, 1, 4>;

/// R1CS for `z = 2x^2 + y`, with 1 constraint:
/// - `z - y = 2xx`
///
/// Using random integers for input variables `x`, `y`
fn main() -> Result<(), String> {
    let left_matrix = Matrix::from_rows(&[RowSVector::from_vec(vec![0, 0, 2, 0])]);
    let right_matrix = Matrix::from_rows(&[RowSVector::from_vec(vec![0, 0, 1, 0])]);
    let output_matrix = Matrix::from_rows(&[RowSVector::from_vec(vec![0, 1, 0, -1])]);
    let mut rng = rand::rng();
    let modulo: u64 = 1000;
    let x: i64 = i64::try_from(rng.random_range(1..modulo)).unwrap();
    let y: i64 = i64::try_from(rng.random_range(1..modulo)).unwrap();
    let z = 2 * x * x + y;
    let witness_vector = Vector4::new(1, z, x, y);
    let res = output_matrix * witness_vector
        == (left_matrix * witness_vector).component_mul(&(right_matrix * witness_vector));
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
