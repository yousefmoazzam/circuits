use nalgebra::{RowSVector, SMatrix, Vector4};
use rand::Rng;

type Matrix = SMatrix<i64, 1, 4>;

/// R1CS for `z = xy + 2`, with one constraint:
/// - `z - 2 = xy`
///
/// Using random integers for input variables `x`, `y`
fn main() -> Result<(), String> {
    let left_matrix = Matrix::from_rows(&[RowSVector::from_vec(vec![0, 0, 1, 0])]);
    let right_matrix = Matrix::from_rows(&[RowSVector::from_vec(vec![0, 0, 0, 1])]);
    let output_matrix = Matrix::from_rows(&[RowSVector::from_vec(vec![-2, 1, 0, 0])]);
    let mut rng = rand::rng();
    let modulo: u64 = 1000;
    let x: i64 = i64::try_from(rng.random_range(1..modulo)).unwrap();
    let y: i64 = i64::try_from(rng.random_range(1..modulo)).unwrap();
    let z = x * y + 2;
    let witness_vector = Vector4::new(1, z, x, y);
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
