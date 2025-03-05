use nalgebra::{RowSVector, SMatrix, Vector6};
use rand::Rng;

type RowVec8 = RowSVector<i64, 6>;
type Matrix = SMatrix<i64, 3, 6>;

/// R1CS for `z = 3yx^2 + 5xy -x -2y + 3`, with three constraints:
/// - `v_1 = 3xx`
/// - `v_2 = v_1y`
/// - `z - 3 + 2y + x - v_2 = 5xy`
///
/// Using random integers for input variables `x`, `y`
fn main() -> Result<(), String> {
    let left_matrix = Matrix::from_rows(&[
        RowVec8::from_vec(vec![0, 0, 3, 0, 0, 0]),
        RowVec8::from_vec(vec![0, 0, 0, 0, 1, 0]),
        RowVec8::from_vec(vec![0, 0, 5, 0, 0, 0]),
    ]);
    let right_matrix = Matrix::from_rows(&[
        RowVec8::from_vec(vec![0, 0, 1, 0, 0, 0]),
        RowVec8::from_vec(vec![0, 0, 0, 1, 0, 0]),
        RowVec8::from_vec(vec![0, 0, 0, 1, 0, 0]),
    ]);
    let output_matrix = Matrix::from_rows(&[
        RowVec8::from_vec(vec![0, 0, 0, 0, 1, 0]),
        RowVec8::from_vec(vec![0, 0, 0, 0, 0, 1]),
        RowVec8::from_vec(vec![-3, 1, 1, 2, 0, -1]),
    ]);
    let mut rng = rand::rng();
    let modulo: u64 = 1000;
    let x: i64 = i64::try_from(rng.random_range(1..modulo)).unwrap();
    let y: i64 = i64::try_from(rng.random_range(1..modulo)).unwrap();
    let v1 = 3 * x * x;
    let v2 = v1 * y;
    let z = 5 * x * y + 3 - 2 * y - x + v2;
    let witness_vector = Vector6::new(1, z, x, y, v1, v2);
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
