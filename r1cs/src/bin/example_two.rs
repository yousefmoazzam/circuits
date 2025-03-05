use nalgebra::{RowSVector, SMatrix, SVector};
use rand::Rng;

type ColVec8 = SVector<u64, 8>;
type RowVec8 = RowSVector<u64, 8>;
type Matrix = SMatrix<u64, 3, 8>;

/// R1CS for `r = xyzu`, with three constraints:
/// - `v_1 = xy`
/// - `v_2 = zu`
/// - `r = v_1v_2`
///
/// Using random integers for input variables `x`, `y`, `z`, `u`
fn main() -> Result<(), String> {
    let left_matrix = Matrix::from_rows(&[
        RowVec8::from_vec(vec![0, 0, 1, 0, 0, 0, 0, 0]),
        RowVec8::from_vec(vec![0, 0, 0, 0, 1, 0, 0, 0]),
        RowVec8::from_vec(vec![0, 0, 0, 0, 0, 0, 1, 0]),
    ]);
    let right_matrix = Matrix::from_rows(&[
        RowVec8::from_vec(vec![0, 0, 0, 1, 0, 0, 0, 0]),
        RowVec8::from_vec(vec![0, 0, 0, 0, 0, 1, 0, 0]),
        RowVec8::from_vec(vec![0, 0, 0, 0, 0, 0, 0, 1]),
    ]);
    let output_matrix = Matrix::from_rows(&[
        RowVec8::from_vec(vec![0, 0, 0, 0, 0, 0, 1, 0]),
        RowVec8::from_vec(vec![0, 0, 0, 0, 0, 0, 0, 1]),
        RowVec8::from_vec(vec![0, 1, 0, 0, 0, 0, 0, 0]),
    ]);
    let mut rng = rand::rng();
    let modulo: u64 = 1000;
    let x: u64 = rng.random_range(1..modulo);
    let y: u64 = rng.random_range(1..modulo);
    let z: u64 = rng.random_range(1..modulo);
    let u: u64 = rng.random_range(1..modulo);
    let v1 = x * y;
    let v2 = z * u;
    let r = v1 * v2;
    let witness_vector = ColVec8::from_vec(vec![1, r, x, y, z, u, v1, v2]);
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
