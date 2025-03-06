use nalgebra::{RowSVector, SMatrix, SVector};

/// Number of constraints in system
const CONSTRAINTS: usize = 15;
/// Number of values in witness vector
const VARIABLES: usize = 37;

type RowVec = RowSVector<i32, VARIABLES>;
type ColVec = SVector<i32, VARIABLES>;
type Matrix = SMatrix<i32, CONSTRAINTS, VARIABLES>;

#[derive(Clone, Copy)]
enum Colour {
    Blue = 1,
    Red = 2,
    Green = 3,
}

/// R1CS for Australia 3-colouring problem
///
/// `wa` = West Australia
/// `sa` = South Australia
/// `nt` = Northern Territory
/// `q` = Queensland
/// `nsw` = New South Wales
/// `v` = Victoria
///
/// System has 15 constraints:
/// - 6 colour constraints (one for each territory)
/// - 9 boundary constraints (one for each pair of neighbouring territories)
///
/// and 37 elements in witness:
/// - 1 unit value
/// - 6 inputs (colour for each territory)
/// - 30 intermediate values:
///     - 6 squared values (one for each territory)
///     - 6 cubed values (one for each territory)
///     - 9 pair-values for each pair of neighbouring territorries
///     - 9 squared pair-values for each pair of neighbouring territories
fn main() -> Result<(), String> {
    let wa = Colour::Blue as i32;
    let sa = Colour::Green as i32;
    let nt = Colour::Red as i32;
    let q = Colour::Blue as i32;
    let nsw = Colour::Red as i32;
    let v = Colour::Blue as i32;

    let v1 = wa * wa;
    let v2 = sa * sa;
    let v3 = nt * nt;
    let v4 = q * q;
    let v5 = nsw * nsw;
    let v6 = v * v;

    let w1 = wa * v1;
    let w2 = sa * v2;
    let w3 = nt * v3;
    let w4 = q * v4;
    let w5 = nsw * v5;
    let w6 = v * v6;

    let x12 = wa * sa;
    let x13 = wa * nt;
    let x23 = sa * nt;
    let x24 = sa * q;
    let x25 = sa * nsw;
    let x26 = sa * v;
    let x34 = nt * q;
    let x45 = q * nsw;
    let x56 = nsw * v;

    let y12 = v1 * v2;
    let y13 = v1 * v3;
    let y23 = v2 * v3;
    let y24 = v2 * v4;
    let y25 = v2 * v5;
    let y26 = v2 * v6;
    let y34 = v3 * v4;
    let y45 = v4 * v5;
    let y56 = v5 * v6;

    let witness_vector = ColVec::from_vec(vec![
        1, wa, sa, nt, q, nsw, v, v1, v2, v3, v4, v5, v6, w1, w2, w3, w4, w5, w6, x12, x13, x23,
        x24, x25, x26, x34, x45, x56, y12, y13, y23, y24, y25, y26, y34, y45, y56,
    ]);

    let left_matrix = Matrix::from_rows(&[
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // SA colour constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // NT colour constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // Q colour constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // NSW colour constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // V colour constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // WA/SA boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // WA/NT boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // SA/NT boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // SA/Q boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // SA/NSW boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // SA/V boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // NT/Q boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // Q/NSW boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // NSW/V boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
    ]);

    let right_matrix = Matrix::from_rows(&[
        // WA colour constraint
        RowVec::from_vec(vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // SA colour constraint
        RowVec::from_vec(vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // NT colour constraint
        RowVec::from_vec(vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // Q colour constraint
        RowVec::from_vec(vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // NSW colour constraint
        RowVec::from_vec(vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // V colour constraint
        RowVec::from_vec(vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // WA/SA boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // WA/NT boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // SA/NT boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // SA/Q boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // SA/NSW boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // SA/V boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // NT/Q boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // Q/NSW boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // NSW/V boundary constraint
        RowVec::from_vec(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ]),
    ]);

    let output_matrix = Matrix::from_rows(&[
        // WA colour constraint
        RowVec::from_vec(vec![
            -6, 11, 0, 0, 0, 0, 0, -6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // SA colour constraint
        RowVec::from_vec(vec![
            -6, 0, 11, 0, 0, 0, 0, 0, -6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // NT colour constraint
        RowVec::from_vec(vec![
            -6, 0, 0, 11, 0, 0, 0, 0, 0, -6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // Q colour constraint
        RowVec::from_vec(vec![
            -6, 0, 0, 0, 11, 0, 0, 0, 0, 0, -6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // NSW colour constraint
        RowVec::from_vec(vec![
            -6, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, -6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // V colour constraint
        RowVec::from_vec(vec![
            -6, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, -6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // WA/SA boundary constraint
        RowVec::from_vec(vec![
            -36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 0,
            -11, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // WA/NT boundary constraint
        RowVec::from_vec(vec![
            -36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0,
            0, -11, 0, 0, 0, 0, 0, 0, 0,
        ]),
        // SA/NT boundary constraint
        RowVec::from_vec(vec![
            -36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0,
            0, 0, -11, 0, 0, 0, 0, 0, 0,
        ]),
        // SA/Q boundary constraint
        RowVec::from_vec(vec![
            -36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 0, 0,
            0, 0, 0, -11, 0, 0, 0, 0, 0,
        ]),
        // SA/NSW boundary constraint
        RowVec::from_vec(vec![
            -36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 0,
            0, 0, 0, 0, -11, 0, 0, 0, 0,
        ]),
        // SA/V boundary constraint
        RowVec::from_vec(vec![
            -36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0,
            0, 0, 0, 0, 0, -11, 0, 0, 0,
        ]),
        // NT/Q boundary constraint
        RowVec::from_vec(vec![
            -36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0, 0,
            0, 0, 0, 0, 0, 0, -11, 0, 0,
        ]),
        // Q/NSW boundary constraint
        RowVec::from_vec(vec![
            -36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 0,
            0, 0, 0, 0, 0, 0, 0, -11, 0,
        ]),
        // NSW/V boundary constraint
        RowVec::from_vec(vec![
            -36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36,
            0, 0, 0, 0, 0, 0, 0, 0, -11,
        ]),
    ]);

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
