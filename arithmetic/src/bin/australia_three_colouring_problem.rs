#[derive(Clone, Copy)]
enum Colour {
    Blue = 1,
    Red = 2,
    Green = 3,
}

/// `wa` = West Australia
/// `sa` = South Australia
/// `nt` = Northern Territory
/// `q` = Queensland
/// `nsw` = New South Wales
/// `v` = Victoria
fn main() -> Result<(), String> {
    let wa = Colour::Blue;
    let sa = Colour::Green;
    let nt = Colour::Red;
    let q = Colour::Blue;
    let nsw = Colour::Red;
    let v = Colour::Blue;

    let wa_colour_assignment_constraint = (1 - wa as i8) * (2 - wa as i8) * (3 - wa as i8) == 0;
    let sa_colour_assignment_constraint = (1 - sa as i8) * (2 - sa as i8) * (3 - sa as i8) == 0;
    let nt_colour_assignment_constraint = (1 - nt as i8) * (2 - nt as i8) * (3 - nt as i8) == 0;
    let q_colour_assignment_constraint = (1 - q as i8) * (2 - q as i8) * (3 - q as i8) == 0;
    let nsw_colour_assignment_constraint = (1 - nsw as i8) * (2 - nsw as i8) * (3 - nsw as i8) == 0;
    let v_colour_assignment_constraint = (1 - v as i8) * (2 - v as i8) * (3 - v as i8) == 0;
    let colour_assignment_constraint = wa_colour_assignment_constraint
        && sa_colour_assignment_constraint
        && nt_colour_assignment_constraint
        && q_colour_assignment_constraint
        && nsw_colour_assignment_constraint
        && v_colour_assignment_constraint;

    let wa_boundary_constraints = [
        (2 - wa as i8 * sa as i8) * (3 - wa as i8 * sa as i8) * (6 - wa as i8 * sa as i8) == 0,
        (2 - wa as i8 * nt as i8) * (3 - wa as i8 * nt as i8) * (6 - wa as i8 * nt as i8) == 0,
    ];
    let nt_boundary_constraints = [
        (2 - nt as i8 * sa as i8) * (3 - nt as i8 * sa as i8) * (6 - nt as i8 * sa as i8) == 0,
        (2 - nt as i8 * q as i8) * (3 - nt as i8 * q as i8) * (6 - nt as i8 * q as i8) == 0,
    ];
    let sa_boundary_constraints = [
        (2 - sa as i8 * q as i8) * (3 - sa as i8 * q as i8) * (6 - sa as i8 * q as i8) == 0,
        (2 - sa as i8 * nsw as i8) * (3 - sa as i8 * nsw as i8) * (6 - sa as i8 * nsw as i8) == 0,
        (2 - sa as i8 * v as i8) * (3 - sa as i8 * v as i8) * (6 - sa as i8 * v as i8) == 0,
    ];
    let q_boundary_constraints =
        [(2 - q as i8 * nsw as i8) * (3 - q as i8 * nsw as i8) * (6 - q as i8 * nsw as i8) == 0];
    let nsw_boundary_constraints =
        [(2 - nsw as i8 * v as i8) * (3 - nsw as i8 * v as i8) * (6 - nsw as i8 * v as i8) == 0];
    let mut boundary_constraint = true;
    let boundary_constraints_iter = wa_boundary_constraints
        .iter()
        .chain(nt_boundary_constraints.iter())
        .chain(sa_boundary_constraints.iter())
        .chain(q_boundary_constraints.iter())
        .chain(nsw_boundary_constraints.iter());
    for constraint in boundary_constraints_iter {
        boundary_constraint &= constraint;
    }

    let expression = colour_assignment_constraint && boundary_constraint;
    if !expression {
        return Err("Invalid colouring solution".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify_have_valid_solution() {
        assert!(main().is_ok());
    }
}
