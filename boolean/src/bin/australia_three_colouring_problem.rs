/// `wa` = West Australia
/// `sa` = South Australia
/// `nt` = Northern Territory
/// `q` = Queensland
/// `nsw` = New South Wales
/// `v` = Victoria
#[allow(clippy::nonminimal_bool)]
fn main() -> Result<(), String> {
    let wa_g = false;
    let wa_b = true;
    let wa_r = false;

    let sa_g = true;
    let sa_b = false;
    let sa_r = false;

    let nt_g = false;
    let nt_b = false;
    let nt_r = true;

    let q_g = false;
    let q_b = true;
    let q_r = false;

    let nsw_g = false;
    let nsw_b = false;
    let nsw_r = true;

    let v_g = false;
    let v_b = true;
    let v_r = false;

    let wa_colour_assignment_constraint =
        (wa_g && !wa_b && !wa_r) || (!wa_g && wa_b && !wa_r) || (!wa_g && !wa_b && wa_r);
    let sa_colour_assignment_constraint =
        (sa_g && !sa_b && !sa_r) || (!sa_g && sa_b && !sa_r) || (!sa_g && !sa_b && sa_r);
    let nt_colour_assignment_constraint =
        (nt_g && !nt_b && !nt_r) || (!nt_g && nt_b && !nt_r) || (!nt_g && !nt_b && nt_r);
    let nsw_colour_assignment_constraint =
        (nsw_g && !nsw_b && !nsw_r) || (!nsw_g && nsw_b && !nsw_r) || (!nsw_g && !nsw_b && nsw_r);
    let v_colour_assignment_constraint =
        (v_g && !v_b && !v_r) || (!v_g && v_b && !v_r) || (!v_g && !v_b && v_r);
    let colour_assignment_constraint = wa_colour_assignment_constraint
        && sa_colour_assignment_constraint
        && nt_colour_assignment_constraint
        && nsw_colour_assignment_constraint
        && v_colour_assignment_constraint;

    let wa_boundary_constraints = [
        !(wa_g && sa_g) && !(wa_b && sa_b) && !(wa_r && sa_r),
        !(wa_g && nt_g) && !(wa_b && nt_b) && !(wa_r && nt_r),
    ];
    let nt_boundary_constraints = [
        !(nt_g && sa_g) && !(nt_b && sa_b) && !(nt_r && sa_r),
        !(nt_g && q_g) && !(nt_b && q_b) && !(nt_r && q_r),
    ];
    let sa_boundary_constraints = [
        !(sa_g && q_g) && !(sa_b && q_b) && !(sa_r && q_r),
        !(sa_g && nsw_g) && !(sa_b && nsw_b) && !(sa_r && nsw_r),
        !(sa_g && v_g) && !(sa_b && v_b) && !(sa_r && v_r),
    ];
    let q_boundary_constraints = [!(q_g && nsw_g) && !(q_b && nsw_b) && !(q_r && nsw_r)];
    let nsw_boundary_constraints = [!(nsw_g && v_g) && !(nsw_b && v_b) && !(nsw_r && v_r)];
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
