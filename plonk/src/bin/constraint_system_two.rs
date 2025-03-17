/// Take the eqn `x^3 + x + 5 = y` where `y = 35` represented as an arithmetic circuit (addition
/// and multiplication gates only), represent as a PLONK constraint system, and check that the
/// system is indeed satisfied by a known correct solution.
fn main() -> Result<(), String> {
    let private_input = 3;

    // Copy constraints for eqn 1 (associated with first multn gate)
    let l_1 = private_input;
    let r_1 = l_1;

    let ql_1 = 0;
    let qr_1 = 0;
    let qo_1 = 1;
    let qm_1 = 1;
    let qc_1 = 0;
    let o_1 = l_1 * r_1;
    //let o_1 = (-ql_1 * a_1 - qr_1 * b_1 - qm_1 * a_1 * b_1 - qc_1) / qo_1;
    let eqn_1 = ql_1 * l_1 + qr_1 * r_1 - qo_1 * o_1 + qc_1 + qm_1 * l_1 * r_1;

    // Copy constraints for eqn 2 (associated with second multn gate)
    let l_2 = o_1;

    let r_2 = private_input;
    let o_2 = l_2 * r_2;
    let ql_2 = 0;
    let qr_2 = 0;
    let qo_2 = 1;
    let qm_2 = 1;
    let qc_2 = 0;
    let eqn_2 = ql_2 * l_2 + qr_2 * r_2 - qo_2 * o_2 + qc_2 + qm_2 * l_2 * r_2;

    // Copy constraints for eqn 3 (associated with first addition gate)
    let r_3 = o_2;

    let l_3 = private_input;
    let o_3 = l_3 + r_3;
    let ql_3 = 1;
    let qr_3 = 1;
    let qo_3 = 1;
    let qm_3 = 0;
    let qc_3 = 0;
    let eqn_3 = ql_3 * l_3 + qr_3 * r_3 - qo_3 * o_3 + qc_3 + qm_3 * l_3 * r_3;

    // Copy constraints for eqn 4 (associated with second addition gate)
    let l_4 = o_3;

    // Public input
    let o_4 = 35;

    let r_4 = 0;
    let ql_4 = 1;
    let qr_4 = 0;
    let qo_4 = 1;
    let qm_4 = 0;
    let qc_4 = 5;
    let eqn_4 = ql_4 * l_4 + qr_4 * r_4 - qo_4 * o_4 + qc_4 + qm_4 * l_4 * r_4;

    let are_constraints_satisfied = eqn_1 == 0 && eqn_2 == 0 && eqn_3 == 0 && eqn_4 == 0;
    if !are_constraints_satisfied {
        return Err("Constraint system is not satisfied".to_string());
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
