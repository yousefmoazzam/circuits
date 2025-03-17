/// Take the eqn `a^2 + 1 = b` where `b = 26` represented as an arithmetic circuit (addition and
/// multiplication gates only), represent as a PLONK constraint system, and check that the system
/// is indeed satisfied by a known correct solution.
fn main() -> Result<(), String> {
    let private_input = 5;

    // Copy constraints for eqn 1
    let l_1 = private_input;
    let r_1 = l_1;

    // Public input
    let o_2 = 26;

    let ql_1 = 0;
    let qr_1 = 0;
    let qo_1 = 1;
    let qc_1 = 0;
    let qm_1 = 1;
    let o_1 = l_1 * r_1;
    let eqn_1 = ql_1 * l_1 + qr_1 * r_1 - qo_1 * o_1 + qc_1 + qm_1 * l_1 * r_1;

    // Copy constraints for eqn 2
    let l_2 = o_1;

    let r_2 = 0;
    let ql_2 = 1;
    let qr_2 = 0;
    let qo_2 = 1;
    let qc_2 = 1;
    let qm_2 = 0;
    let eqn_2 = ql_2 * l_2 + qr_2 * r_2 - qo_2 * o_2 + qc_2 + qm_2 * l_2 * r_2;

    let are_constraints_satisfied = eqn_1 == 0 && eqn_2 == 0;
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
        assert!(main().is_ok());
    }
}
