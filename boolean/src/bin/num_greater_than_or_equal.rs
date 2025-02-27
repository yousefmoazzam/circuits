fn main() -> Result<(), String> {
    let number = 186;
    const HUNDRED: u8 = 100;

    let p_7 = number & 0b10000000 == 0b10000000;
    let p_6 = number & 0b01000000 == 0b01000000;
    let p_5 = number & 0b00100000 == 0b00100000;
    let p_4 = number & 0b00010000 == 0b00010000;
    let p_3 = number & 0b00001000 == 0b00001000;
    let p_2 = number & 0b00000100 == 0b00000100;
    let p_1 = number & 0b00000010 == 0b00000010;
    let p_0 = number & 0b00000001 == 0b00000001;

    let q_7 = HUNDRED & 0b10000000 == 0b10000000;
    let q_6 = HUNDRED & 0b01000000 == 0b01000000;
    let q_5 = HUNDRED & 0b00100000 == 0b00100000;
    let q_4 = HUNDRED & 0b00010000 == 0b00010000;
    let q_3 = HUNDRED & 0b00001000 == 0b00001000;
    let q_2 = HUNDRED & 0b00000100 == 0b00000100;
    let q_1 = HUNDRED & 0b00000010 == 0b00000010;
    let q_0 = HUNDRED & 0b00000001 == 0b00000001;

    let bit_7_constraint = greater_than(p_7, q_7);
    let bit_7_6_constraints = eq(p_7, q_7) && greater_than(p_6, q_6);
    let bit_7_6_5_constraints = eq(p_7, q_7) && eq(p_6, q_6) && greater_than(p_5, q_5);
    let bit_7_6_5_4_constraints =
        eq(p_7, q_7) && eq(p_6, q_6) && eq(p_5, q_5) && greater_than(p_4, q_4);
    let bit_7_6_5_4_3_constraints =
        eq(p_7, q_7) && eq(p_6, q_6) && eq(p_5, q_5) && eq(p_4, q_4) && greater_than(p_3, q_3);
    let bit_7_6_5_4_3_2_constraints = eq(p_7, q_7)
        && eq(p_6, q_6)
        && eq(p_5, q_5)
        && eq(p_4, q_4)
        && eq(p_3, q_3)
        && greater_than(p_2, q_2);
    let bit_7_6_5_4_3_2_1_constraints = eq(p_7, q_7)
        && eq(p_6, q_6)
        && eq(p_5, q_5)
        && eq(p_4, q_4)
        && eq(p_3, q_3)
        && eq(p_2, q_2)
        && greater_than(p_1, q_1);
    let bit_7_6_5_4_3_2_1_0_constraints = eq(p_7, q_7)
        && eq(p_6, q_6)
        && eq(p_5, q_5)
        && eq(p_4, q_4)
        && eq(p_3, q_3)
        && eq(p_2, q_2)
        && eq(p_1, q_1)
        && (greater_than(p_0, q_0) || eq(p_0, q_0));
    let comparison_expression = bit_7_constraint
        || bit_7_6_constraints
        || bit_7_6_5_constraints
        || bit_7_6_5_4_constraints
        || bit_7_6_5_4_3_constraints
        || bit_7_6_5_4_3_2_constraints
        || bit_7_6_5_4_3_2_1_constraints
        || bit_7_6_5_4_3_2_1_0_constraints;
    if !comparison_expression {
        return Err(format!("Value not greater than {}", HUNDRED));
    }
    Ok(())
}

/// Check if bits `a` and `b` (represented as booleans) are equal using boolean operators
fn eq(a: bool, b: bool) -> bool {
    (a && b) || (!a && !b)
}

/// Check if bit `a` (represented as a boolean) is greater than bit `b` (represented as a boolean)
/// using boolean operators
fn greater_than(a: bool, b: bool) -> bool {
    a && !b
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn verify_have_num_greater_than_or_equal_to_hundred() {
        assert!(main().is_ok());
    }
}
