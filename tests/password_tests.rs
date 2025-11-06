use mdp_manager::password_generator::*;

#[test]
fn test_password_generation_length() {
    let options = PasswordGeneratorOptions {
        length: 20,
        ..Default::default()
    };

    let password = generate_password(&options).unwrap();
    assert_eq!(password.len(), 20);
}

#[test]
fn test_password_includes_required_chars() {
    let options = PasswordGeneratorOptions {
        length: 100,
        include_uppercase: true,
        include_lowercase: true,
        include_numbers: true,
        include_symbols: true,
        avoid_ambiguous: false,
    };

    let password = generate_password(&options).unwrap();

    assert!(password.chars().any(|c| c.is_uppercase()), "Should contain uppercase");
    assert!(password.chars().any(|c| c.is_lowercase()), "Should contain lowercase");
    assert!(password.chars().any(|c| c.is_numeric()), "Should contain numbers");
    assert!(password.chars().any(|c| !c.is_alphanumeric()), "Should contain symbols");
}

#[test]
fn test_password_avoids_ambiguous() {
    let options = PasswordGeneratorOptions {
        length: 100,
        include_uppercase: true,
        include_lowercase: true,
        include_numbers: true,
        include_symbols: false,
        avoid_ambiguous: true,
    };

    let password = generate_password(&options).unwrap();
    let ambiguous = "il1Lo0O";

    for c in password.chars() {
        assert!(!ambiguous.contains(c), "Should not contain ambiguous character: {}", c);
    }
}

#[test]
fn test_password_only_lowercase() {
    let options = PasswordGeneratorOptions {
        length: 50,
        include_uppercase: false,
        include_lowercase: true,
        include_numbers: false,
        include_symbols: false,
        avoid_ambiguous: false,
    };

    let password = generate_password(&options).unwrap();
    assert!(password.chars().all(|c| c.is_lowercase()));
}

#[test]
fn test_password_strength_estimation() {
    assert_eq!(estimate_strength("abc"), PasswordStrength::Weak);
    assert_eq!(estimate_strength("abcd1234"), PasswordStrength::Medium);
    assert_eq!(estimate_strength("Abcd1234!@#$"), PasswordStrength::Strong);
    assert_eq!(estimate_strength("Abcd1234!@#$5678"), PasswordStrength::VeryStrong);
}

#[test]
fn test_empty_charset_error() {
    let options = PasswordGeneratorOptions {
        length: 10,
        include_uppercase: false,
        include_lowercase: false,
        include_numbers: false,
        include_symbols: false,
        avoid_ambiguous: false,
    };

    let result = generate_password(&options);
    assert!(result.is_err());
}

#[test]
fn test_zero_length_error() {
    let options = PasswordGeneratorOptions {
        length: 0,
        ..Default::default()
    };

    let result = generate_password(&options);
    assert!(result.is_err());
}