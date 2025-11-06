use rand::Rng;

pub struct PasswordGeneratorOptions {
    pub length: usize,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_numbers: bool,
    pub include_symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordGeneratorOptions {
    fn default() -> Self {
        Self {
            length: 16,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
            avoid_ambiguous: true,
        }
    }
}

const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const NUMBERS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";
const AMBIGUOUS: &str = "il1Lo0O";

pub fn generate_password(options: &PasswordGeneratorOptions) -> Result<String, String> {
    if options.length == 0 {
        return Err("La longueur doit être > 0".to_string());
    }

    let mut charset = String::new();

    if options.include_uppercase {
        charset.push_str(UPPERCASE);
    }
    if options.include_lowercase {
        charset.push_str(LOWERCASE);
    }
    if options.include_numbers {
        charset.push_str(NUMBERS);
    }
    if options.include_symbols {
        charset.push_str(SYMBOLS);
    }

    if charset.is_empty() {
        return Err("Au moins un type de caractère doit être sélectionné".to_string());
    }

    // Retirer les caractères ambigus si demandé
    if options.avoid_ambiguous {
        charset.retain(|c| !AMBIGUOUS.contains(c));
    }

    let charset: Vec<char> = charset.chars().collect();
    let mut rng = rand::thread_rng();

    let password: String = (0..options.length)
        .map(|_| charset[rng.gen_range(0..charset.len())])
        .collect();

    Ok(password)
}

pub fn estimate_strength(password: &str) -> PasswordStrength {
    let len = password.len();
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

    let variety = [has_upper, has_lower, has_digit, has_symbol]
        .iter()
        .filter(|&&x| x)
        .count();

    if len < 8 {
        PasswordStrength::Weak
    } else if len < 12 || variety < 3 {
        PasswordStrength::Medium
    } else if len < 16 || variety < 4 {
        PasswordStrength::Strong
    } else {
        PasswordStrength::VeryStrong
    }
}

#[derive(Debug, PartialEq)]
pub enum PasswordStrength {
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

impl PasswordStrength {
    pub fn label(&self) -> &str {
        match self {
            PasswordStrength::Weak => "Faible",
            PasswordStrength::Medium => "Moyen",
            PasswordStrength::Strong => "Fort",
            PasswordStrength::VeryStrong => "Très fort",
        }
    }

    pub fn color(&self) -> egui::Color32 {
        match self {
            PasswordStrength::Weak => egui::Color32::from_rgb(220, 53, 69),
            PasswordStrength::Medium => egui::Color32::from_rgb(255, 193, 7),
            PasswordStrength::Strong => egui::Color32::from_rgb(40, 167, 69),
            PasswordStrength::VeryStrong => egui::Color32::from_rgb(0, 123, 255),
        }
    }
}