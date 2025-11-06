use crate::crypto::*;
use crate::models::{Entry, Vault, VaultFile};
use std::fs;
use std::path::Path;

pub fn save_vault(
    vault: &Vault,
    path: &Path,
    master_password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Sérialiser le coffre
    let plaintext = serde_json::to_string(vault)?;

    // Générer salt et nonce
    let salt = generate_salt();
    let nonce = generate_nonce();

    // Dériver la clé
    let params = CryptoParams::default();
    let key = derive_key(master_password, &salt, &params)?;
    let secure_key = SecureKey::new(key);

    // Chiffrer
    let ciphertext = encrypt(plaintext.as_bytes(), secure_key.as_bytes(), &nonce)?;

    // Créer la structure du fichier
    let vault_file = VaultFile {
        version: 1,
        kdf: "argon2id".to_string(),
        salt: encode_base64(&salt),
        nonce: encode_base64(&nonce),
        ciphertext: encode_base64(&ciphertext),
    };

    // Sauvegarder
    let json = serde_json::to_string_pretty(&vault_file)?;
    fs::write(path, json)?;

    Ok(())
}

pub fn load_vault(
    path: &Path,
    master_password: &str,
) -> Result<Vault, Box<dyn std::error::Error>> {
    // Charger le fichier
    let contents = fs::read_to_string(path)?;
    let vault_file: VaultFile = serde_json::from_str(&contents)?;

    // Décoder base64
    let salt = decode_base64(&vault_file.salt)?;
    let nonce = decode_base64(&vault_file.nonce)?;
    let ciphertext = decode_base64(&vault_file.ciphertext)?;

    // Dériver la clé
    let params = CryptoParams::default();
    let key = derive_key(master_password, &salt, &params)?;
    let secure_key = SecureKey::new(key);

    // Déchiffrer
    let plaintext = decrypt(&ciphertext, secure_key.as_bytes(), &nonce)?;

    // Désérialiser
    let vault: Vault = serde_json::from_slice(&plaintext)?;

    Ok(vault)
}

pub fn export_csv(
    vault: &Vault,
    path: &Path,
    plaintext: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = csv::Writer::from_path(path)?;

    wtr.write_record(&["name", "login", "password", "url", "notes", "tags"])?;

    for entry in &vault.entries {
        let password_field = if plaintext {
            entry.password.as_str()
        } else {
            "***"
        };
        
        wtr.write_record(&[
            &entry.name,
            &entry.login,
            password_field,
            entry.url.as_deref().unwrap_or(""),
            entry.notes.as_deref().unwrap_or(""),
            &entry.tags.join(";"),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

pub fn import_csv(path: &Path) -> Result<Vec<Entry>, Box<dyn std::error::Error>> {
    let mut rdr = csv::Reader::from_path(path)?;
    let mut entries = Vec::new();

    for result in rdr.records() {
        let record = result?;

        if record.len() < 3 {
            continue;
        }

        let name = record.get(0).unwrap_or("").to_string();
        let login = record.get(1).unwrap_or("").to_string();
        let password = record.get(2).unwrap_or("").to_string();

        if name.is_empty() || login.is_empty() {
            continue;
        }

        let mut entry = Entry::new(name, login, password);

        if let Some(url) = record.get(3) {
            if !url.is_empty() {
                entry.url = Some(url.to_string());
            }
        }

        if let Some(notes) = record.get(4) {
            if !notes.is_empty() {
                entry.notes = Some(notes.to_string());
            }
        }

        if let Some(tags) = record.get(5) {
            if !tags.is_empty() {
                entry.tags = tags.split(';').map(|s| s.trim().to_string()).collect();
            }
        }

        entries.push(entry);
    }

    Ok(entries)
}