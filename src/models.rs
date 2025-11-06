use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub name: String,
    pub login: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

impl Entry {
    pub fn new(name: String, login: String, password: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            login,
            password,
            url: None,
            notes: None,
            tags: Vec::new(),
            created_at: now,
            modified_at: now,
        }
    }

    pub fn update_modified(&mut self) {
        self.modified_at = Utc::now();
    }

    pub fn matches_search(&self, query: &str) -> bool {
        let query_lower = query.to_lowercase();
        self.name.to_lowercase().contains(&query_lower)
            || self.login.to_lowercase().contains(&query_lower)
            || self.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
            || self.url.as_ref().map_or(false, |u| u.to_lowercase().contains(&query_lower))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Vault {
    pub entries: Vec<Entry>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

impl Vault {
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            entries: Vec::new(),
            created_at: now,
            modified_at: now,
        }
    }

    pub fn add_entry(&mut self, entry: Entry) {
        self.entries.push(entry);
        self.modified_at = Utc::now();
    }

    pub fn update_entry(&mut self, id: Uuid, updated: Entry) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) {
            *entry = updated;
            entry.update_modified();
            self.modified_at = Utc::now();
        }
    }

    pub fn delete_entry(&mut self, id: Uuid) {
        self.entries.retain(|e| e.id != id);
        self.modified_at = Utc::now();
    }

    pub fn get_entry(&self, id: Uuid) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub kdf: String,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone)]
pub enum AuditAction {
    VaultCreated,
    VaultOpened,
    VaultLocked,
    EntryCreated(String),
    EntryUpdated(String),
    EntryDeleted(String),
    ExportPlaintext,
    ExportEncrypted,
    ImportCsv,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: AuditAction,
}

impl AuditEntry {
    pub fn new(action: AuditAction) -> Self {
        Self {
            timestamp: Utc::now(),
            action,
        }
    }

    pub fn description(&self) -> String {
        match &self.action {
            AuditAction::VaultCreated => "Coffre créé".to_string(),
            AuditAction::VaultOpened => "Coffre ouvert".to_string(),
            AuditAction::VaultLocked => "Coffre verrouillé".to_string(),
            AuditAction::EntryCreated(name) => format!("Entrée créée: {}", name),
            AuditAction::EntryUpdated(name) => format!("Entrée modifiée: {}", name),
            AuditAction::EntryDeleted(name) => format!("Entrée supprimée: {}", name),
            AuditAction::ExportPlaintext => "⚠️ Export en clair".to_string(),
            AuditAction::ExportEncrypted => "Export chiffré".to_string(),
            AuditAction::ImportCsv => "Import CSV".to_string(),
        }
    }
}