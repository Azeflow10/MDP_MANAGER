use crate::models::{AuditAction, AuditEntry, Entry, Vault};
use crate::password_generator::*;
use crate::storage::*;
use arboard::Clipboard;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub struct PasswordManagerApp {
    // État du coffre
    vault: Option<Vault>,
    vault_path: Option<PathBuf>,
    is_locked: bool,

    // UI État
    screen: Screen,
    master_password: String,
    new_vault_path: String,
    error_message: Option<String>,
    success_message: Option<String>,

    // Entrées
    selected_entry: Option<Uuid>,
    search_query: String,
    filtered_entries: Vec<Uuid>,

    // Modal
    show_entry_modal: bool,
    editing_entry: Option<Entry>,

    // Générateur
    show_generator: bool,
    generator_options: PasswordGeneratorOptions,
    generated_password: String,

    // Confirmations
    confirm_delete: Option<Uuid>,
    confirm_export_plain: bool,

    // Verrouillage auto
    last_activity: Instant,
    auto_lock_seconds: u64,

    // Audit
    audit_log: Vec<AuditEntry>,
    show_audit: bool,

    // Clipboard
    clipboard: Option<Clipboard>,
    clipboard_clear_time: Option<Instant>,
    clipboard_clear_delay: u64,
}

#[derive(Debug, PartialEq)]
enum Screen {
    Welcome,
    Main,
    Unlock,
}

impl Default for PasswordManagerApp {
    fn default() -> Self {
        Self {
            vault: None,
            vault_path: None,
            is_locked: false,
            screen: Screen::Welcome,
            master_password: String::new(),
            new_vault_path: String::new(),
            error_message: None,
            success_message: None,
            selected_entry: None,
            search_query: String::new(),
            filtered_entries: Vec::new(),
            show_entry_modal: false,
            editing_entry: None,
            show_generator: false,
            generator_options: PasswordGeneratorOptions::default(),
            generated_password: String::new(),
            confirm_delete: None,
            confirm_export_plain: false,
            last_activity: Instant::now(),
            auto_lock_seconds: 300,
            audit_log: Vec::new(),
            show_audit: false,
            clipboard: Clipboard::new().ok(),
            clipboard_clear_time: None,
            clipboard_clear_delay: 30,
        }
    }
}

impl PasswordManagerApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }

    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    fn check_auto_lock(&mut self) {
        if self.vault.is_some() && !self.is_locked {
            let elapsed = self.last_activity.elapsed();
            if elapsed > Duration::from_secs(self.auto_lock_seconds) {
                self.lock_vault();
            }
        }
    }

    fn check_clipboard_clear(&mut self) {
        if let Some(clear_time) = self.clipboard_clear_time {
            if Instant::now() > clear_time {
                if let Some(clipboard) = &mut self.clipboard {
                    let _ = clipboard.set_text("");
                }
                self.clipboard_clear_time = None;
            }
        }
    }

    fn add_audit(&mut self, action: AuditAction) {
        self.audit_log.push(AuditEntry::new(action));
    }

    fn create_vault(&mut self) {
        if self.master_password.len() < 8 {
            self.error_message = Some("Le mot de passe maître doit contenir au moins 8 caractères".to_string());
            return;
        }

        if self.new_vault_path.is_empty() {
            self.error_message = Some("Veuillez spécifier un chemin pour le coffre".to_string());
            return;
        }

        let path = PathBuf::from(&self.new_vault_path);
        let vault = Vault::new();

        match save_vault(&vault, &path, &self.master_password) {
            Ok(_) => {
                self.vault = Some(vault);
                self.vault_path = Some(path);
                self.screen = Screen::Main;
                self.master_password.clear();
                self.new_vault_path.clear();
                self.success_message = Some("Coffre créé avec succès!".to_string());
                self.add_audit(AuditAction::VaultCreated);
                self.update_search();
            }
            Err(e) => {
                self.error_message = Some(format!("Erreur lors de la création: {}", e));
            }
        }
    }

    fn open_vault(&mut self) {
        if self.new_vault_path.is_empty() {
            self.error_message = Some("Veuillez spécifier un chemin de coffre".to_string());
            return;
        }

        let path = PathBuf::from(&self.new_vault_path);

        match load_vault(&path, &self.master_password) {
            Ok(vault) => {
                self.vault = Some(vault);
                self.vault_path = Some(path);
                self.screen = Screen::Main;
                self.master_password.clear();
                self.new_vault_path.clear();
                self.success_message = Some("Coffre ouvert avec succès!".to_string());
                self.add_audit(AuditAction::VaultOpened);
                self.update_search();
            }
            Err(e) => {
                self.error_message = Some(format!("Erreur: {}", e));
            }
        }
    }

    fn lock_vault(&mut self) {
        self.is_locked = true;
        self.screen = Screen::Unlock;
        self.master_password.clear();
        self.selected_entry = None;
        self.add_audit(AuditAction::VaultLocked);
    }

    fn unlock_vault(&mut self) {
        if let Some(path) = &self.vault_path.clone() {
            match load_vault(path, &self.master_password) {
                Ok(vault) => {
                    self.vault = Some(vault);
                    self.is_locked = false;
                    self.screen = Screen::Main;
                    self.master_password.clear();
                    self.success_message = Some("Coffre déverrouillé".to_string());
                    self.update_activity();
                    self.update_search();
                }
                Err(e) => {
                    self.error_message = Some(format!("Mot de passe incorrect: {}", e));
                }
            }
        }
    }

    fn update_search(&mut self) {
        if let Some(vault) = &self.vault {
            self.filtered_entries = vault
                .entries
                .iter()
                .filter(|e| {
                    if self.search_query.is_empty() {
                        true
                    } else {
                        e.matches_search(&self.search_query)
                    }
                })
                .map(|e| e.id)
                .collect();
        }
    }

    fn copy_to_clipboard(&mut self, text: &str) {
        if let Some(clipboard) = &mut self.clipboard {
            if clipboard.set_text(text).is_ok() {
                self.success_message = Some(format!(
                    "Copié! Sera effacé dans {} secondes",
                    self.clipboard_clear_delay
                ));
                self.clipboard_clear_time = Some(Instant::now() + Duration::from_secs(self.clipboard_clear_delay));
            }
        }
    }

    fn show_welcome(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(50.0);
            ui.heading("🔐 Gestionnaire de Mots de Passe");
            ui.add_space(30.0);

            ui.group(|ui| {
                ui.set_width(400.0);
                ui.label("Chemin du coffre:");
                ui.text_edit_singleline(&mut self.new_vault_path);

                ui.add_space(10.0);
                ui.label("Mot de passe maître:");
                ui.add(egui::TextEdit::singleline(&mut self.master_password).password(true));

                ui.add_space(20.0);

                ui.horizontal(|ui| {
                    if ui.button("📁 Ouvrir un coffre").clicked() {
                        self.open_vault();
                        self.update_activity();
                    }

                    if ui.button("➕ Créer un coffre").clicked() {
                        self.create_vault();
                        self.update_activity();
                    }
                });
            });

            ui.add_space(20.0);
            ui.label("⚠️ Application locale - Aucune donnée n'est envoyée sur internet");
        });
    }

    fn show_unlock(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(100.0);
            ui.heading("🔒 Coffre verrouillé");
            ui.add_space(30.0);

            ui.group(|ui| {
                ui.set_width(300.0);
                ui.label("Mot de passe maître:");
                let response = ui.add(egui::TextEdit::singleline(&mut self.master_password).password(true));

                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.unlock_vault();
                }

                ui.add_space(10.0);

                if ui.button("🔓 Déverrouiller").clicked() {
                    self.unlock_vault();
                }
            });
        });
    }

    fn show_main(&mut self, _ui: &mut egui::Ui, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🔐 Gestionnaire de Mots de Passe");
                ui.separator();

                if ui.button("🔒 Verrouiller").clicked() {
                    self.lock_vault();
                }

                if ui.button("📊 Audit").clicked() {
                    self.show_audit = !self.show_audit;
                    self.update_activity();
                }

                ui.separator();
                ui.label(format!("⏱️ Verrouillage auto: {}s", self.auto_lock_seconds));
            });
        });

        egui::SidePanel::left("entries_panel").min_width(300.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("🔍");
                let response = ui.add(egui::TextEdit::singleline(&mut self.search_query).hint_text("Rechercher..."));
                if response.changed() {
                    self.update_search();
                    self.update_activity();
                }
            });

            ui.separator();

            if ui.button("➕ Nouvelle entrée").clicked() {
                self.editing_entry = Some(Entry::new(String::new(), String::new(), String::new()));
                self.show_entry_modal = true;
                self.update_activity();
            }

            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
                let filtered_ids = self.filtered_entries.clone();
                for entry_id in filtered_ids {
                    if let Some(vault) = &self.vault {
                        if let Some(entry) = vault.get_entry(entry_id) {
                            let is_selected = self.selected_entry == Some(entry_id);
                            let response = ui.selectable_label(is_selected, &entry.name);

                            if response.clicked() {
                                self.selected_entry = Some(entry_id);
                                self.update_activity();
                            }
                        }
                    }
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(selected_id) = self.selected_entry {
                if let Some(vault) = &self.vault {
                    if let Some(entry) = vault.get_entry(selected_id) {
                        let entry_clone = entry.clone();
                        self.show_entry_details(ui, &entry_clone);
                    }
                }
            } else {
                ui.vertical_centered(|ui| {
                    ui.add_space(100.0);
                    ui.heading("Sélectionnez une entrée");
                });
            }
        });

        if self.show_entry_modal {
            self.show_entry_editor(ctx);
        }

        if self.show_generator {
            self.show_password_generator(ctx);
        }

        if self.confirm_delete.is_some() {
            self.show_delete_confirmation(ctx);
        }

        if self.show_audit {
            self.show_audit_window(ctx);
        }
    }

    fn show_entry_details(&mut self, ui: &mut egui::Ui, entry: &Entry) {
        ui.heading(&entry.name);
        ui.separator();

        ui.horizontal(|ui| {
            if ui.button("✏️ Modifier").clicked() {
                self.editing_entry = Some(entry.clone());
                self.show_entry_modal = true;
                self.update_activity();
            }

            if ui.button("🗑️ Supprimer").clicked() {
                self.confirm_delete = Some(entry.id);
                self.update_activity();
            }
        });

        ui.add_space(20.0);

        ui.group(|ui| {
            ui.label("Identifiant:");
            ui.horizontal(|ui| {
                ui.label(&entry.login);
                if ui.button("📋").clicked() {
                    let login = entry.login.clone();
                    self.copy_to_clipboard(&login);
                    self.update_activity();
                }
            });
        });

        ui.add_space(10.0);

        ui.group(|ui| {
            ui.label("Mot de passe:");
            ui.horizontal(|ui| {
                ui.label("••••••••");
                if ui.button("📋 Copier").clicked() {
                    let password = entry.password.clone();
                    self.copy_to_clipboard(&password);
                    self.update_activity();
                }
            });
        });

        if let Some(url) = &entry.url {
            ui.add_space(10.0);
            ui.group(|ui| {
                ui.label("URL:");
                ui.hyperlink(url);
            });
        }

        if let Some(notes) = &entry.notes {
            ui.add_space(10.0);
            ui.group(|ui| {
                ui.label("Notes:");
                ui.label(notes);
            });
        }

        if !entry.tags.is_empty() {
            ui.add_space(10.0);
            ui.group(|ui| {
                ui.label("Tags:");
                ui.horizontal_wrapped(|ui| {
                    for tag in &entry.tags {
                        ui.label(format!("🏷️ {}", tag));
                    }
                });
            });
        }

        ui.add_space(10.0);
        ui.label(format!("Créé: {}", entry.created_at.format("%Y-%m-%d %H:%M")));
        ui.label(format!("Modifié: {}", entry.modified_at.format("%Y-%m-%d %H:%M")));
    }

    fn show_entry_editor(&mut self, ctx: &egui::Context) {
        let mut open = true;
        let mut should_close = false;
        let mut should_save = false;
        let mut error_msg = None;

        egui::Window::new("Éditer l'entrée")
            .open(&mut open)
            .collapsible(false)
            .show(ctx, |ui| {
                if let Some(entry) = &mut self.editing_entry {
                    ui.label("Nom du service:");
                    ui.text_edit_singleline(&mut entry.name);

                    ui.add_space(10.0);
                    ui.label("Identifiant / Login:");
                    ui.text_edit_singleline(&mut entry.login);

                    ui.add_space(10.0);
                    ui.label("Mot de passe:");
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut entry.password);
                        if ui.button("🎲 Générer").clicked() {
                            self.show_generator = true;
                        }
                    });

                    ui.add_space(10.0);
                    ui.label("URL (optionnel):");
                    let mut url = entry.url.clone().unwrap_or_default();
                    ui.text_edit_singleline(&mut url);
                    entry.url = if url.is_empty() { None } else { Some(url) };

                    ui.add_space(10.0);
                    ui.label("Notes (optionnel):");
                    let mut notes = entry.notes.clone().unwrap_or_default();
                    ui.text_edit_multiline(&mut notes);
                    entry.notes = if notes.is_empty() { None } else { Some(notes) };

                    ui.add_space(20.0);

                    ui.horizontal(|ui| {
                        if ui.button("💾 Sauvegarder").clicked() {
                            if entry.name.is_empty() || entry.login.is_empty() || entry.password.is_empty() {
                                error_msg = Some("Nom, login et mot de passe requis".to_string());
                            } else {
                                should_save = true;
                                should_close = true;
                            }
                        }

                        if ui.button("❌ Annuler").clicked() {
                            should_close = true;
                        }
                    });
                }
            });

        if !open {
            should_close = true;
        }

        if let Some(msg) = error_msg {
            self.error_message = Some(msg);
        }

        if should_save {
            if let Some(entry) = &self.editing_entry {
                let entry_clone = entry.clone();
                let entry_id = entry.id;
                let entry_name = entry.name.clone();
                
                if let Some(vault) = &mut self.vault {
                    let is_existing = vault.get_entry(entry_id).is_some();
                    
                    let action = if is_existing {
                        AuditAction::EntryUpdated(entry_name.clone())
                    } else {
                        AuditAction::EntryCreated(entry_name.clone())
                    };

                    vault.update_entry(entry_id, entry_clone.clone());
                    if !vault.entries.iter().any(|e| e.id == entry_clone.id) {
                        vault.add_entry(entry_clone);
                    }

                    self.add_audit(action);
                    self.update_search();
                    self.success_message = Some("Entrée sauvegardée".to_string());
                    self.update_activity();
                }
            }
        }

        if should_close {
            self.show_entry_modal = false;
            self.editing_entry = None;
        }
    }

    fn show_password_generator(&mut self, ctx: &egui::Context) {
        let mut open = true;

        egui::Window::new("Générateur de mot de passe")
            .open(&mut open)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label("Longueur:");
                ui.add(egui::Slider::new(&mut self.generator_options.length, 4..=64));

                ui.checkbox(&mut self.generator_options.include_uppercase, "Majuscules (A-Z)");
                ui.checkbox(&mut self.generator_options.include_lowercase, "Minuscules (a-z)");
                ui.checkbox(&mut self.generator_options.include_numbers, "Chiffres (0-9)");
                ui.checkbox(&mut self.generator_options.include_symbols, "Symboles (!@#$...)");
                ui.checkbox(&mut self.generator_options.avoid_ambiguous, "Éviter caractères ambigus (il1Lo0O)");

                ui.add_space(10.0);

                if ui.button("🎲 Générer").clicked() {
                    match generate_password(&self.generator_options) {
                        Ok(pwd) => {
                            self.generated_password = pwd;
                            self.update_activity();
                        }
                        Err(e) => {
                            self.error_message = Some(e);
                        }
                    }
                }

                if !self.generated_password.is_empty() {
                    ui.add_space(10.0);
                    ui.label("Mot de passe généré:");
                    
                    let pwd_clone = self.generated_password.clone();
                    ui.code(&pwd_clone);

                    if ui.button("📋 Copier").clicked() {
                        let pwd = self.generated_password.clone();
                        self.copy_to_clipboard(&pwd);
                        self.update_activity();
                    }

                    if ui.button("✓ Utiliser").clicked() {
                        if let Some(entry) = &mut self.editing_entry {
                            entry.password = self.generated_password.clone();
                        }
                        self.show_generator = false;
                        self.update_activity();
                    }

                    let strength = estimate_strength(&self.generated_password);
                    ui.horizontal(|ui| {
                        ui.label("Force:");
                        ui.colored_label(strength.color(), strength.label());
                    });
                }
            });

        if !open {
            self.show_generator = false;
        }
    }

    fn show_delete_confirmation(&mut self, ctx: &egui::Context) {
        let mut open = true;

        egui::Window::new("⚠️ Confirmation")
            .open(&mut open)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label("Voulez-vous vraiment supprimer cette entrée ?");
                ui.label("Cette action est irréversible.");

                ui.add_space(20.0);

                if ui.button("🗑️ Supprimer").clicked() {
                    if let Some(id) = self.confirm_delete {
                        if let Some(vault) = &mut self.vault {
                            if let Some(entry) = vault.get_entry(id) {
                                let name = entry.name.clone();
                                vault.delete_entry(id);
                                self.add_audit(AuditAction::EntryDeleted(name));
                                self.selected_entry = None;
                                self.update_search();
                                self.success_message = Some("Entrée supprimée".to_string());
                            }
                        }
                    }
                    self.confirm_delete = None;
                    self.update_activity();
                }

                if ui.button("❌ Annuler").clicked() {
                    self.confirm_delete = None;
                    self.update_activity();
                }
            });

        if !open {
            self.confirm_delete = None;
        }
    }

    fn show_audit_window(&mut self, ctx: &egui::Context) {
        let mut open = true;

        egui::Window::new("📊 Journal d'audit")
            .open(&mut open)
            .collapsible(false)
            .default_width(500.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for entry in self.audit_log.iter().rev() {
                        ui.horizontal(|ui| {
                            ui.label(entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string());
                            ui.separator();
                            ui.label(entry.description());
                        });
                    }
                });
            });

        if !open {
            self.show_audit = false;
        }
    }
}

impl eframe::App for PasswordManagerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.check_auto_lock();
        self.check_clipboard_clear();

        if let Some(msg) = &self.error_message.clone() {
            egui::Window::new("❌ Erreur")
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label(msg);
                    if ui.button("OK").clicked() {
                        self.error_message = None;
                    }
                });
        }

        if let Some(msg) = &self.success_message.clone() {
            egui::Window::new("✓ Succès")
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label(msg);
                    if ui.button("OK").clicked() {
                        self.success_message = None;
                    }
                });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.screen {
                Screen::Welcome => self.show_welcome(ui),
                Screen::Unlock => self.show_unlock(ui),
                Screen::Main => {
                    self.show_main(ui, ctx);
                }
            }
        });

        ctx.request_repaint_after(Duration::from_secs(1));
    }
}