#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod crypto;
mod models;
mod password_generator;
mod storage;

use app::PasswordManagerApp;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Gestionnaire de Mots de Passe",
        native_options,
        Box::new(|cc| Ok(Box::new(PasswordManagerApp::new(cc)))),
    )
}