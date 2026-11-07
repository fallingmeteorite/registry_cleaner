#![windows_subsystem = "windows"]

mod app;
mod registry_delete;
mod registry_search;
mod ui;

use app::CleanerApp;
use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([920.0, 640.0])
            .with_min_inner_size([720.0, 460.0])
            .with_title("简易注册表清理工具"),
        ..Default::default()
    };

    eframe::run_native(
        "registry-cleaner",
        options,
        Box::new(|cc| {
            ui::setup_fonts(&cc.egui_ctx);
            ui::setup_style(&cc.egui_ctx);
            Ok(Box::new(CleanerApp::new()))
        }),
    )
}