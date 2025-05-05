// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::error::Error;

use slint::SharedString;

slint::include_modules!();

fn main() -> Result<(), Box<dyn Error>> {
    let ui = AppWindow::new()?;

    ui.on_choose_file({
        let ui_handle = ui.as_weak();
        move || {
            let ui = ui_handle.unwrap();
            ui.set_file_path(SharedString::from(choose_file().unwrap()));
        }
    });

    ui.run()?;

    Ok(())
}

fn choose_file() -> Option<String> {
    if let Some(file) = rfd::FileDialog::new().pick_file() {
        Some(file.display().to_string())
    } else {
        None
    }
}
