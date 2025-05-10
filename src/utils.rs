pub mod file {
    use std::{fs::{self, File}, io::Write, path::PathBuf};
    
    pub fn read_file_content(file_path: &str) -> Vec<u8> {
        fs::read(file_path).expect("Failed to read file")
    }
    
    pub fn write_file_content(file_path: &str, data: &[u8]) {
        let mut file = File::create(file_path).expect("Failed to create file");
        file.write_all(data).expect("Failed to write data");
    }

    pub fn select_file() -> Option<PathBuf> {
        rfd::FileDialog::new().pick_file()
    }

    pub fn select_files() -> Option<Vec<PathBuf>> {
        rfd::FileDialog::new().pick_files()
    }
    
    pub fn get_path(file: &PathBuf) -> String {
        file.display()
            .to_string()
    }
}