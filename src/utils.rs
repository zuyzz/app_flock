pub mod file {
    use std::{error::Error, fs::{self, File}, io::Write, path::{Path, PathBuf}};

    use tempfile::NamedTempFile;
    
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

    pub fn get_file_extension(path: &str) -> Option<String> {
        Path::new(path).extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_string())
    }

    
    pub fn open_temp_file(data: &[u8], extension: &str) -> Result<(), Box<dyn Error>> {
        let suffix = format!(".{extension}");
        let mut temp_file = NamedTempFile::with_suffix(suffix)?;
        temp_file.write_all(data)?;

        let temp_path = temp_file
            .into_temp_path()
            .keep()?;

        opener::open(&temp_path)?;
        // std::fs::remove_file(&temp_path)?;

        Ok(())
    }
}