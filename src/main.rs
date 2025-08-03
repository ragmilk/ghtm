use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(name = "ghtm")]
#[command(about = "GitHub Token Manager - Securely manage GitHub authentication tokens")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add,
    Load { name: Option<String> },
    List,
    Remove { name: String },
    Rm { name: String },
}

#[derive(Serialize, Deserialize, Clone)]
struct TokenEntry {
    name: String,
    encrypted_token: String,
    nonce: String,
    expires: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
struct Config {
    master_password_hash: String,
    salt: String,
    tokens: Vec<TokenEntry>,
    last_used_token: Option<String>,
}

struct Ghtm {
    config_path: PathBuf,
}

impl Ghtm {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let proj_dirs = ProjectDirs::from("com", "ghtm", "ghtm").ok_or("Could not determine config directory")?;

        let config_dir = proj_dirs.config_dir();
        fs::create_dir_all(config_dir)?;

        let config_path = config_dir.join("config.json");

        Ok(Self { config_path })
    }

    fn load_config(&self) -> Result<Config, Box<dyn std::error::Error>> {
        if !self.config_path.exists() {
            return Err("Configuration not found. Run 'ghtm init' first.".into());
        }

        let content = fs::read_to_string(&self.config_path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    fn save_config(&self, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_json::to_string_pretty(config)?;
        fs::write(&self.config_path, content)?;
        Ok(())
    }

    fn derive_key(&self, password: &str, salt: &str) -> Key<Aes256Gcm> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt.as_bytes());
        let result = hasher.finalize();
        *Key::<Aes256Gcm>::from_slice(&result)
    }

    fn encrypt_token(&self, token: &str, password: &str, salt: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
        let key = self.derive_key(password, salt);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let encrypted = cipher.encrypt(&nonce, token.as_bytes()).map_err(|e| format!("Encryption failed: {:?}", e))?;

        let encrypted_b64 = general_purpose::STANDARD.encode(&encrypted);
        let nonce_b64 = general_purpose::STANDARD.encode(&nonce);

        Ok((encrypted_b64, nonce_b64))
    }

    fn decrypt_token(&self, encrypted_token: &str, nonce: &str, password: &str, salt: &str) -> Result<String, Box<dyn std::error::Error>> {
        let key = self.derive_key(password, salt);
        let cipher = Aes256Gcm::new(&key);

        let encrypted = general_purpose::STANDARD.decode(encrypted_token)?;
        let nonce_bytes = general_purpose::STANDARD.decode(nonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypted = cipher.decrypt(nonce, encrypted.as_ref()).map_err(|e| format!("Decryption failed: {:?}", e))?;
        Ok(String::from_utf8(decrypted)?)
    }

    fn hash_password(&self, password: &str, salt: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt.as_bytes());
        let result = hasher.finalize();
        general_purpose::STANDARD.encode(&result)
    }

    fn verify_password(&self, password: &str, config: &Config) -> bool {
        let hash = self.hash_password(password, &config.salt);
        hash == config.master_password_hash
    }

    fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.config_path.exists() {
            println!("Configuration already exists. Overwrite? [y/n]");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                return Ok(());
            }
        }

        println!("Set master password:");
        let password = rpassword::read_password()?;

        println!("Confirm master password:");
        let confirm = rpassword::read_password()?;

        if password != confirm {
            return Err("Passwords do not match".into());
        }

        let salt = general_purpose::STANDARD.encode(&rand::random::<[u8; 32]>());
        let password_hash = self.hash_password(&password, &salt);

        let config = Config {
            master_password_hash: password_hash,
            salt,
            tokens: Vec::new(),
            last_used_token: None,
        };

        self.save_config(&config)?;
        println!("Master password set successfully.");

        Ok(())
    }

    fn add(&self) -> Result<(), Box<dyn std::error::Error>> {
        let expired_tokens = self.cleanup_expired_tokens()?;
        if !expired_tokens.is_empty() {
            println!("Removed {} expired token(s): {}", expired_tokens.len(), expired_tokens.join(", "));
        }

        let mut config = self.load_config()?;

        println!("Enter token name:");
        let mut name = String::new();
        std::io::stdin().read_line(&mut name)?;
        let name = name.trim().to_string();

        if name.is_empty() {
            return Err("Token name cannot be empty".into());
        }

        println!("Enter expiration date (YYYY-MM-DD):");
        let mut expires = String::new();
        std::io::stdin().read_line(&mut expires)?;
        let expires = expires.trim().to_string();

        println!("Enter master password:");
        let password = rpassword::read_password()?;

        if !self.verify_password(&password, &config) {
            return Err("Invalid master password".into());
        }

        println!("Enter GitHub personal access token:");
        let token = rpassword::read_password()?;

        let expires_dt = chrono::NaiveDate::parse_from_str(&expires, "%Y-%m-%d")?
            .and_hms_opt(23, 59, 59)
            .ok_or("Invalid date format")?
            .and_utc();

        let (encrypted_token, nonce) = self.encrypt_token(&token, &password, &config.salt)?;

        config.tokens.retain(|entry| entry.name != name);

        let token_entry = TokenEntry {
            name: name.clone(),
            encrypted_token,
            nonce,
            expires: expires_dt,
        };

        config.tokens.push(token_entry);
        self.save_config(&config)?;

        println!("Token '{}' added successfully.", name);
        Ok(())
    }

    fn load(&self, token_name: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        let expired_tokens = self.cleanup_expired_tokens()?;
        if !expired_tokens.is_empty() {
            println!("Removed {} expired tokens: {}", expired_tokens.len(), expired_tokens.join(", "));
        }

        let config = self.load_config()?;

        let selected_name = match token_name {
            Some(name) => name,
            None => {
                if config.tokens.is_empty() {
                    return Err("No tokens stored. Use 'ghtm add' to add a token first.".into());
                }

                if let Some(ref last_token) = config.last_used_token {
                    if config.tokens.iter().any(|t| &t.name == last_token && t.expires >= Utc::now()) {
                        println!("Using last used token: {}", last_token);
                        last_token.clone()
                    } else {
                        self.interactive_token_selection(&config)?
                    }
                } else {
                    self.interactive_token_selection(&config)?
                }
            }
        };

        let token_entry = config
            .tokens
            .iter()
            .find(|entry| entry.name == selected_name)
            .ok_or(format!("Token '{}' not found", selected_name))?;

        if token_entry.expires < Utc::now() {
            return Err(format!("Token '{}' has expired", selected_name).into());
        }

        println!("Enter master password:");
        let password = rpassword::read_password()?;

        if !self.verify_password(&password, &config) {
            return Err("Invalid master password".into());
        }

        let decrypted_token = self.decrypt_token(&token_entry.encrypted_token, &token_entry.nonce, &password, &config.salt)?;

        let mut updated_config = config;
        updated_config.last_used_token = Some(selected_name.clone());
        self.save_config(&updated_config)?;

        let cache_timeout = 43200;
        Command::new("git")
            .args(&["config", "--global", "credential.helper", &format!("cache --timeout={}", cache_timeout)])
            .output()?;

        let credential_input = format!("protocol=https\nhost=github.com\nusername=token\npassword={}\n\n", decrypted_token);

        let mut child = Command::new("git")
            .args(&["credential", "approve"])
            .stdin(std::process::Stdio::piped())
            .spawn()?;

        if let Some(stdin) = child.stdin.as_mut() {
            use std::io::Write;
            stdin.write_all(credential_input.as_bytes())?;
        }

        child.wait()?;

        println!("Loaded token '{}'.", selected_name);
        println!("Credentials will be cached for {} hours.", cache_timeout / 3600);

        Ok(())
    }

    fn cleanup_expired_tokens(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut config = self.load_config()?;
        let now = Utc::now();

        let initial_count = config.tokens.len();
        let expired_tokens: Vec<String> = config
            .tokens
            .iter()
            .filter(|token| token.expires < now)
            .map(|token| token.name.clone())
            .collect();

        config.tokens.retain(|token| token.expires >= now);

        if config.tokens.len() != initial_count {
            self.save_config(&config)?;
        }

        Ok(expired_tokens)
    }

    fn interactive_token_selection(&self, config: &Config) -> Result<String, Box<dyn std::error::Error>> {
        println!("Available tokens:");
        for (i, entry) in config.tokens.iter().enumerate() {
            let status = if entry.expires < Utc::now() { " (EXPIRED)" } else { "" };
            println!("  {}: {}{}", i + 1, entry.name, status);
        }

        println!("Enter token number or name:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if let Ok(index) = input.parse::<usize>() {
            if index > 0 && index <= config.tokens.len() {
                Ok(config.tokens[index - 1].name.clone())
            } else {
                Err("Invalid token number".into())
            }
        } else {
            Ok(input.to_string())
        }
    }

    fn list(&self) -> Result<(), Box<dyn std::error::Error>> {
        let expired_tokens = self.cleanup_expired_tokens()?;
        if !expired_tokens.is_empty() {
            println!("Removed {} expired token(s): {}", expired_tokens.len(), expired_tokens.join(", "));
        }

        let config = self.load_config()?;

        if config.tokens.is_empty() {
            println!("No tokens stored.");
            return Ok(());
        }

        println!("Stored tokens:");
        for entry in &config.tokens {
            let status = if entry.expires < Utc::now() { "EXPIRED" } else { "Active" };

            println!("  {} - {} (expires: {})", entry.name, status, entry.expires.format("%Y-%m-%d"));
        }

        Ok(())
    }

    fn remove(&self, name: String) -> Result<(), Box<dyn std::error::Error>> {
        let expired_tokens = self.cleanup_expired_tokens()?;
        if !expired_tokens.is_empty() {
            println!("Removed {} expired token(s): {}", expired_tokens.len(), expired_tokens.join(", "));
        }

        let mut config = self.load_config()?;

        println!("Enter master password:");
        let password = rpassword::read_password()?;

        if !self.verify_password(&password, &config) {
            return Err("Invalid master password".into());
        }

        let initial_count = config.tokens.len();
        config.tokens.retain(|token| token.name != name);

        if config.tokens.len() == initial_count {
            return Err(format!("Token '{}' not found", name).into());
        }

        if let Some(ref last_token) = config.last_used_token {
            if last_token == &name {
                config.last_used_token = None;
            }
        }

        self.save_config(&config)?;
        println!("Token '{}' removed successfully.", name);

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let manager = Ghtm::new()?;

    match args.command {
        Commands::Init => manager.init(),
        Commands::Add => manager.add(),
        Commands::Load { name } => manager.load(name),
        Commands::List => manager.list(),
        Commands::Remove { name } => manager.remove(name),
        Commands::Rm { name } => manager.remove(name),
    }
}
