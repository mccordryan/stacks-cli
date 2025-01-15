use std::process::Command;
use std::fs;
use anyhow::{Result, Context};
use clap::{Parser, Subcommand};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate new RSA key pair
    Genrsa {
        /// Name of the key (will create KEYNAME.pri and KEYNAME.pub)
        keyname: String,
        
        /// Key size in bits
        #[arg(short, long, default_value_t = 2048)]
        bits: u32,
    },
    /// Get RSA key in SDK format
    Getrsa {
        /// Name of the key to read
        keyname: String,
        
        /// Get public key
        #[arg(short = 'b', long)]
        pub_: bool,
        
        /// Get private key
        #[arg(short, long)]
        pri: bool,
    },
}

fn generate_keys(keyname: &str, bits: u32) -> Result<()> {
    // Generate temporary PEM file
    let temp_pem = format!("{}.pem", keyname);
    
    // Generate private key
    Command::new("openssl")
        .args(["genrsa", "-out", &temp_pem, &bits.to_string()])
        .output()
        .context("Failed to generate RSA key")?;

    // Extract private exponent (d)
    let private_exp = String::from_utf8(
        Command::new("openssl")
            .args(["rsa", "-in", &temp_pem, "-text", "-noout"])
            .output()
            .context("Failed to extract private exponent")?
            .stdout
    )?;
    
    // Extract and format private exponent
    let d = private_exp
        .lines()
        .skip_while(|line| !line.contains("privateExponent:"))
        .nth(1)
        .context("Could not find private exponent")?
        .replace(" ", "")
        .replace(":", "");

    // Extract modulus (n)
    let modulus = String::from_utf8(
        Command::new("openssl")
            .args(["rsa", "-in", &temp_pem, "-modulus", "-noout"])
            .output()
            .context("Failed to extract modulus")?
            .stdout
    )?;
    
    let n = modulus
        .trim()
        .strip_prefix("Modulus=")
        .context("Invalid modulus format")?;

    // Format keys with Base64 encoding
    let private_key = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
        BASE64.encode(format!("{},{}", d.to_lowercase(), n.to_lowercase()).as_bytes())
    );
    
    let public_key = format!(
        "-----BEGIN RSA PUBLIC KEY-----\n{}\n-----END RSA PUBLIC KEY-----",
        BASE64.encode(format!("10001,{}", n.to_lowercase()).as_bytes())
    );

    // Write keys to files
    fs::write(format!("{}.pri", keyname), private_key)?;
    fs::write(format!("{}.pub", keyname), public_key)?;
    
    // Clean up temporary PEM file
    fs::remove_file(temp_pem)?;
    
    println!("Generated RSA key pair:");
    println!("  Private key: {}.pri", keyname);
    println!("  Public key: {}.pub", keyname);
    
    Ok(())
}

fn get_key(keyname: &str, pub_: bool, pri: bool) -> Result<()> {
    if pub_ {
        match fs::read_to_string(format!("{}.pub", keyname)) {
            Ok(key) => println!("{}", key),
            Err(_) => println!("Public key not found: {}.pub", keyname),
        }
    }
    
    if pri {
        match fs::read_to_string(format!("{}.pri", keyname)) {
            Ok(key) => println!("{}", key),
            Err(_) => println!("Private key not found: {}.pri", keyname),
        }
    }
    
    if !pub_ && !pri {
        println!("Please specify either --pub or --pri flag");
    }
    
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Genrsa { keyname, bits } => {
            generate_keys(keyname, *bits)?;
        }
        Commands::Getrsa { keyname, pub_, pri } => {
            get_key(keyname, *pub_, *pri)?;
        }
    }
    Ok(())
}