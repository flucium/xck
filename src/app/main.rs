use std::{
    self,
    fs,
    hash,
    // io::{self, stderr, stdout, Read, Write},
    io::{self, Read},
    path::{Path, PathBuf},
};

use clap::{
    Args as ClapArgs, Parser as ClapParser, Subcommand as ClapSubcommand,
    // ValueEnum as ClapValueEnum,
};

const NAME: &str = "XCK";

const VERSION: &str = "0.0.1";

const AUTHOR: &str = "flucium";

const ABOUT: &str = "";

#[derive(ClapParser)]
#[command(name = NAME, version = VERSION, author = AUTHOR, about = ABOUT)]
#[clap(disable_help_subcommand(true))]
struct Command {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(ClapSubcommand)]
enum Subcommand {
    /// hex is...
    #[command(name = "hex")]
    Hex {
        /// encode is...
        #[arg(long = "encode", short = 'e')]
        #[clap(alias = "enc")]
        encode: bool,

        /// decode is...
        #[arg(long = "decode", short = 'd')]
        #[clap(alias = "dec")]
        decode: bool,

        /// message is...
        #[arg(long = "message", short = 'm')]
        #[clap(alias = "msg")]
        message: String,
    },

    // base16 is...
    // #[command(name = "base16")]
    // Base16 {
    //     /// encode is...
    //     #[arg(long = "encode", short = 'e')]
    //     #[clap(alias = "enc")]
    //     encode: bool,

    //     /// decode is...
    //     #[arg(long = "decode", short = 'd')]
    //     #[clap(alias = "dec")]
    //     decode: bool,

    //     /// message is...
    //     #[arg(long = "message", short = 'm')]
    //     #[clap(alias = "msg")]
    //     message: String,
    // },

    // base32 is...
    // #[command(name = "base32")]
    // Base32 {
    //     /// encode is...
    //     #[arg(long = "encode", short = 'e')]
    //     #[clap(alias = "enc")]
    //     encode: bool,

    //     /// decode is...
    //     #[arg(long = "decode", short = 'd')]
    //     #[clap(alias = "dec")]
    //     decode: bool,

    //     /// message is...
    //     #[arg(long = "message", short = 'm')]
    //     #[clap(alias = "msg")]
    //     message: String,
    // },

    /// base64 is...
    #[command(name = "base64")]
    Base64 {
        /// encode is...
        #[arg(long = "encode", short = 'e')]
        #[clap(alias = "enc")]
        encode: bool,

        /// decode is...
        #[arg(long = "decode", short = 'd')]
        #[clap(alias = "dec")]
        decode: bool,

        /// message is...
        #[arg(long = "message", short = 'm')]
        #[clap(alias = "msg")]
        message: String,
    },

    /// deflate is...
    #[command(name = "deflate")]
    Deflate {
        /// encode is...
        #[arg(long = "encode", short = 'e')]
        #[clap(alias = "enc")]
        encode: bool,

        /// decode is...
        #[arg(long = "decode", short = 'd')]
        #[clap(alias = "dec")]
        decode: bool,

        /// level is...
        #[arg(long = "level", short = 'l', default_value = "6")]
        #[clap(alias = "lv")]
        level: usize,

        /// message is...
        #[arg(long = "message", short = 'm')]
        #[clap(alias = "msg")]
        message: String,
    },

    /// zlib is...  
    #[command(name = "zlib")]
    Zlib {
        /// encode is...
        #[arg(long = "encode", short = 'e')]
        #[clap(alias = "enc")]
        encode: bool,

        /// decode is...
        #[arg(long = "decode", short = 'd')]
        #[clap(alias = "dec")]
        decode: bool,

        /// level is...
        #[arg(long = "level", short = 'l', default_value = "6")]
        #[clap(alias = "lv")]
        level: usize,

        /// message is...
        #[arg(long = "message", short = 'm')]
        #[clap(alias = "msg")]
        message: String,
    },

    /// gz is...
    #[command(name = "gz")]
    Gz {
        /// encode is...
        #[arg(long = "encode", short = 'e')]
        #[clap(alias = "enc")]
        encode: bool,

        /// decode is...
        #[arg(long = "decode", short = 'd')]
        #[clap(alias = "dec")]
        decode: bool,

        /// level is...
        #[arg(long = "level", short = 'l', default_value = "6")]
        #[clap(alias = "lv")]
        level: usize,

        /// message is...
        #[arg(long = "message", short = 'm')]
        #[clap(alias = "msg")]
        message: String,
    },

    /// random is...
    #[command(name = "random")]
    #[clap(alias = "rand")]
    Random(RandomArgs),

    /// chacha20poly1305 is...
    #[command(name = "chacha20poly1305")]
    ChaCha20Poly1305(ChaCha20Poly1305Args),

    /// xchacha20poly1305 is...
    #[command(name = "xchacha20poly1305")]
    XChaCha20Poly1305(XChaCha20Poly1305Args),
    //
    //
    //
    // ToDo
    // #[command(name = "aes-128-gcm")]
    // Aes128Gcm

    // #[command(name = "aes-192-gcm")]
    // Aes192Gcm

    // #[command(name = "aes-256-gcm")]
    // Aes256Gcm

    // #[command(name = "argon2")]
    // Argon2 (Variant i/d/id)

    // #[command(name = "pbkdf2")]
    // Pbkdf2

    // #[command(name = "blake3")]
    // #[clap(alias = "b3")]
    // Blake3 (Variant regular/kdf/xof/mac)

    // #[command(name = "sha256")]
    // #[clap(alias = "sha2")]
    // Sha256

    // #[command(name = "sha512")]
    // Sha512

    // #[command(name = "sha512-256")]
    // Sha512_256
}

#[derive(ClapArgs)]
struct ChaCha20Poly1305Args {
    /// encrypt is...
    #[arg(long = "encrypt", short = 'e')]
    #[clap(alias = "enc")]
    encrypt: bool,

    /// decrypt is...
    #[arg(long = "decrypt", short = 'd')]
    #[clap(alias = "dec")]
    decrypt: bool,

    /// key is...
    #[arg(long = "key", short = 'k')]
    key: String,

    /// aad is...
    #[arg(long = "additionaldata", short = 'a')]
    #[clap(alias = "aad")]
    additionaldata: String,

    /// message is...
    #[arg(long = "message", short = 'm')]
    #[clap(alias = "msg")]
    message: String,
}

#[derive(ClapArgs)]
struct XChaCha20Poly1305Args {
    /// encrypt is...
    #[arg(long = "encrypt", short = 'e')]
    #[clap(alias = "enc")]
    encrypt: bool,

    /// decrypt is...
    #[arg(long = "decrypt", short = 'd')]
    #[clap(alias = "dec")]
    decrypt: bool,

    /// key is...
    #[arg(long = "key", short = 'k')]
    key: String,

    /// aad is...
    #[arg(long = "additionaldata", short = 'a')]
    #[clap(alias = "aad")]
    additionaldata: String,

    /// message is...
    #[arg(long = "message", short = 'm')]
    #[clap(alias = "msg")]
    message: String,
}

#[derive(ClapArgs)]
struct RandomArgs {
    // #[arg(long = "length", short = 'l', default_value = "32")]
    // #[clap(alias = "len")]
    // length: usize,
}

fn app() {
    let command = Command::parse();
    match command.subcommand {
        Subcommand::Hex {
            encode,
            decode,
            message,
        } => todo!(),
        // Subcommand::Base16 {
        //     encode,
        //     decode,
        //     message,
        // } => todo!(),
        // Subcommand::Base32 {
        //     encode,
        //     decode,
        //     message,
        // } => todo!(),
        Subcommand::Base64 {
            encode,
            decode,
            message,
        } => todo!(),
        Subcommand::Deflate {
            encode,
            decode,
            level,
            message,
        } => todo!(),
        Subcommand::Zlib {
            encode,
            decode,
            level,
            message,
        } => todo!(),
        Subcommand::Gz {
            encode,
            decode,
            level,
            message,
        } => todo!(),
        Subcommand::Random(args) => todo!(),
        Subcommand::ChaCha20Poly1305(args) => todo!(),
        Subcommand::XChaCha20Poly1305(args) => todo!(),
    }
}

fn read_arg(string: String) -> io::Result<Vec<u8>> {
    let bytes = match arg_type_of(string) {
        ArgType::Cli(string) => string.as_bytes().to_owned(),
        ArgType::File(path) => read_file(&path)?,
    };

    Ok(bytes)
}

fn read_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;

    let mut buf = Vec::new();

    file.read_to_end(&mut buf)?;

    Ok(buf)
}

fn arg_type_of(string: String) -> ArgType {
    match string.split_once(':') {
        None => ArgType::Cli(string),
        Some((a, b)) => match a.as_ref() {
            "file" => ArgType::File(PathBuf::from(b)),
            "cli" => ArgType::Cli(b.to_string()),
            _ => ArgType::Cli(b.to_string()),
        },
    }
}

#[derive(Debug)]
enum ArgType {
    Cli(String),
    File(PathBuf),
}

fn main() {
    app()
}
