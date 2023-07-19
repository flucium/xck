use std::{
    self,
    fs,
    // io::{self, stderr, stdout, Read, Write},
    io::{self, Read},
    path::{Path, PathBuf},
};

use clap::{
    Args as ClapArgs,
    Parser as ClapParser,
    Subcommand as ClapSubcommand,
    // ValueEnum as ClapValueEnum,
};

const NAME: &str = "XCK";

const VERSION: &str = "0.0.1";

const AUTHOR: &str = "flucium <flucium@flucium.net>";

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
    Hex(HexArgs),

    /// base64 is...    
    #[command(name = "base64")]
    Base64(Base64Args),

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
}

#[derive(ClapArgs)]
struct HexArgs {
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
}

#[derive(ClapArgs)]
struct Base64Args {
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
        Subcommand::Hex(args) => todo!(),
        Subcommand::Base64(args) => todo!(),
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

#[derive(Debug)]
enum ArgType {
    Cli(String),
    File(PathBuf),
}

// file:testfile.txt -> file
// cli:hello_world -> cli
// hello_world -> cli
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

fn main() {
    app()
}
