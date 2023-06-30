use std::{
    self, fs,
    io::{self, stderr, stdout, Read, Write},
    path::{Path, PathBuf},
    process::exit,
};

use clap::{
    Args as ClapArgs, Parser as ClapParser, Subcommand as ClapSubcommand,
    ValueEnum as ClapValueEnum,
};

use xck::symmetric;

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
    #[command(name = "encode")]
    Encode {
        /// format is...
        #[arg(long = "format", short = 'f', default_value = "bytes")]
        #[clap(alias = "fmt")]
        format: Format,

        /// message is...
        #[arg(long = "message", short = 'm')]
        #[clap(alias = "msg")]
        message: String,
    },

    #[command(name = "decode")]
    Decode {
        /// format is...
        #[arg(long = "format", short = 'f', default_value = "bytes")]
        #[clap(alias = "fmt")]
        format: Format,

        /// message is...
        #[arg(long = "message", short = 'm')]
        #[clap(alias = "msg")]
        message: String,
    },

    #[command(name = "chacha20poly1305")]
    ChaCha20Poly1305(ChaCha20Poly1305Args),

    #[command(name = "xchacha20poly1305")]
    XChaCha20Poly1305(XChaCha20Poly1305Args),

    #[command(name = "random")]
    #[clap(alias = "rand")]
    Random(RandomArgs),
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
    #[arg(long = "format", short = 'f', default_value = "bytes")]
    #[clap(alias = "fmt")]
    format: Format,
}

#[derive(Clone, ClapValueEnum)]
enum Format {
    String,
    Bytes,
    Hex,
    Base64,
}

fn app() {
    let command = Command::parse();
    match command.subcommand {
        Subcommand::Encode { format, message } => match format {
            Format::String => todo!(),
            Format::Bytes => todo!(),
            Format::Hex => todo!(),
            Format::Base64 => todo!(),
        },

        Subcommand::Decode { format, message } => match format {
            Format::String => todo!(),
            Format::Bytes => todo!(),
            Format::Hex => todo!(),
            Format::Base64 => todo!(),
        },

        Subcommand::ChaCha20Poly1305(args) => {
            let key = match read_arg(args.key) {
                Err(err) => {
                    //エラーここ
                    //ToDo
                    panic!("")
                }
                Ok(bytes) => match TryInto::<[u8; 32]>::try_into(bytes) {
                    Err(_) => {
                        //エラーここ
                        //ToDo
                        panic!("")
                    }
                    Ok(bytes) => bytes,
                },
            };

            let additionaldata = match read_arg(args.additionaldata) {
                Err(err) => {
                    //エラーここ
                    //ToDo
                    panic!("")
                }
                Ok(bytes) => bytes,
            };

            let message = match read_arg(args.message) {
                Err(err) => {
                    //エラーここ
                    //ToDo
                    panic!("")
                }
                Ok(bytes) => bytes,
            };

            let cipher = match symmetric::chacha20poly1305_encrypt(key, [0u8; 12], &additionaldata, &message) {
                Err(err) => {
                    //エラーここ
                    //ToDo
                    panic!("")
                },
                Ok(cipher) => {
                    cipher
                }
            };

            
        }

        Subcommand::XChaCha20Poly1305(args) => todo!(),

        Subcommand::Random(args) => {
            todo!()
        }
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

// main
fn main() -> io::Result<()> {
    Ok(())
}
