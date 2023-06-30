use std::{
    self,
    io::{self, stderr, stdout, Write},
    process::exit, path::Path, fs,
};

use clap::{
    Args as ClapArgs, Parser as ClapParser, Subcommand as ClapSubcommand,
    ValueEnum as ClapValueEnum,
};

use rand::{Rng, SeedableRng};

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
    aad: String,

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
    aad: String,

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

fn app() -> io::Result<()> {
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
            println!("{:?}", args.message);
        }

        Subcommand::XChaCha20Poly1305(args) => todo!(),

        Subcommand::Random(args) => {
            todo!()
        }
    }

    Ok(())
}

fn read_file(path:&Path){
    fs::File::open(path);

    todo!()
}

fn arg_type_of(string: &str) -> ArgType {
    match string
        .split_once(':')
        .unwrap_or_default()
        .0
        .to_lowercase()
        .as_ref()
    {
        "file" => ArgType::File,
        "cli" => ArgType::Cli,
        _ => ArgType::Cli,
    }
}

#[derive(Debug)]
enum ArgType {
    Cli,
    File,
}

fn main() -> io::Result<()> {
    app()
}
