use std::{
    self,
    io::{self, stderr, stdout, Write},
    process::exit,
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
    #[command(name = "chacha20poly1305")]
    ChaCha20Poly1305(ChaCha20Poly1305Args),

    #[command(name = "xchacha20poly1305")]
    XChaCha20Poly1305(XChaCha20Poly1305Args),

    #[command(name = "random")]
    #[clap(alias = "rand")]
    Random(Random),
}

#[derive(ClapArgs)]
struct ChaCha20Poly1305Args {
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
struct Random {
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
        Subcommand::ChaCha20Poly1305(args) => todo!(),

        Subcommand::XChaCha20Poly1305(args) => todo!(),

        Subcommand::Random(args) => {
            let bytes = xck::rand::generate();

            match args.format {
                Format::String => {
                    stdout().write(String::from_utf8_lossy(&bytes).as_bytes())?;
                }
                Format::Hex => {
                    stdout().write(xck::utils::hex(&bytes).as_bytes())?;
                }
                Format::Bytes => {
                    stdout().write(&bytes)?;
                }
                Format::Base64 => todo!(),
            }
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    app()
}
