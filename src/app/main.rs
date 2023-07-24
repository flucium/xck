use std::{
    self,
    fs,
    // io::{self, stderr, stdout, Read, Write},
    io::{self, Read, Write},
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
    /// random is...
    #[command(name = "random")]
    #[clap(alias = "rand")]
    Random(RandomArgs),

    #[command(name = "ed25519")]
    Ed25519(Ed25519Args),

    #[command(name = "x25519")]
    X21159(X25519Args),
}

// trait CommandArgs<T> {
//     fn work(&self) -> T;
// }

#[derive(ClapArgs)]
struct RandomArgs {
    #[arg(long = "length", short = 'l', default_value = "32")]
    length: u32,
}

#[derive(ClapParser)]
struct Ed25519Args {
    #[command(subcommand)]
    subcommand: Ed25519SubCommand,
}

#[derive(ClapSubcommand)]
enum Ed25519SubCommand {
    #[command(name = "sign")]
    Sign(Ed25519SignArgs),

    #[command(name = "verify")]
    Verify(Ed25519VerifyArgs),

    #[command(name = "gen-private-key")]
    #[clap(alias = "gen-privatekey")]
    Ed25519GenPrivateKey(Ed25519GenPrivateKeyArgs),

    #[command(name = "gen-public-key")]
    #[clap(alias = "gen-publickey")]
    Ed25519GenPublicKey(Ed25519GenPublicKeyArgs),
}

#[derive(ClapArgs)]
struct Ed25519SignArgs {
    #[arg(long = "private-key", short = 'k')]
    #[clap(alias = "privatekey")]
    private_key: String,

    #[arg(long = "message", short = 'm')]
    #[clap(alias = "msg")]
    message: String,
}

#[derive(ClapArgs)]
struct Ed25519VerifyArgs {
    #[arg(long = "public-key", short = 'k')]
    #[clap(alias = "publickey")]
    private_key: String,

    #[arg(long = "message", short = 'm')]
    #[clap(alias = "msg")]
    message: String,

    #[arg(long = "signature", short = 's')]
    #[clap(alias = "sign")]
    signature: String,
}

#[derive(ClapArgs)]
struct Ed25519GenPrivateKeyArgs;

#[derive(ClapArgs)]
struct Ed25519GenPublicKeyArgs {
    #[arg(long = "public-key")]
    #[clap(alias = "publickey")]
    private_key: String,
}

#[derive(ClapParser)]
struct X25519Args {
    #[command(subcommand)]
    subcommand: X25519SubCommand,
}

#[derive(ClapSubcommand)]
enum X25519SubCommand {
    #[command(name = "diffie-hellman")]
    #[clap(alias = "dh")]
    #[clap(alias = "keyexchange")]
    DiffiHellman {},

    #[command(name = "gen-private-key")]
    #[clap(alias = "gen-privatekey")]
    X25519GenPrivateKey(X25519GenPrivateKeyArgs),

    #[command(name = "gen-public-key")]
    #[clap(alias = "gen-publickey")]
    X25519GenPublicKey(X25519GenPublicKeyArgs),
}

#[derive(ClapArgs)]
struct X25519GenPrivateKeyArgs;

#[derive(ClapArgs)]
struct X25519GenPublicKeyArgs {
    #[arg(long = "public-key")]
    #[clap(alias = "publickey")]
    private_key: String,
}

#[derive(ClapArgs)]
struct X21159DiffieHellmanArgs {
    #[arg(long = "public-key")]
    #[clap(alias = "publickey")]
    private_key: String,

    #[arg(long = "public-key")]
    #[clap(alias = "publickey")]
    public_key: String,
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

fn stdout(buf: impl AsRef<[u8]>) {
    let mut stdout = io::stdout().lock();

    stdout.write_all(buf.as_ref()).unwrap();

    stdout.flush().unwrap();
}

fn main() {
    let command = Command::parse();

    match command.subcommand {
        Subcommand::Random(args) => {}
        Subcommand::Ed25519(args) => match args.subcommand {
            Ed25519SubCommand::Sign(_) => todo!(),
            Ed25519SubCommand::Verify(_) => todo!(),
            Ed25519SubCommand::Ed25519GenPrivateKey(_) => todo!(),
            Ed25519SubCommand::Ed25519GenPublicKey(_) => todo!(),
        },
        Subcommand::X21159(args) => match args.subcommand {
            X25519SubCommand::DiffiHellman {} => todo!(),
            X25519SubCommand::X25519GenPrivateKey(_) => todo!(),
            X25519SubCommand::X25519GenPublicKey(_) => todo!(),
        },
    }
}
