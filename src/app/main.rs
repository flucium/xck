use std::{
    self, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use clap::{Args, Parser, Subcommand};

const NAME: &str = "XCK";

const VERSION: &str = "0.0.1";

const AUTHOR: &str = "flucium";

const ABOUT: &str = "";

#[derive(Parser)]
#[command(name = NAME, version = VERSION, author = AUTHOR, about = ABOUT)]
#[clap(disable_help_subcommand(true))]
struct AppCommand {
    #[command(subcommand)]
    subcommand: AppSubcommand,
}

#[derive(Subcommand)]
enum AppSubcommand {
    /// random is...
    #[command(name = "random")]
    #[clap(alias = "rand")]
    Random(RandomArgs),

    /// Ed25519 is...
    #[command(name = "ed25519")]
    Ed25519(Ed25519Args),

    /// X25519 is ...
    #[command(name = "x25519")]
    X21159(X25519Args),

    #[command(name = "chacha20-poly1305")]
    #[clap(alias = "chacha20poly1305")]
    ChaCha20Poly1305(ChaCha20Poly1305Args),
}

#[derive(Args)]
struct RandomArgs {
    #[arg(long = "length", short = 'l', default_value = "32")]
    #[clap(alias = "len")]
    length: u32,
}

#[derive(Parser)]
struct Ed25519Args {
    #[command(subcommand)]
    subcommand: Ed25519SubCommand,
}

#[derive(Subcommand)]
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

#[derive(Args)]
struct Ed25519SignArgs {
    #[arg(long = "private-key", short = 'k')]
    #[clap(alias = "privatekey")]
    private_key: String,

    #[arg(long = "message", short = 'm')]
    #[clap(alias = "msg")]
    message: String,
}

#[derive(Args)]
struct Ed25519VerifyArgs {
    #[arg(long = "public-key", short = 'k')]
    #[clap(alias = "publickey")]
    public_key: String,

    #[arg(long = "message", short = 'm')]
    #[clap(alias = "msg")]
    message: String,

    #[arg(long = "signature", short = 's')]
    #[clap(alias = "sign")]
    signature: String,
}

#[derive(Args)]
struct Ed25519GenPrivateKeyArgs;

#[derive(Args)]
struct Ed25519GenPublicKeyArgs {
    #[arg(long = "private-key")]
    #[clap(alias = "privatekey")]
    private_key: String,
}

#[derive(Parser)]
struct X25519Args {
    #[command(subcommand)]
    subcommand: X25519SubCommand,
}

#[derive(Subcommand)]
enum X25519SubCommand {
    #[command(name = "diffie-hellman")]
    #[clap(alias = "dh")]
    #[clap(alias = "keyexchange")]
    DiffiHellman(X21159DiffieHellmanArgs),

    #[command(name = "gen-private-key")]
    #[clap(alias = "gen-privatekey")]
    X25519GenPrivateKey(X25519GenPrivateKeyArgs),

    #[command(name = "gen-public-key")]
    #[clap(alias = "gen-publickey")]
    X25519GenPublicKey(X25519GenPublicKeyArgs),
}

#[derive(Args)]
struct X25519GenPrivateKeyArgs;

#[derive(Args)]
struct X25519GenPublicKeyArgs {
    #[arg(long = "private-key")]
    #[clap(alias = "privatekey")]
    private_key: String,
}

#[derive(Args)]
struct X21159DiffieHellmanArgs {
    #[arg(long = "private-key")]
    #[clap(alias = "privatekey")]
    private_key: String,

    #[arg(long = "public-key")]
    #[clap(alias = "publickey")]
    public_key: String,
}

#[derive(Args)]
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

    stdout.write(&[10]).unwrap();

    stdout.flush().unwrap();
}

fn stderr(buf: impl AsRef<[u8]>) {
    let mut stderr = io::stderr().lock();

    stderr.write_all(buf.as_ref()).unwrap();

    stderr.write(&[10]).unwrap();

    stderr.flush().unwrap();
}

fn main() {
    let command = AppCommand::parse();

    match command.subcommand {
        AppSubcommand::Random(args) => {
            const LEN_MIN: u32 = 1;

            const LEN_MAX: u32 = 32;

            if args.length < LEN_MIN || args.length > LEN_MAX {
                stderr("xck: error: Output length can be specified between 1 and 32 digits.");
                return;
            }

            let bytes = xck::rand::generate_ascii()
                .get(0..args.length as usize)
                .unwrap()
                .to_vec();

            stdout(bytes);
        }

        AppSubcommand::Ed25519(args) => match args.subcommand {
            Ed25519SubCommand::Sign(args) => {
                let pem_encoded = match read_arg(args.private_key) {
                    Err(_) => {
                        stderr("xck: error: File read failed.");
                        return;
                    }
                    Ok(bytes) => bytes,
                };

                let (label, private_key) = match xck::format::pem_decode(&pem_encoded) {
                    Err(_) => {
                        stderr("xck: error: Failed from decode PEM format.");
                        return;
                    }
                    Ok(decoded) => decoded,
                };

                if label != xck::format::PEM_LABEL_PRIVATE_KEY {
                    stderr("xck: error: The key type does not match the label in PEM format.");
                    return;
                }

                let message = match read_arg(args.message) {
                    Err(_) => {
                        stderr("xck: error: File read failed.");
                        return;
                    }
                    Ok(bytes) => bytes,
                };

                // Format ToDo...
                let signature = match xck::asymmetric::ed25519_sign(&private_key, &message) {
                    Err(_) => {
                        stderr("xck: error: Ed25519, Signature failed.");
                        return;
                    }
                    Ok(bytes) => bytes,
                };

                let encoded = match xck::format::base64_encode(&signature) {
                    Err(_) => {
                        stderr("xck: error: Encoding to Base64 failed.");
                        return;
                    }
                    Ok(b64string) => b64string,
                };

                stdout(encoded);
            }

            Ed25519SubCommand::Verify(args) => {
                let message = match read_arg(args.message) {
                    Err(_) => {
                        stderr("xck: error: File read failed.");
                        return;
                    }
                    Ok(bytes) => bytes,
                };

                let encoded_signature = match read_arg(args.signature) {
                    Err(_) => {
                        stderr("xck: error: File read failed.");
                        return;
                    }
                    Ok(bytes) => bytes,
                };

                // Format ToDo...
                let bytes = match xck::format::base64_decode(
                    String::from_utf8(encoded_signature).unwrap_or_default(),
                ) {
                    Err(_) => {
                        stderr("xck: error: Decoding from Base64 failed.");
                        return;
                    }
                    Ok(bytes) => bytes,
                };

                let signature: [u8; 64] = bytes.try_into().unwrap_or([0u8; 64]);

                let pem_encoded = match read_arg(args.public_key) {
                    Err(_) => {
                        stderr("xck: error: File read failed.");
                        return;
                    }
                    Ok(bytes) => bytes,
                };

                let (label, public_key) = match xck::format::pem_decode(&pem_encoded) {
                    Err(_) => {
                        stderr("xck: error: Failed from decode PEM format.");
                        return;
                    }
                    Ok(encoded) => encoded,
                };

                if label != xck::format::PEM_LABEL_PUBLIC_KEY {
                    stderr("xck: error: The key type does not match the label in PEM format.");
                    return;
                }

                stdout(
                    xck::asymmetric::ed25519_verify(&public_key, &message, &signature)
                        .is_ok()
                        .to_string(),
                );
            }

            Ed25519SubCommand::Ed25519GenPrivateKey(_) => {
                let private_key = xck::asymmetric::ed25519_gen_private_key();

                let pem_encoded =
                    xck::format::pem_encode(xck::format::PEM_LABEL_PRIVATE_KEY, &private_key)
                        .unwrap();

                stdout(pem_encoded);
            }

            Ed25519SubCommand::Ed25519GenPublicKey(args) => {
                let bytes = match read_arg(args.private_key) {
                    Err(_) => {
                        stderr("xck: error: File read failed.");
                        return;
                    }
                    Ok(bytes) => bytes,
                };

                let (label, private_key) = match xck::format::pem_decode(&bytes) {
                    Err(_) => {
                        stderr("xck: error: Failed from decode PEM format.");
                        return;
                    }
                    Ok(encoded) => encoded,
                };

                if label != xck::format::PEM_LABEL_PRIVATE_KEY {
                    stderr("xck: error: The key type does not match the label in PEM format.");
                    return;
                }

                let public_key = xck::asymmetric::ed25519_gen_public_key(&private_key);

                let pem_encoded =
                    xck::format::pem_encode(xck::format::PEM_LABEL_PUBLIC_KEY, &public_key)
                        .unwrap();

                stdout(pem_encoded);
            }
        },

        AppSubcommand::X21159(args) => match args.subcommand {
            X25519SubCommand::DiffiHellman(args) => {
                let pem_encoded = match read_arg(args.private_key) {
                    Err(_) => {
                        stderr("xck: error: File read failed.");
                        return;
                    }
                    Ok(bytes) => bytes,
                };

                let (label, private_key) = match xck::format::pem_decode(&pem_encoded) {
                    Err(_) => {
                        stderr("xck: error: Failed from decode PEM format.");
                        return;
                    }
                    Ok(encoded) => encoded,
                };

                if label != xck::format::PEM_LABEL_PRIVATE_KEY {
                    stderr("xck: error: The key type does not match the label in PEM format.");
                    return;
                }

                let pem_encoded = match read_arg(args.public_key) {
                    Err(_) => {
                        stderr("xck: error: File read failed.");
                        return;
                    }
                    Ok(bytes) => bytes,
                };

                let (label, public_key) = match xck::format::pem_decode(&pem_encoded) {
                    Err(_) => {
                        stderr("xck: error: Failed from decode PEM format.");
                        return;
                    }
                    Ok(encoded) => encoded,
                };

                if label != xck::format::PEM_LABEL_PUBLIC_KEY {
                    stderr("xck: error: The key type does not match the label in PEM format.");
                    return;
                }

                let shared_key = xck::asymmetric::x25519_diffie_hellman(&private_key, &public_key);

                // Format ToDo...
                let b64_encoded_string = xck::format::base64_encode(&shared_key).unwrap();

                stdout(b64_encoded_string);
            }

            X25519SubCommand::X25519GenPrivateKey(_) => {
                let private_key = xck::asymmetric::x25519_gen_private_key();

                let pem_encoded =
                    xck::format::pem_encode(xck::format::PEM_LABEL_PRIVATE_KEY, &private_key)
                        .unwrap();

                stdout(pem_encoded);
            }

            X25519SubCommand::X25519GenPublicKey(args) => {
                let bytes = match read_arg(args.private_key) {
                    Err(_) => {
                        stderr("xck: error: File read failed.");
                        return;
                    }
                    Ok(bytes) => bytes,
                };

                let (label, private_key) = match xck::format::pem_decode(&bytes) {
                    Err(_) => {
                        stderr("xck: error: Failed from decode PEM format.");
                        return;
                    }
                    Ok(encoded) => encoded,
                };

                if label != xck::format::PEM_LABEL_PRIVATE_KEY {
                    stderr("xck: error: The key type does not match the label in PEM format.");
                    return;
                }

                let public_key = xck::asymmetric::ed25519_gen_public_key(&private_key);

                let pem_encoded =
                    xck::format::pem_encode(xck::format::PEM_LABEL_PUBLIC_KEY, &public_key)
                        .unwrap();

                stdout(pem_encoded);
            }
        },

        AppSubcommand::ChaCha20Poly1305(args) => {}
    }
}
