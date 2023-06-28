use std::{
    self,
    io::{self, stderr, Write},
    process::exit,
};

use xck::size::SIZE_32;

const NAME: &str = "XCK";

const VERSION: &str = "0.0.1";

const AUTHOR: &str = "flucium";

const ABOUT: &str = "";

fn app() -> clap::Command {
    clap::Command::new(NAME)
        .version(VERSION)
        .author(AUTHOR)
        .about(ABOUT)
        .subcommands([clap::Command::new("chacha20-poly1305").args(app_symmetric_args())])
        .subcommands([clap::Command::new("xchacha20-poly1305").args(app_symmetric_args())])
}

fn app_symmetric_args() -> [clap::Arg; 4] {
    [
        clap::Arg::new("encrypt")
            .long("encrypt")
            .short('e')
            .alias("enc")
            .action(clap::ArgAction::SetTrue),
        clap::Arg::new("decrypt")
            .long("decrypt")
            .short('d')
            .alias("dec")
            .action(clap::ArgAction::SetTrue),
        clap::Arg::new("key")
            .long("key")
            .short('k')
            .action(clap::ArgAction::Set)
            .required(false),
        clap::Arg::new("message")
            .long("message")
            .short('m')
            .alias("msg")
            .action(clap::ArgAction::Set)
            .required(false),
    ]
}

fn main() -> io::Result<()> {
    let app = app();

    let matches = app.get_matches();

    match matches.subcommand() {
        Some(("xchacha20-poly1305", arg_matches)) => {
            let _key: &[u8; SIZE_32] = match arg_matches
                .get_one::<String>("key")
                .unwrap_or(&String::default())
                .as_bytes()
                .try_into()
            {
                Err(err) => {
                    write!(&mut stderr(), "{:?}", err)?;

                    exit(1)
                }
                Ok(key) => key,
            };

            let _message = arg_matches
                .get_one::<String>("message")
                .unwrap_or(&String::default())
                .as_bytes();

            if arg_matches.get_flag("encrypt") {}
            if arg_matches.get_flag("decrypt") {
            } else {
            }
        }

        Some(("chacha20-poly1305", arg_matches)) => {
            let _key: &[u8; SIZE_32] = match arg_matches
                .get_one::<String>("key")
                .unwrap_or(&String::default())
                .as_bytes()
                .try_into()
            {
                Err(err) => {
                    write!(&mut stderr(), "{:?}", err)?;

                    exit(1)
                }
                Ok(key) => key,
            };

            let _message = arg_matches
                .get_one::<String>("message")
                .unwrap_or(&String::default())
                .as_bytes();

            if arg_matches.get_flag("encrypt") {}
            if arg_matches.get_flag("decrypt") {
            } else {
            }
        }

        _ => {}
    }

    Ok(())
}
