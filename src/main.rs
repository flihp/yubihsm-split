// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand};
use env_logger::Builder;
use log::LevelFilter;
use std::path::PathBuf;
use yubihsm::{object::Id, Client, Connector, Credentials, UsbConfig};

const AUTH_KEY_ID: &str = "1";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// Create and restore split yubihsm wrap keys
struct Args {
    /// Increase verbosity
    #[clap(long, env)]
    verbose: bool,

    /// Directory where HSM config description and CA state goes
    /// TODO: coordinate this with OS?
    #[clap(long, env, default_value = "./keystore-state")]
    state: PathBuf,

    /// Directory where public data goes
    /// TODO: coordinate this with OS?
    #[clap(long, env, default_value = "./public")]
    public: PathBuf,

    #[clap(long, env, default_value = AUTH_KEY_ID)]
    auth_key_id: Id,

    #[clap(long, env, default_value = "password")]
    auth_passwd: String,

    /// subcommands
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate keys in YubiHSM from specification
    Generate {
        #[clap(long, env, default_value = "data/key-request-rsa4k.json")]
        key_spec: PathBuf,
    },
    /// Initialize the YubiHSM by creating a new aes256-ccm-wrap key,
    /// splitting it into shares, creating a new authentication key
    /// personalized by the caller, and backing up this new auth key under
    /// wrap.
    Initialize,
    /// Restore a previously split aes256-ccm-wrap key
    Restore,
}

// 2 minute to support RSA4K key generation
const TIMEOUT_MS: u64 = 120000;

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    builder.filter(None, level).init();

    // connect to the first YubiHSM found
    // NOTE: don't use the http connector unless you have to
    // yubihsm-shell commands
    //let config = HttpConfig {
    //    addr: "127.0.0.1".to_owned(),
    //    port: 12345,
    //    timeout_ms: TIMEOUT_MS,
    //};
    //let connector = Connector::http(&config);
    let config = UsbConfig {
        serial: None,
        timeout_ms: TIMEOUT_MS,
    };
    let connector = Connector::usb(&config);
    // this will only work if the default auth key is still available
    // the next step in our process must be: replace the default auth key
    let credentials = Credentials::from_password(
        args.auth_key_id,
        args.auth_passwd.as_bytes(),
    );
    let client = Client::open(connector, credentials, true)?;

    match args.command {
        Command::Initialize => yubihsm_split::initialize(&client, &args.public),
        Command::Generate { key_spec } => {
            yubihsm_split::generate(&client, &key_spec)
        }
        Command::Restore => yubihsm_split::restore(&client),
    }
}
