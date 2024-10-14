// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::util;
use anyhow::Result;
use const_format::concatcp;
use log::debug;
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

pub const DEFAULT_INPUT: &str = "/usr/share/oks";
pub const DEFAULT_STATE: &str = "/var/lib/oks";

pub const ATTEST_FILE_NAME: &str = "hsm.attest.cert.pem";
pub const VERIFIER_FILE_NAME: &str = "verifier.json";
pub const OUT_DIR_NAME: &str = "output";

pub const DEFAULT_VERIFIER: &str = concatcp!(DEFAULT_INPUT, VERIFIER_FILE_NAME);
pub const DEFAULT_ATTEST: &str = concatcp!(DEFAULT_STATE, ATTEST_FILE_NAME);

/// OKS is stateful. This type represents the writable state of an OKS
/// instance.
/// By convention we store
/// - OpenSSL ca state directories for each PKI at $path/$key-label
/// - output files in $path
#[derive(Clone)]
pub struct Storage {
    pub path: PathBuf,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(path: Option<P>) -> Self {
        let path = match path {
            Some(p) => p.as_ref().to_path_buf(),
            None => PathBuf::from_str(DEFAULT_STATE).expect("fml"),
        };

        Self { path }
    }

    pub fn write_to_output(&self, name: &str, data: &[u8]) -> Result<()> {
        util::make_dir(&self.path)?;

        debug!("Writing name: {} to: {}", name, self.path.display());

        Ok(fs::write(self.path.join(name), data)?)
    }

    // These are a hack to support the `ca` module w/ minimal changes.
    pub fn get_output(&self) -> Result<PathBuf> {
        util::make_dir(&self.path)?;
        Ok(self.path.clone())
    }

    pub fn get_ca_root(&self) -> Result<PathBuf> {
        util::make_dir(&self.path)?;
        Ok(self.path.clone())
    }
}
