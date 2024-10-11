// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use const_format::concatcp;
use log::debug;
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::util;

pub const DEFAULT_INPUT: &str = "/usr/share/oks";
pub const DEFAULT_OUTPUT: &str = "/var/lib/oks/output";
pub const DEFAULT_STATE: &str = "/var/lib/oks";

pub const ATTEST_FILE_NAME: &str = "hsm.attest.cert.pem";
pub const VERIFIER_FILE_NAME: &str = "verifier.json";
pub const OUT_DIR_NAME: &str = "output";

pub const DEFAULT_VERIFIER: &str = concatcp!(DEFAULT_INPUT, VERIFIER_FILE_NAME);
pub const DEFAULT_ATTEST: &str = concatcp!(DEFAULT_OUTPUT, ATTEST_FILE_NAME);

// `state` defaults to DEFAULT_STATE
// `output` defaults to None / state_dir/output, can be set in constructor
pub struct Storage {
    pub output: PathBuf,
    pub state: PathBuf,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(state: Option<P>, output: Option<P>) -> Self {
        // unwrap_or?
        let output = match output {
            Some(p) => p.as_ref().to_path_buf(),
            None => PathBuf::from_str(DEFAULT_OUTPUT).expect("fml"),
        };
        let state = match state {
            Some(p) => p.as_ref().to_path_buf(),
            None => PathBuf::from_str(DEFAULT_STATE).expect("fml"),
        };

        Self { output, state }
    }

    pub fn write_to_output(&self, name: &str, data: &[u8]) -> Result<()> {
        util::make_dir(&self.output)?;

        debug!("Writing name: {} to: {}", name, self.output.display(),);

        Ok(fs::write(self.output.join(name), data)?)
    }
}
