// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use log::{debug, warn};
use std::{
    fs,
    ops::Deref,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::{tempdir, TempDir};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::backup::Share;

pub const DEFAULT_CDRW_DEV: &str = "/dev/cdrom";

#[derive(Debug, Error)]
pub enum CdrwError {
    #[error("The device provided isn't a block dev or a regular file.")]
    BadDevice,

    #[error("Source directory is neither a file nor a directory.")]
    BadSrc,

    #[error("Failed to burn tmpdir to CDR device.")]
    BurnFail,

    #[error("Failed to eject Cdr.")]
    EjectFail,

    #[error("Unable to get next available loopback device.")]
    GetLoopback,

    #[error("Failed to make ISO from state directory.")]
    IsoFail,

    #[error("Failed to mount Cdr.")]
    MountFail,
}

pub struct Cdr {
    device: PathBuf,
    tmpdir: TempDir,
    loopback: Option<PathBuf>,
}

impl Cdr {
    pub fn new<P: AsRef<Path>>(device: Option<P>) -> Result<Self> {
        let device = match device {
            Some(s) => PathBuf::from(s.as_ref()),
            None => PathBuf::from(DEFAULT_CDRW_DEV),
        };
        Ok(Self {
            device,
            tmpdir: tempdir()?,
            loopback: None,
        })
    }

    pub fn eject(&self) -> Result<()> {
        let mut cmd = Command::new("eject");
        let output = cmd.arg(&self.device).output().with_context(|| {
            format!("failed to run the \"eject\" command: \"{:?}\"", cmd)
        })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CdrwError::EjectFail.into());
        }

        Ok(())
    }

    pub fn mount(&mut self) -> Result<()> {
        use std::os::unix::fs::FileTypeExt;
        // if self.device is a regular file assume it's an iso ... check
        // suffix too?
        // else if it's a device then just mount it
        // otherwise fail
        let file_type = self.device.metadata()?.file_type();
        if file_type.is_file() {
            // if we've been givn an ISO we need to setup a loopback device
            // checkout udisksctl?
            let mut cmd = Command::new("losetup");
            let output = cmd
                .arg("-f")
                .output()
                .with_context(|| "unable to execute \"losetup\"")?;

            debug!("executing command: \"{:#?}\"", cmd);

            if !output.status.success() {
                warn!("command failed with status: {}", output.status);
                warn!(
                    "stderr: \"{}\"",
                    String::from_utf8_lossy(&output.stderr)
                );
                return Err(CdrwError::GetLoopback.into());
            }
            // get path to the loopback device from `losetup` stdout
            let loop_dev =
                String::from(String::from_utf8(output.stdout)?.trim());
            debug!("got loopback device: {}", loop_dev);
            let loop_dev = PathBuf::from(loop_dev);

            let mut cmd = Command::new("losetup");
            let output = cmd
                .arg(&loop_dev)
                .arg(&self.device)
                .output()
                .with_context(|| "failed to execute \"losetup\"")?;

            debug!("executing command: \"{:#?}\"", cmd);
            if !output.status.success() {
                warn!("command failed with status: {}", output.status);
                warn!(
                    "stderr: \"{}\"",
                    String::from_utf8_lossy(&output.stderr)
                );
                return Err(CdrwError::GetLoopback.into());
            }

            self._mount(&loop_dev)?;
            self.loopback = Some(loop_dev);
        } else if file_type.is_block_device() {
            self._mount(&self.device)?;
        } else {
            return Err(CdrwError::BadDevice.into());
        }

        Ok(())
    }

    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.tmpdir.as_ref().join(name);
        debug!("reading data from {}", path.display());

        fs::read(&path).with_context(|| {
            format!("failed to read file: {} from Cdr", path.display())
        })
    }

    // TODO: be resilient to device already mounted ...
    // iterate over Process::mountinfo?
    fn _mount<P: AsRef<Path>>(&self, device: &P) -> Result<()> {
        let mut cmd = Command::new("mount");
        let output = cmd
            .arg(device.as_ref())
            .arg(self.tmpdir.as_ref())
            .output()
            .with_context(|| {
                format!(
                    "failed to mount \"{}\" at \"{}\"",
                    device.as_ref().display(),
                    self.tmpdir.as_ref().display()
                )
            })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CdrwError::MountFail.into());
        }

        Ok(())
    }

    // do this in `Drop`?
    pub fn teardown(&self) {
        // unmount self.tmpdir
        let mut cmd = Command::new("umount");
        // TODO: clone
        let output = cmd
            .arg(self.device.clone())
            .arg(self.tmpdir.as_ref())
            .output();
        let output = match output {
            Ok(o) => o,
            _ => {
                warn!(
                    "failed to unmount \"{}\"",
                    self.tmpdir.as_ref().display()
                );
                return;
            }
        };

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return;
        }

        if self.loopback.is_some() {
            let loopback = self.loopback.clone().unwrap();
            let mut cmd = Command::new("losetup");
            let output = cmd.arg("-d").arg(&loopback).output();

            let output = match output {
                Ok(o) => o,
                _ => {
                    warn!(
                        "failed to destroy loopback device {}",
                        loopback.display()
                    );
                    return;
                }
            };

            if !output.status.success() {
                warn!("command failed with status: {}", output.status);
                warn!(
                    "stderr: \"{}\"",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

pub struct IsoWriter {
    tmpdir: TempDir,
}

impl IsoWriter {
    pub fn new() -> Result<Self> {
        Ok(Self { tmpdir: tempdir()? })
    }

    pub fn add(&self, name: &str, data: &[u8]) -> Result<()> {
        let dst = self.tmpdir.path().join(name);

        fs::write(&dst, data).context(format!(
            "Failed to write data to: \"{}\"",
            dst.display()
        ))?;

        Ok(())
    }

    pub fn to_iso<P: AsRef<Path>>(self, path: P) -> Result<()> {
        let mut cmd = Command::new("mkisofs");
        let output = cmd
            .arg("-r")
            .arg("-iso-level")
            .arg("4")
            .arg("-o")
            .arg(path.as_ref())
            .arg(self.tmpdir.as_ref())
            .output()
            .with_context(|| {
                format!(
                    "failed to create ISO \"{}\" from dir \"{}\"",
                    path.as_ref().display(),
                    self.tmpdir.as_ref().display()
                )
            })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CdrwError::IsoFail.into());
        }

        Ok(())
    }
}

pub struct Cdw {
    iso_writer: IsoWriter,
    device: PathBuf,
}

impl Cdw {
    pub fn new<P: AsRef<Path>>(device: Option<P>) -> Result<Self> {
        let device = match device {
            Some(s) => PathBuf::from(s.as_ref()),
            None => PathBuf::from(DEFAULT_CDRW_DEV),
        };

        Ok(Self {
            device,
            iso_writer: IsoWriter::new()?,
        })
    }

    pub fn write_password(&self, data: &Zeroizing<String>) -> Result<()> {
        debug!(
            "Writing password \"{}\"",
            <Zeroizing<String> as AsRef<str>>::as_ref(data),
        );
        self.iso_writer.add("password", data.deref().as_bytes())
    }

    pub fn write_share(&self, data: &Zeroizing<Share>) -> Result<()> {
        debug!("Writing share: {:?}", data.deref());
        self.iso_writer.add("share", data.deref().as_ref())
    }

    /// Burn data to CD & eject disk when done.
    pub fn burn(self) -> Result<()> {
        use tempfile::NamedTempFile;

        let iso = NamedTempFile::new()?;
        self.iso_writer.to_iso(&iso)?;

        let mut cmd = Command::new("cdrecord");
        let output = cmd
            .arg("-eject")
            .arg("-data")
            .arg(iso.path())
            .arg(format!("dev={}", self.device.display()))
            .arg("gracetime=0")
            .arg("timeout=1000")
            .output()
            .with_context(|| {
                format!(
                    "failed to burn ISO \"{}\" to \"{}\"",
                    iso.path().display(),
                    self.device.display()
                )
            })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CdrwError::BurnFail.into());
        }

        Ok(())
    }

    /// Eject / open CD device.
    pub fn eject(&self) -> Result<()> {
        let mut cmd = Command::new("eject");
        let output = cmd.arg(&self.device).output().with_context(|| {
            format!("failed to eject CD device \"{}\"", self.device.display())
        })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CdrwError::EjectFail.into());
        }

        Ok(())
    }
}
