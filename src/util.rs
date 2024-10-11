// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use log::{debug, info};
use std::{fs, path::Path};
use yubihsm::{
    object::{Id, Type},
    wrap::Message,
    Client,
};

use crate::config::{self, BACKUP_EXT}; // duplicated from HSM module
const WRAP_ID: Id = 1;

/// Provided a key ID and a object type this function will find the object
/// in the HSM and generate the appropriate KeySpec for it.
pub fn backup_object<P: AsRef<Path>>(
    client: &Client,
    id: Id,
    kind: Type,
    file: P,
) -> Result<()> {
    info!("Backing up object with id: {:#06x} and type: {}", id, kind);
    let message = client.export_wrapped(WRAP_ID, kind, id)?;
    debug!("Got Message: {:?}", &message);

    let json = serde_json::to_string(&message)?;
    debug!("JSON: {}", json);

    let path = if file.as_ref().is_dir() {
        // get info
        // append format!("{}.backup.json", info.label)
        let info = client.get_object_info(id, kind)?;
        file.as_ref().join(format!("{}.backup.json", info.label))
    } else if file.as_ref().exists() {
        // file exists ... overwrite it?
        return Err(anyhow::anyhow!("File already exists."));
    } else {
        file.as_ref().to_path_buf()
    };

    info!("Writing backup to: \"{}\"", path.display());
    Ok(fs::write(path, json)?)
}

pub fn restore<P: AsRef<Path>>(client: &Client, file: P) -> Result<()> {
    let file = file.as_ref();
    info!("Restoring from backups in: \"{}\"", &file.display());
    let paths = if file.is_file() {
        vec![file.to_path_buf()]
    } else {
        config::files_with_ext(file, BACKUP_EXT)?
    };

    if paths.is_empty() {
        return Err(anyhow::anyhow!("backup directory is empty"));
    }

    for path in paths {
        info!("Restoring wrapped backup from file: {}", path.display());
        let json = fs::read_to_string(path)?;

        debug!("backup json: {}", json);
        let message: Message = serde_json::from_str(&json)?;

        debug!("deserialized message: {:?}", &message);
        let handle = client.import_wrapped(WRAP_ID, message)?;

        info!(
            "Imported {} key with object id {}.",
            handle.object_type, handle.object_id
        );
    }

    Ok(())
}

pub fn make_dir<P: AsRef<Path>>(path: P) -> Result<()> {
    if !path.as_ref().exists() {
        // output directory doesn't exist, create it
        info!(
            "required directory does not exist, creating: \"{}\"",
            path.as_ref().display()
        );
        Ok(fs::create_dir_all(path)?)
    } else if !path.as_ref().is_dir() {
        Err(anyhow::anyhow!(
            "directory provided is not a directory: \"{}\"",
            path.as_ref().display()
        ))
    } else {
        Ok(())
    }
}
