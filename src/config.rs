// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use log::{error, warn};
use lpc55_sign::debug_auth::DebugCredentialSigningRequest;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use thiserror::Error;
use yubihsm::{
    asymmetric,
    object::{Id, Label},
    Capability, Domain,
};

// string for environment variable used to pass in the authentication
// password for the HSM
pub const ENV_PASSWORD: &str = "OKS_PASSWORD";
// string for environment variable used to pass in a NEW authentication
// password for the HSM
pub const ENV_NEW_PASSWORD: &str = "OKS_NEW_PASSWORD";

pub const KEYSPEC_EXT: &str = ".keyspec.json";

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed conversion from YubiHSM Label")]
    BadLabel,

    #[error("failed conversion from YubiHSM Capability")]
    BadCapability,

    #[error("failed to parse key spec from JSON")]
    BadKeySpec { e: serde_json::Error },

    #[error("failed to parse csr spec from JSON")]
    BadCsrSpec { e: serde_json::Error },
}

// Conversion functions to / from String <-> Label
serde_with::serde_conv!(
    LabelAsString,
    Label,
    |label: &Label| label.to_string(),
    |string: String| -> Result<Label, anyhow::Error> {
        Ok(Label::from(string.as_str()))
    }
);

// These structs duplicate data from the yubihsm crate
// The Algorithm and Domain types serialize but won't deserialize
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
enum OksAlgorithm {
    Rsa4096,
    Ecp384,
}

impl From<OksAlgorithm> for asymmetric::Algorithm {
    fn from(val: OksAlgorithm) -> Self {
        match val {
            OksAlgorithm::Rsa4096 => asymmetric::Algorithm::Rsa4096,
            OksAlgorithm::Ecp384 => asymmetric::Algorithm::EcP384,
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
enum OksDomain {
    DOM1,
}

impl From<OksDomain> for Domain {
    fn from(val: OksDomain) -> Self {
        match val {
            OksDomain::DOM1 => Domain::DOM1,
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct OksLabel(String);

impl TryInto<Label> for OksLabel {
    type Error = ConfigError;

    fn try_into(self) -> Result<Label, Self::Error> {
        match Label::from_bytes(self.0.as_bytes()) {
            Ok(label) => Ok(label),
            Err(_e) => Err(ConfigError::BadLabel),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
enum OksCapability {
    All,
}

impl From<OksCapability> for Capability {
    fn from(val: OksCapability) -> Self {
        match val {
            OksCapability::All => Capability::all(),
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Hash {
    Sha256,
    Sha384,
}

/// Values in this enum are mapped to OpenSSL config sections for v3 extensions.
/// All certs issued by the OKS are assumed to be intermediate CAs.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Purpose {
    RoTDevelopmentRoot,
    RoTReleaseRoot,
    RoTDevelopmentCodeSigning,
    RoTReleaseCodeSigning,
    Identity,
}

/// NOTE: These strings correspond to config sections for v3 extensions in the
/// openssl.cnf.
impl ToString for Purpose {
    fn to_string(&self) -> String {
        let str = match self {
            Purpose::RoTReleaseRoot => "v3_rot_release_root",
            Purpose::RoTDevelopmentRoot => "v3_rot_development_root",
            Purpose::RoTReleaseCodeSigning => "v3_code_signing_rel",
            Purpose::RoTDevelopmentCodeSigning => "v3_code_signing_dev",
            Purpose::Identity => "v3_identity",
        };
        String::from(str)
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct OksKeySpec {
    pub common_name: String,
    pub id: Id,
    pub algorithm: OksAlgorithm,
    pub capabilities: OksCapability,
    pub domain: OksDomain,
    pub hash: Hash,
    pub label: OksLabel,
    pub purpose: Purpose,
    #[serde(with = "hex")]
    pub initial_serial_number: [u8; 20],
    pub self_signed: bool,
}

#[derive(Debug)]
pub struct KeySpec {
    pub common_name: String,
    pub id: Id,
    pub algorithm: asymmetric::Algorithm,
    pub capabilities: Capability,
    pub domain: Domain,
    pub hash: Hash,
    pub label: Label,
    pub purpose: Purpose,
    pub initial_serial_number: BigUint,
    pub self_signed: bool,
}

impl FromStr for KeySpec {
    type Err = ConfigError;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
        let spec: OksKeySpec = serde_json::from_str(data)
            .map_err(|e| ConfigError::BadKeySpec { e })?;
        spec.try_into()
    }
}

impl TryFrom<OksKeySpec> for KeySpec {
    type Error = ConfigError;

    fn try_from(spec: OksKeySpec) -> Result<Self, Self::Error> {
        Ok(KeySpec {
            common_name: spec.common_name,
            id: spec.id,
            algorithm: spec.algorithm.into(),
            capabilities: spec.capabilities.into(),
            domain: spec.domain.into(),
            hash: spec.hash,
            label: spec.label.try_into()?,
            purpose: spec.purpose,
            initial_serial_number: BigUint::from_bytes_be(
                &spec.initial_serial_number,
            ),
            self_signed: spec.self_signed,
        })
    }
}

/// CSRs are great but we need to know which key / CA should be used to sign
/// the cert. This is a small wrapper over a key label and a CSR. When sending
/// a CSR to the OKS, populate this structure with the label for the key / CA
/// you want to sign your cert and the PEM encoded CSR.
#[serde_with::serde_as]
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct CsrSpec {
    /// The key / CA that should be used to sign the CSR.
    #[serde_as(as = "LabelAsString")]
    pub label: Label,
    /// the CSR to be signed
    pub csr: String,
}

impl CsrSpec {
    /// Return the JSON representation of CsrSpec
    pub fn json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl FromStr for CsrSpec {
    type Err = ConfigError;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(data).map_err(|e| ConfigError::BadCsrSpec { e })
    }
}

pub fn files_with_ext(dir: &Path, ext: &str) -> Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for element in fs::read_dir(dir)? {
        match element {
            Ok(e) => {
                let path = e.path();
                if path.to_string_lossy().ends_with(ext) {
                    paths.push(path);
                }
            }
            Err(e) => {
                warn!("skipping directory entry due to error: {}", e);
                continue;
            }
        }
    }

    Ok(paths)
}

#[serde_with::serde_as]
#[derive(Debug, Deserialize, Serialize)]
pub struct DcsrSpec {
    /// The key / CA that should be used to sign the CSR.
    #[serde_as(as = "LabelAsString")]
    pub label: Label,

    /// Root keys matching those registered in target device's CMPA.
    #[serde_as(as = "Vec<LabelAsString>")]
    pub root_labels: Vec<Label>,

    /// The DCSR to be signed
    pub dcsr: DebugCredentialSigningRequest,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Transport {
    Http,
    Usb,
}

impl FromStr for Transport {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "http" => Ok(Transport::Http),
            "usb" => Ok(Transport::Usb),
            _ => Err(anyhow::anyhow!("Invalid transport string")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON_RSA4K: &str = r#"{
        "common_name":
            "Gimlet RoT Stage0 Code Signing Engineering Offline CA A",
        "id":1,
        "algorithm":"Rsa4096",
        "capabilities":"All",
        "domain":"DOM1",
        "hash":"Sha256",
        "label":"rot-stage0-signing-root-eng-a",
        "purpose":"RoTReleaseCodeSigning",
        "initial_serial_number":"3cc3000000000000000000000000000000000000",
        "self_signed":true
    }"#;

    #[test]
    fn test_rsa4k_deserialize() -> Result<()> {
        let key_spec: OksKeySpec = serde_json::from_str(&JSON_RSA4K)?;
        assert_eq!(
            key_spec.common_name,
            "Gimlet RoT Stage0 Code Signing Engineering Offline CA A",
        );
        assert_eq!(key_spec.id, 1);
        assert_eq!(key_spec.capabilities, OksCapability::All);
        assert_eq!(key_spec.domain, OksDomain::DOM1);
        assert_eq!(
            key_spec.label,
            OksLabel("rot-stage0-signing-root-eng-a".to_string())
        );
        assert_eq!(key_spec.algorithm, OksAlgorithm::Rsa4096);
        Ok(())
    }

    #[test]
    fn test_oks_spec_convert() -> Result<()> {
        let key_spec = KeySpec::from_str(JSON_RSA4K)?;

        //assert_eq!(key_spec.id, 1);
        assert_eq!(key_spec.capabilities, Capability::all());
        //assert_eq!(key_spec.domain, Domain::DOM1);
        //assert_eq!(
        //    key_spec.label,
        //    Label::from_bytes("rot-stage0-signing-root-eng-a".as_bytes())?,
        //);
        //assert_eq!(key_spec.algorithm, asymmetric::Algorithm::Rsa4096);
        Ok(())
    }

    const JSON_ECP384: &str = r#"{
        "common_name": "RoT Identity Signing Offline CA",
        "id": 2,
        "algorithm":"Ecp384",
        "capabilities":"All",
        "domain":"DOM1",
        "hash":"Sha384",
        "label":"rot-identity-signing-ca",
        "purpose":"RoTDevelopmentCodeSigning",
        "initial_serial_number":"0000000000000000000000000000000000000000",
        "self_signed":true
    }"#;

    #[test]
    fn test_ecp384_deserialize() -> Result<()> {
        let key_spec: OksKeySpec = serde_json::from_str(&JSON_ECP384)?;
        assert_eq!(key_spec.common_name, "RoT Identity Signing Offline CA",);
        assert_eq!(key_spec.id, 2);
        assert_eq!(key_spec.capabilities, OksCapability::All);
        assert_eq!(key_spec.domain, OksDomain::DOM1);
        assert_eq!(
            key_spec.label,
            OksLabel("rot-identity-signing-ca".to_string())
        );
        assert_eq!(key_spec.algorithm, OksAlgorithm::Ecp384);
        assert_eq!(key_spec.purpose, Purpose::RoTDevelopmentCodeSigning);
        Ok(())
    }

    const JSON_IDENTITY: &str = r#"{
        "common_name": "RoT Identity Signing Offline CA",
        "id": 2,
        "algorithm":"Ecp384",
        "capabilities":"All",
        "domain":"DOM1",
        "hash":"Sha384",
        "label":"rot-identity-signing-ca",
        "purpose":"Identity",
        "initial_serial_number":"0000000000000000000000000000000000000000",
        "self_signed":true
    }"#;

    #[test]
    fn test_extensions_engineering() -> Result<()> {
        let key_spec: OksKeySpec = serde_json::from_str(&JSON_IDENTITY)?;
        assert_eq!(key_spec.purpose, Purpose::Identity);
        Ok(())
    }

    // NOTE: this CSR in this struct is designed for testing and is not a
    // valid CSR
    const JSON_CSR: &str = r#"{
        "label":"rot-identity-signing-ca",
        "csr": "-----BEGIN CERTIFICATE REQUEST-----\nOQ==\n-----END CERTIFICATE REQUEST-----"
    }"#;

    #[test]
    fn test_csr_deserialize() -> Result<()> {
        let csr_spec: CsrSpec = CsrSpec::from_str(&JSON_CSR)?;
        assert_eq!(
            csr_spec.label,
            Label::from_bytes("rot-identity-signing-ca".as_bytes())?
        );
        assert_eq!(csr_spec.csr,
            "-----BEGIN CERTIFICATE REQUEST-----\nOQ==\n-----END CERTIFICATE REQUEST-----");

        Ok(())
    }

    #[test]
    fn test_csr_spec_serialize() -> Result<()> {
        let label = "psc-rot-stage0-code-signing-dev-a";
        let csr = "-----BEGIN CERTIFICATE REQUEST-----
0000000000000000000000000000000000000000000000000000000000000000
1111111111111111111111111111111111111111111111111111111111111111
-----END CERTIFICATE REQUEST-----
"
        .to_string();

        let csr_spec = CsrSpec {
            label: Label::from_str(label)?,
            csr: csr.clone(),
        };
        let json = csr_spec.json()?;

        let csr_spec: CsrSpec = serde_json::from_str(&json)?;

        let expected = CsrSpec {
            label: label.into(),
            csr,
        };

        assert_eq!(expected, csr_spec);

        Ok(())
    }
}
