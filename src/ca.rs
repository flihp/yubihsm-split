// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, warn};
use std::{
    env,
    fs::{self, OpenOptions, Permissions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str::FromStr,
    thread,
    time::Duration,
};
use tempfile::{NamedTempFile, TempDir};
use thiserror::Error;
use yubihsm::Client;
use zeroize::Zeroizing;

use crate::{
    config::{
        self, CsrSpec, DcsrSpec, KeySpec, Purpose, Transport, ENV_PASSWORD,
    },
    hsm::Hsm,
};

macro_rules! openssl_cnf_fmt {
    () => {
        r#"
openssl_conf                = default_modules

[default_modules]
engines                     = engine_section
oid_section                 = OIDs

[engine_section]
pkcs11                      = pkcs11_section

[pkcs11_section]
engine_id                   = pkcs11
MODULE_PATH                 = {pkcs11_path}
# add 'debug' to INIT_ARGS
INIT_ARGS                   = connector=http://127.0.0.1:12345
init                        = 0

[ ca ]
default_ca                  = CA_default

[ CA_default ]
dir                         = ./
crl_dir                     = $dir/crl
database                    = $dir/index.txt
new_certs_dir               = $dir/newcerts
certificate                 = $dir/ca.cert.pem
serial                      = $dir/serial
# key format:   <slot>:<key id>
private_key                 = 0:{key:04x}
name_opt                    = ca_default
cert_opt                    = ca_default
# certs may be retired, but they won't expire
default_enddate             = 99991231235959Z
default_crl_days            = 30
default_md                  = {hash:?}
preserve                    = no
policy                      = policy_match
email_in_dn                 = no
# Setting rand_serial to _any_ value, including "no", enables that option
#rand_serial                = yes
unique_subject              = no

[ policy_match ]
countryName                 = supplied
stateOrProvinceName         = optional
organizationName            = supplied
organizationalUnitName      = optional
commonName                  = supplied
emailAddress                = optional

[ req ]
default_md                  = {hash:?}
string_mask                 = utf8only

[ v3_rot_release_root ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:true
keyUsage                    = critical, keyCertSign, cRLSign
extendedKeyUsage            = nxpLpc55DebugAuthCredentialSigning
certificatePolicies         = rotCodeSigningReleasePolicy

[ v3_code_signing_rel ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:false
keyUsage                    = critical, digitalSignature
extendedKeyUsage            = codeSigning
certificatePolicies         = rotCodeSigningReleasePolicy

[ v3_rot_development_root ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:true
keyUsage                    = critical, keyCertSign, cRLSign
extendedKeyUsage            = nxpLpc55DebugAuthCredentialSigning
certificatePolicies         = rotCodeSigningDevelopmentPolicy

[ v3_code_signing_dev ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:false
keyUsage                    = critical, digitalSignature
extendedKeyUsage            = codeSigning
certificatePolicies         = rotCodeSigningDevelopmentPolicy

[ v3_identity ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:true
keyUsage                    = critical, keyCertSign, cRLSign
certificatePolicies         = critical, deviceIdentityPolicy, tcg-dice-kp-identityInit, tcg-dice-kp-attestInit, tcg-dice-kp-eca

[ OIDs ]
# https://github.com/oxidecomputer/oana#asn1-object-identifiers
rotCodeSigningReleasePolicy = 1.3.6.1.4.1.57551.1.1
rotCodeSigningDevelopmentPolicy = 1.3.6.1.4.1.57551.1.2
deviceIdentityPolicy = 1.3.6.1.4.1.57551.1.3
nxpLpc55DebugAuthCredentialSigning = 1.3.6.1.4.1.57551.2.1
tcg-dice-kp-identityInit = 2.23.133.5.4.100.6
tcg-dice-kp-attestInit = 2.23.133.5.4.100.8
tcg-dice-kp-eca = 2.23.133.5.4.100.12

"#
    };
}

/// Name of file in root of a CA directory with key spec used to generate key
/// in HSM.
const CA_KEY_SPEC: &str = "key.spec";

/// Name of file in root of a CA directory containing the CA's own certificate.
const CA_CERT: &str = "ca.cert.pem";

const CSRSPEC_EXT: &str = ".csrspec.json";
const DCSRSPEC_EXT: &str = ".dcsrspec.json";

#[derive(Error, Debug)]
pub enum CaError {
    #[error("Invalid path to CsrSpec file")]
    BadCsrSpecPath,
    #[error("Invalid path to DcsrSpec file")]
    BadDcsrSpecPath,
    #[error("Invalid path to KeySpec file")]
    BadKeySpecPath,
    #[error("Invalid purpose for root CA key")]
    BadPurpose,
    #[error("path not a directory")]
    BadSpecDirectory,
    #[error("failed to generate certificate")]
    CertGenFail,
    #[error("failed to create self signed cert for key")]
    SelfCertGenFail,
}

// TODO: address open questions:
// - when do we set the password (env)?
// - when do we start the connector?
pub struct Ca {
    root: PathBuf,
    spec: KeySpec,
}

// TryFrom is how we create a Ca from an existing directory path.
impl Ca {
    // TODO: sanity checks:
    // - is `root` a directory / does it exist
    // - are the files in `root` in the right place
    // - are the files complete / correct
    // minimum bar is directory, openssl.cnf and key.spec
    /// Create a Ca instance from a directory
    /// This directory must be the root of a previously initialized Ca
    pub fn load<P: AsRef<Path>>(root: P) -> Result<Self> {
        let root = PathBuf::from(root.as_ref());

        let spec = root.join("key.spec");
        let spec = fs::read_to_string(spec)?;
        let spec = KeySpec::from_str(spec.as_ref())?;

        Ok(Self { root, spec })
    }

    pub fn name(&self) -> String {
        self.spec.label.to_string()
    }

    // The path should not exist and we create everyting from the
    // provided keyspec.
    /// Create a new CA instance under `root` & initialize its metadata
    /// according to the provided keyspec. The `pkcs11_lib` is inserted into
    /// the generated openssl.cnf so openssl can find it. If the keyspec
    /// defines a root / selfsigned CA then the self signed cert will be
    /// written to the output path w/ name `$label.cert.pem`. If not then we
    /// create a CSR named `$label.csr.pem` instead.
    pub fn initialize<P: AsRef<Path>>(
        spec: KeySpec,
        root: P,
        pkcs11_lib: P,
        out: P,
    ) -> Result<Self> {
        // sanity check: no signing keys at CA init
        // this makes me think we need different types for this:
        // one for the CA keys, one for the children we sign
        match spec.purpose {
            Purpose::RoTReleaseRoot
            | Purpose::RoTDevelopmentRoot
            | Purpose::Identity => (),
            _ => return Err(CaError::BadPurpose.into()),
        }

        let pwd = std::env::current_dir()?;
        debug!("got current directory: {:?}", pwd);

        // setup CA directory structure
        let label = spec.label.to_string();
        let root = PathBuf::from(root.as_ref());
        let ca_dir = root.join(&label);
        fs::create_dir_all(&ca_dir)?;
        info!("Bootstrapping CA files for key with label: {}", &label);
        debug!("setting current directory: {}", ca_dir.display());
        std::env::set_current_dir(&ca_dir)?;

        // copy the key spec file to the ca state dir
        let spec_json = spec.to_json()
            .context("Failed to serialize KeySpec to json")?;
        fs::write("key.spec", spec_json)?;

        // create directories expected by `openssl ca`: crl, newcerts
        for dir in ["crl", "newcerts", "csr"] {
            debug!("creating directory: {}?", dir);
            fs::create_dir(dir)?;
        }

        // the 'private' directory is a special case w/ restricted permissions
        let priv_dir = "private";
        debug!("creating directory: {}?", priv_dir);
        fs::create_dir(priv_dir)?;
        let perms = Permissions::from_mode(0o700);
        debug!(
            "setting permissions on directory {} to {:#?}",
            priv_dir, perms
        );
        fs::set_permissions(priv_dir, perms)?;

        // touch 'index.txt' file
        let index = "index.txt";
        debug!("touching file {}", index);
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(index)?;

        // write initial serial number to 'serial' (echo 1000 > serial)
        let serial = "serial";
        let init_serial_hex = format!("{:020x}", spec.initial_serial_number);
        debug!(
            "setting initial serial number to \"{init_serial_hex}\" in file \"{serial}\""
        );
        fs::write(serial, init_serial_hex)?;

        // create & write out an openssl.cnf
        fs::write(
            "openssl.cnf",
            format!(
                openssl_cnf_fmt!(),
                key = spec.id,
                hash = spec.hash,
                pkcs11_path = pkcs11_lib.as_ref().display(),
            ),
        )?;

        // the connector must be running for the PKCS#11 module to work
        let mut connector = start_connector()?;
        passwd_to_env("OKM_HSM_PKCS11_AUTH")?;

        let csr = NamedTempFile::new()?;

        let mut cmd = Command::new("openssl");
        let output = cmd
            .arg("req")
            .arg("-config")
            .arg("openssl.cnf")
            .arg("-new")
            .arg("-subj")
            .arg(format!(
                "/C=US/O=Oxide Computer Company/CN={}/",
                spec.common_name
            ))
            .arg("-engine")
            .arg("pkcs11")
            .arg("-keyform")
            .arg("engine")
            .arg("-key")
            .arg(format!("0:{:04x}", spec.id))
            .arg("-passin")
            .arg("env:OKM_HSM_PKCS11_AUTH")
            .arg("-out")
            .arg(csr.path())
            .output()?;

        debug!("executing command: \"{:#?}\"", cmd);

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CaError::SelfCertGenFail.into());
        }

        let out = PathBuf::from(out.as_ref());
        if spec.self_signed {
            // sleep to let sessions cycle
            thread::sleep(Duration::from_millis(1500));

            //  generate cert for CA root
            info!("Generating self-signed cert for CA root");
            let mut cmd = Command::new("openssl");
            let output = cmd
                .arg("ca")
                .arg("-batch")
                .arg("-selfsign")
                .arg("-notext")
                .arg("-config")
                .arg("openssl.cnf")
                .arg("-engine")
                .arg("pkcs11")
                .arg("-keyform")
                .arg("engine")
                .arg("-keyfile")
                .arg(format!("0:{:04x}", spec.id))
                .arg("-extensions")
                .arg(spec.purpose.to_string())
                .arg("-passin")
                .arg("env:OKM_HSM_PKCS11_AUTH")
                .arg("-in")
                .arg(csr.path())
                .arg("-out")
                .arg("ca.cert.pem")
                .output()?;

            debug!("executing command: \"{:#?}\"", cmd);

            if !output.status.success() {
                warn!("command failed with status: {}", output.status);
                warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
                return Err(CaError::SelfCertGenFail.into());
            }

            let cert = out.join(format!("{}.cert.pem", label));
            fs::copy("ca.cert.pem", cert)?;
        } else {
            // when we're not generating a self signed cert we copy the csr
            // to the output directory so it can be certified through an
            // external process
            fs::copy(csr, out.join(format!("{}.csr.pem", label)))?;
        }

        // done w/ openssl cmds, kill connector
        connector.kill()?;

        env::set_current_dir(pwd)?;

        Ok(Self::load(ca_dir)?)
    }
}

/// Get password for pkcs11 operations to keep the user from having to enter
/// the password multiple times (once for signing the CSR, one for signing
/// the cert). We also prefix the password with '0002' so the YubiHSM
/// PKCS#11 module knows which key to use
fn passwd_to_env(env_str: &str) -> Result<()> {
    let mut password = Zeroizing::new("0002".to_string());
    let passwd = Zeroizing::new(match env::var(ENV_PASSWORD).ok() {
        Some(p) => p,
        None => rpassword::prompt_password("Enter YubiHSM Password: ")?,
    });
    password.push_str(&passwd);
    std::env::set_var(env_str, password);

    Ok(())
}

fn passwd_from_env(env_str: &str) -> Result<String> {
    Ok(std::env::var(env_str)?
            .strip_prefix("0002")
            .ok_or_else(|| anyhow!("Missing key identifier prefix in environment variable \"{env_str}\" that is expected to contain an HSM password"))?
            .to_string()
        )
}

/// Start the yubihsm-connector process.
/// NOTE: The connector dumps ~10 lines of text for each command.
/// We can increase verbosity with the `-debug` flag, but the only way
/// we can dial this down is by sending stderr to /dev/null.
fn start_connector() -> Result<Child> {
    debug!("starting connector");
    let child = Command::new("yubihsm-connector")
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .spawn()?;

    // Sleep for a second to allow the connector to start before we start
    // sending commands to it.
    std::thread::sleep(std::time::Duration::from_millis(1000));

    Ok(child)
}

pub fn sign_csrspec(
    csr_spec_path: &Path,
    tmp_dir: &TempDir,
    state: &Path,
    publish: &Path,
) -> Result<()> {
    // deserialize the csrspec
    debug!("Getting CSR spec from: {}", csr_spec_path.display());
    let json = fs::read_to_string(csr_spec_path)?;
    debug!("spec as json: {}", json);

    let csr_spec = CsrSpec::from_str(&json)?;
    debug!("CsrSpec: {:#?}", csr_spec);

    // get the label
    // use label to reconstruct path to CA root dir for key w/ label
    let key_spec = state.join(csr_spec.label.to_string()).join(CA_KEY_SPEC);

    debug!("Getting KeySpec from: {}", key_spec.display());
    let json = fs::read_to_string(key_spec)?;
    debug!("spec as json: {}", json);

    let key_spec = KeySpec::from_str(&json)?;
    debug!("KeySpec: {:#?}", key_spec);

    // sanity check: no signing keys at CA init
    // this makes me think we need different types for this:
    // one for the CA keys, one for the children we sign
    // map purpose of CA key to key associated with CSR
    let purpose = match key_spec.purpose {
        Purpose::RoTReleaseRoot => Purpose::RoTReleaseCodeSigning,
        Purpose::RoTDevelopmentRoot => Purpose::RoTDevelopmentCodeSigning,
        Purpose::Identity => Purpose::Identity,
        _ => return Err(CaError::BadPurpose.into()),
    };

    let publish = fs::canonicalize(publish)?;
    debug!("canonical publish: {}", publish.display());

    // pushd into ca dir based on spec file
    let pwd = std::env::current_dir()?;
    debug!("got current directory: {:?}", pwd);

    let ca_dir = state.join(key_spec.label.to_string());
    std::env::set_current_dir(&ca_dir)?;
    debug!("setting current directory: {}", ca_dir.display());

    // Get prefix from CsrSpec file. We us this to generate file names for the
    // temp CSR file and the output cert file.
    let csr_filename = match csr_spec_path
        .file_name()
        .ok_or(CaError::BadCsrSpecPath)?
        .to_os_string()
        .into_string()
    {
        Ok(s) => s,
        Err(_) => return Err(CaError::BadCsrSpecPath.into()),
    };
    let csr_prefix = match csr_filename.find('.') {
        Some(i) => csr_filename[..i].to_string(),
        None => csr_filename,
    };

    // create a tempdir & write CSR there for openssl: AFAIK the `ca` command
    // won't take the CSR over stdin
    let tmp_csr = tmp_dir.path().join(format!("{}.csr.pem", csr_prefix));
    debug!("writing CSR to: {}", tmp_csr.display());
    fs::write(&tmp_csr, &csr_spec.csr)?;

    let cert = publish.join(format!("{}.cert.pem", csr_prefix));
    debug!("writing cert to: {}", cert.display());

    // sleep to let sessions cycle
    thread::sleep(Duration::from_millis(2500));

    // execute CA command
    info!(
        "Generating cert from CSR & signing with key: {}",
        key_spec.label.to_string()
    );
    let mut cmd = Command::new("openssl");
    cmd.arg("ca")
        .arg("-batch")
        .arg("-notext")
        .arg("-config")
        .arg("openssl.cnf")
        .arg("-engine")
        .arg("pkcs11")
        .arg("-keyform")
        .arg("engine")
        .arg("-keyfile")
        .arg(format!("0:{:04x}", key_spec.id))
        .arg("-extensions")
        .arg(purpose.to_string())
        .arg("-passin")
        .arg("env:OKM_HSM_PKCS11_AUTH")
        .arg("-in")
        .arg(&tmp_csr)
        .arg("-out")
        .arg(&cert);

    debug!("executing command: \"{:#?}\"", cmd);
    let output = cmd.output()?;

    if !output.status.success() {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        return Err(CaError::CertGenFail.into());
    }

    std::env::set_current_dir(pwd)?;

    Ok(())
}

fn sign_dcsrspec(
    dcsr_spec_path: &Path,
    client: &Client,
    state: &Path,
    publish: &Path,
) -> Result<()> {
    let dcsr_spec_json =
        std::fs::read_to_string(dcsr_spec_path).with_context(|| {
            format!(
                "Failed to read DcsrSpec json from {}",
                dcsr_spec_path.display()
            )
        })?;
    let dcsr_spec: DcsrSpec = serde_json::from_str(&dcsr_spec_json)
        .context("Failed to deserialize DcsrSpec from json")?;

    let root_cert_paths = dcsr_spec
        .root_labels
        .iter()
        .map(|x| state.join(x.to_string()).join(CA_CERT))
        .collect::<Vec<PathBuf>>();
    let root_certs = lpc55_sign::cert::read_certs(&root_cert_paths)
        .context("Failed to get certs for DCSR root labels.")?;

    // Load signer's public key
    let mut signer_public_key = None;
    for (idx, label) in dcsr_spec.root_labels.iter().enumerate() {
        if *label == dcsr_spec.label {
            if let Some(x) = root_certs.get(idx) {
                signer_public_key = Some(lpc55_sign::cert::public_key(x)?)
            }
        }
    }
    let signer_public_key = signer_public_key.ok_or_else(|| {
        anyhow!(
            "DcsrSpec label \"{}\" must also be one of the root labels",
            dcsr_spec.label
        )
    })?;

    // Load signing key's KeySpec
    let key_spec = state.join(dcsr_spec.label.to_string()).join(CA_KEY_SPEC);

    debug!("Getting KeySpec from: {}", key_spec.display());
    let json = fs::read_to_string(key_spec)?;
    debug!("spec as json: {}", json);

    let key_spec = KeySpec::from_str(&json)?;
    debug!("KeySpec: {:#?}", key_spec);

    // Get prefix from DcsrSpec file. We us this to generate file names for the
    // output file.
    let dcsr_filename = match dcsr_spec_path
        .file_name()
        .ok_or(CaError::BadDcsrSpecPath)?
        .to_os_string()
        .into_string()
    {
        Ok(s) => s,
        Err(_) => return Err(CaError::BadCsrSpecPath.into()),
    };
    let dcsr_prefix = match dcsr_filename.find('.') {
        Some(i) => dcsr_filename[..i].to_string(),
        None => dcsr_filename,
    };

    // Construct the to-be-signed debug credential
    let dc_tbs = lpc55_sign::debug_auth::debug_credential_tbs(
        root_certs,
        signer_public_key,
        dcsr_spec.dcsr,
    )?;

    // Sign it using the private key stored in the HSM.
    let dc_sig = client.sign_rsa_pkcs1v15_sha256(key_spec.id, &dc_tbs)?;

    // Append the signature to the TBS debug credential to make a complete debug
    // credential
    let mut dc = Vec::new();
    dc.extend_from_slice(&dc_tbs);
    dc.extend_from_slice(&dc_sig.into_vec());

    // Write the debug credential to the output directory
    let dc_path = publish.join(format!("{}.dc.bin", dcsr_prefix));
    debug!("writing debug credential to: {}", dc_path.display());
    std::fs::write(dc_path, &dc)?;

    Ok(())
}
