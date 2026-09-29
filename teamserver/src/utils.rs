use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::fs;
use std::path::Path;
use anyhow::Result;

pub fn get_or_generate_self_signed(cert_path: &str, key_path: &str, common_name: &str) -> Result<()> {
    if Path::new(cert_path).exists() && Path::new(key_path).exists() {
        return Ok(());
    }

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName(common_name.to_string().try_into()?)];

    let keypair = KeyPair::generate()?;
    let cert = params.self_signed(&keypair)?;

    fs::write(cert_path, cert.pem())?;
    fs::write(key_path, keypair.serialize_pem())?;

    Ok(())
}
