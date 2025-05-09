use rustls_pki_types::PrivateKeyDer;

pub(crate) fn read_certificates(
    path: &std::path::Path,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, crate::Error> {
    let bytes = std::fs::read(path)?;
    let certs = read_certificates_from_bytes(bytes)?;
    Ok(certs.into_iter().map(|x| x.into()).collect())
}

pub(crate) fn read_one_cert(
    path: &std::path::Path,
) -> Result<rustls::pki_types::CertificateDer<'static>, crate::Error> {
    let bytes = std::fs::read(path)?;
    let cert = read_one_certificate_from_bytes(bytes)?;
    Ok(cert.into())
}

pub(crate) fn read_private_key(
    path: &std::path::Path,
    password: Option<&str>,
) -> Result<PrivateKeyDer<'static>, crate::Error> {
    let bytes = std::fs::read(path)?;
    let key = match password {
        Some(x) => PrivateKey::decrypt_from_pem(bytes, x)?,
        None => PrivateKey::read_from_pem(bytes)?,
    };

    Ok(key.into_inner())
}

/// Error type used by the library that implements [`std::error::Error`]
#[derive(Debug)]
pub(crate) struct Error {
    details: ErrorDetails,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.details {
            ErrorDetails::InvalidPem(err) => write!(f, "PEM error: {}", err),
            ErrorDetails::DecryptionError(err) => write!(f, "PKCS#8 error: {}", err),
            ErrorDetails::NoPrivateKey => {
                f.write_str("PEM file does not contain a supported private key")
            }
            ErrorDetails::MoreThanOnePrivateKey => {
                f.write_str("PEM file contains more than one supported private key")
            }
            ErrorDetails::MoreThanOneCertificate => {
                f.write_str("PEM file contains more than one certificate")
            }
            ErrorDetails::NoCertificate => f.write_str("PEM file does not contain a certificate"),
        }
    }
}

impl std::error::Error for Error {}

/// Errors that can occur
#[derive(Debug)]
enum ErrorDetails {
    /// Invalid PEM file
    InvalidPem(pem::PemError),
    /// Bad PKCS #8 format or decryption failure
    DecryptionError(pkcs8::Error),
    /// PEM file does not contain a recognized private key format
    NoPrivateKey,
    /// PEM file contains more than one private key
    MoreThanOnePrivateKey,
    /// PEM file contains more than one certificate
    MoreThanOneCertificate,
    /// PEM file does not contain at least one certificate
    NoCertificate,
}

/// Read at least 1 certificate from a PEM file
fn read_certificates_from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Vec<Vec<u8>>, Error> {
    let entries: Vec<pem::Pem> = pem::parse_many(bytes)?;

    let certs: Vec<Vec<u8>> = entries
        .into_iter()
        .filter_map(|x| {
            if x.tag() == "CERTIFICATE" {
                Some(x.contents().to_vec())
            } else {
                None
            }
        })
        .collect();

    if certs.is_empty() {
        return Err(ErrorDetails::NoCertificate.into());
    }

    Ok(certs)
}

/// Read a single certificate from the PEM file. If none or more than 1 is present, an error is
/// returned
fn read_one_certificate_from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Vec<u8>, Error> {
    let mut certs = read_certificates_from_bytes(bytes)?.into_iter();

    let first = match certs.next() {
        Some(x) => x,
        None => return Err(ErrorDetails::NoCertificate.into()),
    };

    if certs.next().is_some() {
        return Err(ErrorDetails::MoreThanOneCertificate.into());
    }

    Ok(first)
}

/// Private key read from a plaintext or encrypted PEM file
struct PrivateKey(PrivateKeyDer<'static>);

impl PrivateKey {
    const ENCRYPTED_PRIVATE_KEY: &'static str = "ENCRYPTED PRIVATE KEY";
    const PRIVATE_KEY: &'static str = "PRIVATE KEY";
    const RSA_PRIVATE_KEY: &'static str = "RSA PRIVATE KEY";

    /// The underlying rustls type
    fn into_inner(self) -> PrivateKeyDer<'static> {
        self.0
    }

    /// Try to read a private key from a PEM file that may also contain certificate data. This method
    /// will extract plaintext private keys denoted by 'PRIVATE KEY' or 'RSA PRIVATE KEY' (PKCS #1)
    /// PEM sections.
    ///
    /// This method ensures that only 1 private key file is present in a possibly multi-section PEM file
    fn read_from_pem<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        let sections = pem::parse_many(bytes)?;

        let mut key: Option<Self> = None;

        for section in sections {
            match section.tag() {
                Self::PRIVATE_KEY => {
                    if key.is_some() {
                        return Err(ErrorDetails::MoreThanOnePrivateKey.into());
                    }
                    key = Some(Self(PrivateKeyDer::Pkcs8(
                        section.contents().to_vec().into(),
                    )))
                }
                Self::RSA_PRIVATE_KEY => {
                    if key.is_some() {
                        return Err(ErrorDetails::MoreThanOnePrivateKey.into());
                    }
                    key = Some(Self(PrivateKeyDer::Pkcs1(
                        section.contents().to_vec().into(),
                    )))
                }
                _ => {}
            }
        }

        match key.take() {
            None => Err(ErrorDetails::NoPrivateKey.into()),
            Some(k) => Ok(k),
        }
    }

    /// Try to decrypt a private key from a PEM file. This method expects the PEM to contain a section
    /// with 'ENCRYPTED PRIVATE KEY' with a PKCS #8 encrypted private key.
    ///
    /// This method ensures that only 1 private key file is present in a possibly multi-section PEM file
    fn decrypt_from_pem<B: AsRef<[u8]>, S: AsRef<[u8]>>(
        bytes: B,
        password: S,
    ) -> Result<Self, Error> {
        let sections = pem::parse_many(bytes)?;

        let mut encrypted: Option<Vec<u8>> = None;

        for section in sections {
            if section.tag() == Self::ENCRYPTED_PRIVATE_KEY {
                if encrypted.is_some() {
                    return Err(ErrorDetails::MoreThanOnePrivateKey.into());
                }
                encrypted = Some(section.contents().to_vec())
            }
        }

        let encrypted = match encrypted.take() {
            None => return Err(ErrorDetails::NoPrivateKey.into()),
            Some(x) => x,
        };

        let parsed = pkcs8::EncryptedPrivateKeyInfo::try_from(encrypted.as_slice())?;
        let document = parsed.decrypt(password.as_ref())?;
        let key = PrivateKeyDer::Pkcs8(document.to_bytes().to_vec().into());
        Ok(Self(key))
    }
}

impl From<pem::PemError> for Error {
    fn from(err: pem::PemError) -> Self {
        Error {
            details: ErrorDetails::InvalidPem(err),
        }
    }
}

impl From<pkcs8::Error> for Error {
    fn from(err: pkcs8::Error) -> Self {
        Error {
            details: ErrorDetails::DecryptionError(err),
        }
    }
}

impl From<ErrorDetails> for Error {
    fn from(details: ErrorDetails) -> Self {
        Error { details }
    }
}

#[cfg(test)]
mod test {
    use super::PrivateKey;
    use rustls::pki_types::PrivateKeyDer;

    const TEST_KEY: &str = r#"
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFJTBPBgkqhkiG9w0BBQ0wQjAhBgkrBgEEAdpHBAswFAQIu0Ufk06Ty+ICAkAA
AgEIAgEBMB0GCWCGSAFlAwQBKgQQIP2MoQA/IuQ9YgoLJAHEnQSCBNBMF6XHpHn8
lKR0MfyeCPi1bGgpp39c6s3he9WdB57Z9r9SLrACbdMeLzOfbr5hF2JmCYk0T7Us
p6s20q5tiwd9zDWAHbGKOnzpVlLJhhz4GvfaTVt6K0onPt7Y3mfB9P44G3p3j83Z
3Ekg784DH26gYgIYK8uo0PNnBZbuoVTiBdj2BtsJpBysoztPeCEbF6xjw4p8obEo
YYOH2djLOfWipr0iqIdX6IAPQ/zKjAkZHy1VwEYcSmE5YS6UbzUkzFGEt4tV9RYJ
4ctJO2PVpFvmdmVvYCrzJI6BHX0a1AYd5FV/j+2Hd/wnRhp2srLv/rsYHF/J6VK0
E6FuLjLDHcG4TthQSlGJ/ewT6xiSZ7HdDn3BJfOJR9d9V8f+FfpEVL55lzPOh9Fl
Ad8cNClliziJCgkAJ7MhUenNwTnxOQYrnVDDUMTNYEiK6EoUWlSDbLp13n/uhmaw
huXvfLAMSmfJvWAEcnXn7X+/mHkEMWtrZkvHg2yDfyTk/8ZtRIw25+hp6MOBpbtn
7py2QlefjDMa5wAQGqACVNkMFUzEpNBNh1hj3CHBYdE1Jo5dyZPFcuGWY8ye75RI
F3Lq/z3NqbaebPUmXlpLh0YSvpyoZJM+Knr6bCGWj1Ik3oq0+gqbGmPQKULpmdkz
5JgD0TsD/yQL6Ldm1KMzhJmwovH25YIxcrbGmlQ2658XGNS/3kPR0UbdIgR4unWz
XcwV75HKT4Rc0E0fAYKzFVE9J08aQawhNKbaGGc8zNQiz9tGSVvpO3OLf35tHoPz
eRs4flWGR/b/seGeEcVzeO5RDNDxXblfoSc/gB7lPdA35ig9z6egQvUyJrmIUhGa
lRKg9UeXsT2gZZHZPCaYekWacBtNWYKzdrdgSHxxKkjvF/tWKxE62RaWzuwqs0qK
tEa7RBKwe+wYRp4KVWe15XO5dvfYYtGkza70QYhQw86foAtYHpI6nMv4ppBf/vkD
mcivoGnImRMGlt1Klo1I3VjKI3lvms9UpmNuI35THwxnz5O1aCvS1pBvXEs+D95y
4qvhVkcbYMF3anxgn0ZD+3LYTxWuPbRBxh6GxC4qbn9tPHtN/7Iop7pSqaQMBFt2
1pe/PuGpiswQY3mtU3WLVP4pC0Mu5KDShswRQmI7XLOIjQgT5ac3JrFogqgkX+rb
9ZS7jHDBNY7eGsI7sLiMVRnHltiOOwhBHu9+NAwi1jmJIvSPLJzf/MW6rRnpg10D
pHC/LdUlon31MBb5kqpidhQa1LD9gWzesMLq3DMkUbTAbY0sddSP8XkUidLsZEMx
mjmaNlfKhLNE0N7o59t40+l3W2bghnsd/VC9fZL66ShSISe3bzHjnJklpLNHhl3/
gFwoMvSG8u6Aboz5QfXFS5HliIf5Fnw8ed+deEb5z3fiSpKi0PbcVRzQWotzG152
FKueCGIlqyTzlh7j8wY8tnChbY/34kIGFUDtKQcAjR6mLSi80s53dBG/lIZAEsG5
P1x3xO3fzO5w9X5yrRxGnN6N6McMqTkF1V4DhUfwrb41QBR2UBdbed126ZhM52fc
9We9YmUyRcV38yXPJ6SB6I9xdNIa5Nv4tB/7DzvpaRS6FBUPVm+VsULxc2XIjHGp
LOCHvWcZO49jGhZErBtxk16H58koZVg5Zw==
-----END ENCRYPTED PRIVATE KEY-----"#;

    const DECYPTED_KEY: &str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDOX/fVrsEE5ihY
BIi97q2u1j7lMx+3plyDBOzjK7uovVtmGadtmfLxtRvrFYG4tdUNZ6svhiFvutNW
GQxT4RWw//UkhnS3Znh+VhR0C4qsrMARP3svugFqLkwqS36jWLAy3bvVXlkxsKKi
Tjf5DQwrgM2s6s7QBYMJNN8+jBsYlZXf+5bUN4pFk6vSU7NFPZUSBZ/u3rSa4mR6
aD0QRMEYW4+fjj7+g+aZgUHHQT8Cz1FKCAbHSgVugOVC7Pwn3L9ozH2RC/cQdDhD
Arq+P1o7+4YyYG12bp/D5lFu+kdT6p0mHSx6l11sEAEIUGGeI/685K3GwZ4t2ip0
qQ+/xbVdAgMBAAECggEBAJjq8WgrWii4JjK6AVzDK3z+kZIhpKHfKnOGxcS6lg29
aako3y/OP/8r1KkHwZxNV7XcGDNZrxLsG0aTvte0U+9YaZwL6RYwXp42SGeIWdQD
GTpukGfX6s5zycoZMJf20nCObmz2wR6ZpJihXsYzDc56XWyAfIgVXXgH7leZV0aJ
08pEv0kAHGZSrxHGBT3n6+wrkHduTZ89Wx3kubwJRiRtHp8IdNhNoxlN44e5uizu
7ix6k/pg5TDaXOwsp4cE8SQ3zUa+kvazX693sCZdhCKlmrwYP9WZCAWLAy8sRFM+
SAj2cNWva1LL/hE3pgrCg4BV9zmr0UFMSLJxdcDAQZ0CgYEA69qUzzWU8KIKmXf5
J7yWKbUftXwIn4DrlabrpeWCYsvxfNsZWYEc+8VqZDczwwI2nf9useXQhfxH7VSc
q5d20ApNY3hHemp6s1p9224oj/6rKJtPBOdSIyAs1cOjNYK+YXcVjYlWHvHBpraL
ct2vo8yTkPkLAOJEqckPbadkVFsCgYEA4ADFJACr1uDK2aMqjR2fEz2GBm+om7j0
Omj6STyHuYxb4wlUzC58sqtNVXGTVB+ha1HZT+DM7NHkCtEQLN2dqVrFCgv39MzI
huxD59j0hsVrqnK23JswgsiJar8AUiEe2MY/ysgHVuUtkDzKEN+bgcVhqap0sn4C
q19oOcA/aqcCgYAefhcJJxtHdRu7tbgfvBEJ+WHNG+kdfhR3N6p1u1N9JHLnOohv
evLdViuoIz7s8mdPTAvqshSgjfpao7rRsHZq9ToGJzHOkN+mOofVC8vwufM0/8da
kfGbmvhQ9scuDuZAQZ4mu1/IBmeL/0POKP0hRzy43IngpmBMNzNocODWywKBgC/b
ukLw6cXlDTHmjIbN11jTAjmJzapHn9aC60aOaikYdeFR8w4UuIur0b/5nhKRF3nI
aPeJ/f5y8ZfmBuCvEKpIPGTjHbztq8I35GI6ljPdJh2qmKsVdQ3cLo/h8v2ZGfAS
mzqF9ht4p31zn3BvddgKBc2sH3arOYLHxYrhKittAoGAIpHK6rYu3O/1eF5Nimok
fRpT+FVOxgRX9fBL6IBuYzZPvtDfhq1kgzOYBo1oW+ObaF9BnFvYdE2CEX8Gr0+Z
s6psX64trGW6DcgvM8bQtQa1EfRSp/EifPGwa5tzPw0UVF/VdpFa9Lum7cAjTDsm
jKIQUja2I9E99ZWstIdBCUE=
-----END PRIVATE KEY-----"#;

    const RSA_PRIVATE_KEY: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA3yFfiZ3YoKZS2MM9iyiI1c2GBzUVcHEvMV/F542Y+HzO6CXu
uI5Fcm9mPN9qNogQh0QMHXPPPjFGzWh69b6tzxhZtYJ4MJvNlet79ydXVtjguuA6
weTuTkflSw5vMCST856jHXzxJS56CC6/vNZ5XRalkbt0feOVAKFQPqFjfUZufG6B
t+TCUKs8waHWWbalw2cs8zzlVXWpx7qpM5VGuIF02U5DQgAXj0V3bFZvj+i1ev9c
9dOMBKc6J5RDTEsIl8lkPBO5PnwMtenzW+9Bx3XESg4FEO+U15j0lApk8jCFJx3i
YLBkqA+1qAJZS4C0SwdW/pt3ziivbdfXK2BB4wIDAQABAoIBAQDHLN5AVNOby/xm
HBoiz0MePwDmDB+gKJis5UYexUoIfjigB8RJoE4jsYc8zV3dYaYHaNm7rLYRWSFP
mHUySkyScbUajmVFVr60lekpnUeccaphhmlMzVNgM1NdpXvhKLWdIT2PxAjqXMt3
5GspYPYi/2U6am+5NF68mkKsNZo+puXToE46bMQ6TZ2voPj9Vzdjs0ToOy+Etzi+
JGGhsy0x903ufyiGzGXxNlK3LSYXYxjGlKcHVTYyzCi2/btKt2fu/uiT+NxeCJQU
F4W4kyjrMWSoY2Vn2gaWeZFca/KV5zhxBTEu2xxWOngXxAfN3NUzr4JWUs7fn1Dm
ljooF8nxAoGBAP5TODs/n54GvD3TlQtnwN5mBWHAWeS6yNm8nrMDAAKPkk8bOWZi
qgPf1GFfWVNzWy5qhYvihNv3qr9Lq3E8uqG+gZ9blWSA32lvycmn+5Tz7bB8eJlv
xe5kMPaO8jZ+3NdiKausH3M3TF2XlHsh/4enUA2MekZsQjWhpz3iH2F5AoGBAOCZ
j4mUyvctJ0INW3mLwgHwFHaA7GTzVpPMKPa4CvRl5fivC5FtFFHp5SWEh0AAR1p7
r5GY6gY+oD6vH6MriWf0QTGctRl2w8fS2/14T9yr/1mffJnHFmlSAyguwccFKX4h
mGipVgqZ2IJf58oM73C8iJK0fs7DXbBNEREFS2M7AoGBANh/JTYikhEm8KW88Hq2
BtQLivdMk/mHG6Vm0L3YhvCnIUhgB3vl746+wn9leJf2ch9QJIERAkJyUZLoqngJ
12IK1zM99i2JGyYZOHCGpD6Ha8Y6HzuWj6rA9YFd7EiBtCNRd+Gg82DUKRjfCVHM
fkcPIbF27Tv3umEHTGP8kvQZAoGABxgSlo/ikUgV01pEp2QorpL8snmD/fRJqcVr
Dc/mWK3XQ7GTtfYyDBxNJpA3DWh02IDLnNetnKDhwtkZMLgxUN1AKeb/OVys9mTM
mgbwztGH8Ta+YsUNCiqS+vPvHvAkzV0WSUf/9bnCQuvwkEs0TOVHkwqsbq9xCB6H
CXiXVv0CgYEA8neRBeiqO7337GrS+n456bvcQaBZhsrIpOE7+lCtMgTt5PTIIIDg
zMeBzj4b4shWrRaiOKoQop5QXWazx4Ma14PehEK8WXgqlHvaD6FMZF432DlpiApC
cr+jfC1zzDLXwxa69QcwOcFGkxtsl9QPToviY4+5PcjU5+ioaA7Hw14=
-----END RSA PRIVATE KEY-----"#;

    #[test]
    fn can_decrypt_pkcs8_key() {
        let key = PrivateKey::decrypt_from_pem(TEST_KEY, "foobar").unwrap();

        let decrypted = pem::parse(DECYPTED_KEY).unwrap();
        assert_eq!(key.into_inner().secret_der(), decrypted.contents());
    }

    #[test]
    fn can_read_pkcs1_key() {
        let key = PrivateKey::read_from_pem(RSA_PRIVATE_KEY).unwrap();
        assert!(std::matches!(key.into_inner(), PrivateKeyDer::Pkcs1(_)));
    }
}
