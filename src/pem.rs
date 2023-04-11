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
pub(crate) fn read_certificates<B: AsRef<[u8]>>(bytes: B) -> Result<Vec<Vec<u8>>, Error> {
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
pub(crate) fn read_one_certificate<B: AsRef<[u8]>>(bytes: B) -> Result<Vec<u8>, Error> {
    let mut certs = read_certificates(bytes)?.into_iter();

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
pub(crate) struct PrivateKey(Vec<u8>);

impl PrivateKey {
    /// PEM tags that are supported for encrypted private keys
    const ALLOWED_ENCRYPTED_KEY_TAGS: &'static [&'static str] = &["ENCRYPTED PRIVATE KEY"];
    /// PEM tags that are supported for plain-text private keys
    const ALLOWED_PLAINTEXT_KEY_TAGS: &'static [&'static str] =
        &["PRIVATE KEY", "BEGIN RSA PRIVATE KEY"];

    /// The underlying vector of bytes
    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// Try to read a private key from a PEM file that may also contain certificate data. This method
    /// will extract plaintext private keys denoted by 'PRIVATE KEY' or 'BEGIN RSA PRIVATE KEY' (PKCS #1)
    /// PEM sections.
    ///
    /// This method ensures that only 1 private key file is present in a possibly multi-section PEM file
    pub(crate) fn read_from_pem<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        let sections = pem::parse_many(bytes)?;
        let key = Self::find_only_content_with_tags(&sections, Self::ALLOWED_PLAINTEXT_KEY_TAGS)?;
        Ok(Self(key.to_vec()))
    }

    /// Try to decrypt a private key from a PEM file. This method expects the PEM to contain a section
    /// with 'ENCRYPTED PRIVATE KEY' with a PKCS #8 encrypted private key.
    ///
    /// This method ensures that only 1 private key file is present in a possibly multi-section PEM file
    pub(crate) fn decrypt_from_pem<B: AsRef<[u8]>, S: AsRef<[u8]>>(
        bytes: B,
        password: S,
    ) -> Result<Self, Error> {
        let sections = pem::parse_many(bytes)?;
        let data = Self::find_only_content_with_tags(&sections, Self::ALLOWED_ENCRYPTED_KEY_TAGS)?;
        let parsed = pkcs8::EncryptedPrivateKeyInfo::try_from(data)?;
        let document = parsed.decrypt(password.as_ref())?;
        Ok(Self(document.as_bytes().to_vec()))
    }

    // find the
    fn find_only_content_with_tags<'a>(
        sections: &'a [pem::Pem],
        allowed_tags: &'static [&'static str],
    ) -> Result<&'a [u8], Error> {
        let mut iter = sections.iter();
        let first = match iter.find(|x| allowed_tags.contains(&x.tag())) {
            Some(x) => x,
            None => return Err(ErrorDetails::NoPrivateKey.into()),
        };

        // make sure there are not other sections that match the allowed tags
        if iter.any(|x| allowed_tags.contains(&x.tag())) {
            return Err(ErrorDetails::MoreThanOnePrivateKey.into());
        }

        Ok(first.contents())
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

    #[test]
    fn can_decrypt_pkcs8_key() {
        let key = PrivateKey::decrypt_from_pem(TEST_KEY, "foobar").unwrap();

        let decrypted = pem::parse(DECYPTED_KEY).unwrap();
        assert_eq!(key.into_inner().as_slice(), decrypted.contents());
    }
}
