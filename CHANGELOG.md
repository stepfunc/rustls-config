# 0.4.0
* :wrench: Make `ring` or `aws-lc-rs` configurable via features

# 0.3.2
* :wrench: Switch back to `ring` because of build complications on embedded platforms.

# 0.3.1
* :wrench: Remove dependency on `ring`.

# 0.3.0
* :wrench: Upgrade to rustls 0.23 which uses `aws-lc` instead of `ring`.

# 0.2.0
* :wrench: Upgrade to rustls 0.22 and refactor how the custom name verifiers work. See [#3](https://github.com/stepfunc/rustls-config/pull/3).
* :mag: Add integration tests with test certificates

# 0.1.2
Update to rustls-webpki 0.101.3