# Description

Configuration routines for [rustls](https://github.com/rustls/rustls) used by Step Function's commercial [DNP3](https://github.com/stepfunc/dnp3)
and [Modbus](https://github.com/stepfunc/rodbus) libraries.

# Usage

Enable exactly one crypto provider, `crypto-ring` or `crypto-aws-lc`:

```toml
[dependencies]
sfio-rustls-config = { version = "0.4", features = ["crypto-ring"] }
```

Requires Rust 1.85 or later.