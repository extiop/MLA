# Migration guide older MLA versions

This guide can help you upgrade code through breaking changes from one MLA version to the next. For a detailed list of all changes, see the [CHANGELOG](https://github.com/ANSSI-FR/MLA/blob/main/CHANGELOG.md).

## from 1.* to 2.0.0

### Deprecation of MLA 1

- MLA 2 is now the default and is incompatible with MLA 1.
- MLA 1 enters low maintenance mode (no new features, only critical bug fixes).

### Generate new keys

MLA 2 introduces a new archive format and signature functionality. You must generate new keys:

```sh
mlar keygen sender
mlar keygen receiver
```

Note: if you don't need signatures (not recommended), see [mlar integration tests](https://github.com/ANSSI-FR/MLA/blob/main/mlar/tests/integration.rs#L201) for bypass examples.

### Upgrade your archives

`mlar-upgrader` is a CLI utility for upgrading [MLA](https://github.com/ANSSI-FR/MLA) archives from version 1 to version 2. It reads a legacy MLA v1 archive, optionally decrypts it using provided private keys, and writes a new MLA v2 archive, optionally re-encrypting it with specified MLA v2 public keys.

**Important notes**

- Hash changes: upgrading an archive modifies its hash.
- Archives upgraded to v2 cannot be opened with MLA 1 tools. Always keep a backup of your v1 archives until your entire workflow uses MLA 2 only.
- Use cases and recommandations:

| Use Case                     | Recommendation                                                                 |
|------------------------------|-------------------------------------------------------------------------------|
| Archive is frequently edited | Upgrade to v2 and use only MLA 2 tools (`mlar 2.0.0`).                  |
| Archive is read-only         | Keep both v1 and v2 archives. Use `mlar list -vv` to compare file hashes.   |
| Mixed usage (read/write)     | Upgrade to v2 but keep v1 tools (`mlar 1.4.0`) for backward compatibility.  |

Full documentation: [mlar-upgrader usage](https://github.com/ANSSI-FR/MLA/tree/main/mlar/mlar-upgrader#usage).

### mlar utility

`mlar repair` command got renamed to `mlar clean-truncated`. It also got fixed regarding to [issue #226](https://github.com/ANSSI-FR/MLA/issues/226).

### API

MLA 2 introduces signifiant API changes for archive creation, encryption and signature handling. Here is an example of an archive creation with compression, encryption and signature:

```rust
use mla::ArchiveWriter;
use mla::config::ArchiveWriterConfig;
use mla::crypto::mlakey::{MLAPrivateKey, MLAPublicKey};
use mla::entry::EntryName;
// for encryption
const RECEIVER_PUB_KEY: &[u8] =
    include_bytes!("../../samples/test_mlakey_archive_v2_receiver.mlapub");
// for signing
const SENDER_PRIV_KEY: &[u8] =
    include_bytes!("../../samples/test_mlakey_archive_v2_sender.mlapriv");

fn main() {
    // For encryption, load the needed receiver public key
    let (pub_enc_key, _pub_sig_verif_key) = MLAPublicKey::deserialize_public_key(RECEIVER_PUB_KEY)
        .unwrap()
        .get_public_keys();
    // For signing, load the needed sender private key
    let (_priv_dec_key, priv_sig_key) = MLAPrivateKey::deserialize_private_key(SENDER_PRIV_KEY)
        .unwrap()
        .get_private_keys();
    // In production, you may want to zeroize the real `SENDER_PRIV_KEY` or
    // associated temporary values of its `Read` implementation here.
    // Create an MLA Archive - Output only needs the Write trait.
    // Here, a Vec is used but it would tipically be a `File` or a network socket.
    let mut buf = Vec::new();
    // The use of multiple keys is supported
    let config =
        ArchiveWriterConfig::with_encryption_with_signature(&[pub_enc_key], &[priv_sig_key])
            .unwrap();
    // Create the Writer
    let mut mla = ArchiveWriter::from_config(&mut buf, config).unwrap();
    // Add a file
    // This creates an entry named "a/filename" (without first "/"), See `EntryName::from_path`
    mla.add_entry(
        EntryName::from_path("/a/filename").unwrap(),
        4,
        &[0, 1, 2, 3][..],
    )
    .unwrap();
    // Complete the archive
    mla.finalize().unwrap();
}
```

For more documentation see [quick API usage](https://docs.rs/mla/2.0.0-beta/mla/#quick-api-usage).

### Bindings

#### C/C++

MLA 2 introduces signifiant API changes for archive creation, encryption and signature handling. Updated examples to read and write an MLA on Linux and Windows [can be found here](https://github.com/ANSSI-FR/MLA/tree/main/bindings/C#examples).

Full documentation: [MLA's C/C++ API](https://github.com/ANSSI-FR/MLA/tree/main/bindings/C#api).

#### Python

MLA 2 introduces two major changes in the Python bindings:
- `MLAFile` split: this class got split into `MLAReader` and `MLAWriter`, see [usage example](https://github.com/ANSSI-FR/MLA/tree/main/bindings/python#usage-example).
- Free-threaded by default: hence if your code requires the GIL, add `#[pymodule(gil_used = true)]` to your module (see [PyO3 migration guide](https://pyo3.rs/main/migration.html)).

Also, MLA 2 now includes stub files (`.pyi`) for better IDE support (type checking, autocompletion).

### Fuzzing

MLA's harness, has been updated for MLA 2, with improvements. To implement yours, we advice you to start from [ours](https://github.com/ANSSI-FR/MLA/blob/6a08b16c1f132e8ce5d92f047f711d56afcc277e/mla-fuzz-afl/src/main.rs).

### Format

If you implemented MLA 1’s format, update your code for MLA 2 as MLA 2 introduces several updated and new notions, notably:
- MLA options (`TLVOpt`): support for custom archives options.
- MLA entry name: filesystem path normalization.
- MLA key format update: support hybrid and signature algorithms.

Full documentation:
- [Format](https://anssi-fr.github.io/MLA/FORMAT.html)
- [Entry name](https://anssi-fr.github.io/MLA/ENTRY_NAME.html)
- [MLA Key Format](https://anssi-fr.github.io/MLA/KEY_FORMAT.html)