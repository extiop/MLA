use clap::{Arg, ArgAction, ArgMatches, value_parser};
use std::fs::{self, File, Permissions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, error, fmt, io};

static MLAR1_BIN: &[u8] = include_bytes!("../assets/bin/mlar1.3.0");
static MLAR2_BIN: &[u8] = include_bytes!("../assets/bin/mlar2.0.0");

// ----- Error ------

#[derive(Debug)]
pub enum MlarError {
    /// IO Error (not enough data, etc.)
    IOError(io::Error),
}

impl fmt::Display for MlarError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // For now, use the debug derived version
        write!(f, "{self:?}")
    }
}

impl From<io::Error> for MlarError {
    fn from(error: io::Error) -> Self {
        Self::IOError(error)
    }
}

impl error::Error for MlarError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Self::IOError(err) => Some(err),
        }
    }
}

// ----- Utils ------

fn add_v2_suffix(path: &Path) -> PathBuf {
    let file_stem = path.file_stem().unwrap().to_string_lossy(); // e.g., "test_x25519_archive_blabla"
    let extension = path.extension().map(|ext| ext.to_string_lossy());

    // Add "_v2" to the stem
    let new_file_name = extension.map_or_else(
        || format!("{file_stem}_v2"),
        |ext| format!("{file_stem}_v2.{ext}"),
    );

    // Combine with the original directory
    path.with_file_name(new_file_name)
}

fn create_temp_dir(prefix: &str) -> io::Result<PathBuf> {
    // Use system temp dir as base
    let mut base = env::temp_dir();

    // Create a unique suffix using current time
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let unique_id = since_epoch.as_millis();

    // Build directory path like /tmp/mlar-upgrade-1715431868941
    base.push(format!("{prefix}{unique_id}"));

    fs::create_dir_all(&base)?;
    Ok(base)
}

fn get_files_in_dir(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        // Only include regular files
        if path.is_file() {
            files.push(path);
        }
    }

    Ok(files)
}

fn write_binary(name: &str, data: &[u8]) -> std::io::Result<PathBuf> {
    // Write to the system's temp directory
    let mut path = env::temp_dir();
    path.push(name);

    let mut file = File::create(&path)?;
    file.write_all(data)?;

    // Make the binary executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = Permissions::from_mode(0o755);
        fs::set_permissions(&path, perm)?;
    }

    #[cfg(windows)]
    {
        // On Windows, .exe files generally don't need manual permission changes
    }

    Ok(path)
}

// ----- Commands ------

fn upgrade(matches: &ArgMatches) -> Result<(), MlarError> {
    let mlar1_path = write_binary("mlar1.3.0", MLAR1_BIN)?;
    let mlar2_path = write_binary("mlar2.0.0", MLAR2_BIN)?;
    let temp_dir = create_temp_dir("mlar-upgrade-")?;

    // Extract the arguments
    let input = matches
        .get_one::<PathBuf>("input")
        .expect("Input path is required");
    let output = matches
        .get_one::<PathBuf>("output")
        .expect("Output path is required");
    let private_keys = matches
        .get_one::<PathBuf>("private_keys")
        .expect("Private key is required");

    let private_keys_v2 = add_v2_suffix(private_keys).with_extension("der");

    // use mlar1
    // extract input archive content to a temporary directory
    // mlar1 extract -k pkey -i archive.mla -o temp_dir
    let status1 = Command::new(&mlar1_path)
        .arg("extract")
        .arg("-k")
        .args(private_keys)
        .arg("-i")
        .arg(input)
        .arg("-o")
        .arg(&temp_dir)
        .status()?;

    if !status1.success() {
        return Err(MlarError::IOError(io::Error::new(
            io::ErrorKind::NotFound,
            "mlar1: extract failed",
        )));
    }

    // use mlar2
    // generate new keypair
    // mlar2 keygen private_keys_v2
    let status2 = Command::new(&mlar2_path)
        .arg("keygen")
        .arg(&private_keys_v2)
        .status()?;

    if !status2.success() {
        return Err(MlarError::IOError(io::Error::new(
            io::ErrorKind::Other,
            "mlar2: keypair generation failed",
        )));
    }

    // write input archive content to MLA 2 format in a new archive
    let public_keys_v2 = private_keys_v2.with_extension("pub");
    let archive_v1_files = get_files_in_dir(&temp_dir)?;
    // to prevent temp dir in archive metadata, we only care about the file names
    let archive_v1_files: Vec<String> = archive_v1_files
        .iter()
        .filter_map(|path| path.file_name()) // Get just the filename
        .map(|path| path.to_string_lossy().to_string())
        .collect();

    // change directory to temp_dir
    let current_dir = env::current_dir()?;
    env::set_current_dir(&temp_dir)?;

    // mlar2 create -p public_keys_v2 -o output archive_v1_files
    let status2 = Command::new(&mlar2_path)
        .arg("create")
        .arg("-p")
        .arg(current_dir.join(public_keys_v2))
        .arg("-o")
        .arg(current_dir.join(output))
        .args(archive_v1_files)
        .status()?;

    if !status2.success() {
        return Err(MlarError::IOError(io::Error::new(
            io::ErrorKind::NotFound,
            "mlar2: new archive write failed",
        )));
    }

    // delete temporary directory content
    fs::remove_dir_all(&temp_dir)?;
    // delete mlar1 and mlar2 binaries
    fs::remove_file(&mlar1_path)?;
    fs::remove_file(&mlar2_path)?;

    Ok(())
}

fn app() -> clap::Command {
    let input_args = vec![
        Arg::new("input")
            .help("MLA 1 archive path")
            .long("input")
            .short('i')
            .num_args(1)
            .value_parser(value_parser!(PathBuf))
            .required(true),
        Arg::new("private_keys")
            .long("private_keys")
            .short('k')
            .help("Candidates ED25519 private key paths (DER or PEM format)")
            .num_args(1)
            .action(ArgAction::Append)
            .value_parser(value_parser!(PathBuf))
            .required(true),
    ];
    let output_args = vec![
        Arg::new("output")
            .help("Output file path for MLA 2 archive. Use - for stdout")
            .long("output")
            .short('o')
            .value_parser(value_parser!(PathBuf))
            .required(true),
    ];

    // Main parsing
    clap::Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            clap::Command::new("upgrade")
                .about("Upgrade an MLA 1 to MLA 2. Original files are kept")
                .args(&input_args)
                .args(&output_args),
        )
}

fn main() {
    let mut app = app();

    // Launch sub-command
    let help = app.render_long_help();
    let matches = app.get_matches();
    let res = matches.subcommand().map_or_else(
        || {
            eprintln!("Error: at least one command required.");
            eprintln!("{}", &help);
            std::process::exit(1);
        },
        |(cmd, matches)| {
            if cmd == "upgrade" {
                upgrade(matches)
            } else {
                eprintln!("Error: unknown command.");
                eprintln!("{}", &help);
                std::process::exit(1);
            }
        },
    );

    if let Err(err) = res {
        eprintln!("[!] Command ended with error: {err:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn verify_app() {
        app().debug_assert();
    }

    #[test]
    fn test_add_v2_suffix() {
        let path = Path::new("test_x25519_archive.pem");
        let new_path = add_v2_suffix(path);
        assert_eq!(new_path.to_str().unwrap(), "test_x25519_archive_v2.pem");
    }

    #[test]
    fn test_add_v2_suffix_no_extension() {
        let path = Path::new("test_x25519_archive");
        let new_path = add_v2_suffix(path);
        assert_eq!(new_path.to_str().unwrap(), "test_x25519_archive_v2");
    }

    #[test]
    fn test_create_temp_dir() {
        let temp_dir = create_temp_dir("test-create_temp_dir-").unwrap();
        assert!(temp_dir.exists());
        assert!(temp_dir.is_dir());

        // Clean up
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn test_get_files_in_dir() {
        let temp_dir = create_temp_dir("test-get_files_in_dir-").unwrap();
        let file_path = temp_dir.join("test_file.txt");
        File::create(&file_path).unwrap();

        let files = get_files_in_dir(&temp_dir).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], file_path);

        // Clean up
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn test_write_binary() {
        let path = write_binary("test_bin", b"test data").unwrap();
        assert!(path.exists());
        assert!(path.is_file());

        // Clean up
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_upgrade() {
        let temp_dir = create_temp_dir("test-upgrade-").unwrap();
        // temporary directory for output as we don't know if we can write in current one
        // copy input and private_keys to temp_dir
        fs::copy(
            "../../samples/archive_v1.mla",
            temp_dir.join("archive_v1.mla"),
        )
        .unwrap();
        fs::copy(
            "../../samples/test_x25519_archive_v1.pem",
            temp_dir.join("test_x25519_archive_v1.pem"),
        )
        .unwrap();
        let input = "archive_v1.mla";
        let output = temp_dir.join("archive_v2.mla");
        let private_keys = "test_x25519_archive_v1.pem";

        env::set_current_dir(&temp_dir).unwrap();

        let matches = app().get_matches_from([
            "mlar-upgrader",
            "upgrade",
            "-k",
            private_keys,
            "-i",
            input,
            "-o",
            output.to_str().unwrap(),
        ]);

        if let Some(upgrade_matches) = matches.subcommand_matches("upgrade") {
            assert!(upgrade(&upgrade_matches).is_ok());
        }

        // Clean up
        fs::remove_dir_all(temp_dir).unwrap();
    }
}
