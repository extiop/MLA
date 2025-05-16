use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use glob::Pattern;
use lru::LruCache;
use mla::config::{ArchiveReaderConfig, ArchiveWriterConfig};
use mla::crypto::hybrid::{HybridPrivateKey, HybridPublicKey};
use mla::crypto::mlakey_parser::{parse_mlakey_privkey, parse_mlakey_pubkey};
use mla::errors::{Error, FailSafeReadError};
use mla::helpers::linear_extract;
use mla::layers::compress::CompressionLayerReader;
use mla::layers::encrypt::EncryptionLayerReader;
use mla::layers::raw::RawLayerReader;
use mla::layers::traits::{InnerReaderTrait, LayerReader};
use mla::{
    ArchiveFailSafeReader, ArchiveFooter, ArchiveHeader, ArchiveReader, ArchiveWriter, Layers,
};
use std::collections::{HashMap, HashSet};
use std::error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::num::NonZeroUsize;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

#[cfg_attr(test, derive(PartialEq))]
#[derive(Debug)]
enum MlaVersion {
    V1,
    V2,
}

// ----- Error ------

#[derive(Debug)]
pub enum MlarError {
    /// Wrap a MLA error
    MlaError(Error),
    /// IO Error (not enough data, etc.)
    IOError(io::Error),
    /// A private key has been provided, but it is not required
    PrivateKeyProvidedButNotUsed,
    /// Configuration error
    ConfigError(mla::errors::ConfigError),
}

impl fmt::Display for MlarError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // For now, use the debug derived version
        write!(f, "{self:?}")
    }
}

impl From<Error> for MlarError {
    fn from(error: Error) -> Self {
        MlarError::MlaError(error)
    }
}

impl From<io::Error> for MlarError {
    fn from(error: io::Error) -> Self {
        MlarError::IOError(error)
    }
}

impl From<mla::errors::ConfigError> for MlarError {
    fn from(error: mla::errors::ConfigError) -> Self {
        MlarError::ConfigError(error)
    }
}

impl error::Error for MlarError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            MlarError::IOError(err) => Some(err),
            MlarError::MlaError(err) => Some(err),
            MlarError::ConfigError(err) => Some(err),
            _ => None,
        }
    }
}

// ----- Utils ------

/// Allow for different kind of output. As ArchiveWriter is parametrized over
/// a Writable type, ArchiveWriter<File> and ArchiveWriter<io::stdout>
/// can't coexist in the same code path.
enum OutputTypes {
    Stdout,
    File { file: File },
}

impl Write for OutputTypes {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            OutputTypes::Stdout => io::stdout().write(buf),
            OutputTypes::File { file } => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            OutputTypes::Stdout => io::stdout().flush(),
            OutputTypes::File { file } => file.flush(),
        }
    }
}

/// Return the parsed version of private keys from arguments `private_keys`
fn open_private_keys(matches: &ArgMatches) -> Result<Vec<HybridPrivateKey>, Error> {
    let mut private_keys = Vec::new();
    if let Some(private_key_args) = matches.get_many::<PathBuf>("private_keys") {
        for private_key_arg in private_key_args {
            let mut file = File::open(private_key_arg)?;
            // Load the the key in-memory and parse it
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            match parse_mlakey_privkey(&buf) {
                Err(_) => return Err(Error::InvalidKeyFormat),
                Ok(private_key) => private_keys.push(private_key),
            };
        }
    };
    Ok(private_keys)
}

/// Return the parsed version of public keys from arguments `public_keys`
fn open_public_keys(matches: &ArgMatches) -> Result<Vec<HybridPublicKey>, Error> {
    let mut public_keys = Vec::new();

    if let Some(public_key_args) = matches.get_many::<PathBuf>("public_keys") {
        for public_key_arg in public_key_args {
            let mut file = File::open(public_key_arg)?;
            // Load the the key in-memory and parse it
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            match parse_mlakey_pubkey(&buf) {
                Err(_) => return Err(Error::InvalidKeyFormat),
                Ok(public_key) => public_keys.push(public_key),
            };
        }
    }
    Ok(public_keys)
}

/// Return the ArchiveWriterConfig corresponding to provided arguments
fn config_from_matches(matches: &ArgMatches) -> ArchiveWriterConfig {
    let mut config = ArchiveWriterConfig::new();

    // Get layers
    let mut layers = Vec::new();
    if matches.contains_id("layers") {
        // Safe to use unwrap() because of the is_present() test
        for layer in matches.get_many::<String>("layers").unwrap() {
            layers.push(layer.as_str());
        }
    } else {
        // Default
        layers.push("compress");
        layers.push("encrypt");
    };

    for layer in layers {
        if layer == "compress" {
            config.enable_layer(Layers::COMPRESS);
        } else if layer == "encrypt" {
            config.enable_layer(Layers::ENCRYPT);
        } else {
            panic!("[ERROR] Unknown layer {}", layer);
        }
    }

    // Encryption specifics
    if matches.contains_id("public_keys") {
        if !config.is_layers_enabled(Layers::ENCRYPT) {
            eprintln!(
                "[WARNING] 'public_keys' argument ignored, because 'encrypt' layer is not enabled"
            );
        } else {
            let public_keys = match open_public_keys(matches) {
                Ok(public_keys) => public_keys,
                Err(error) => {
                    panic!("[ERROR] Unable to open public keys: {}", error);
                }
            };
            config.add_public_keys(&public_keys);
        }
    }

    // Compression specifics
    if matches.contains_id("compression_level") {
        if !config.is_layers_enabled(Layers::COMPRESS) {
            eprintln!(
                "[WARNING] 'compression_level' argument ignored, because 'compress' layer is not enabled"
            );
        } else {
            let comp_level: u32 = *matches
                .get_one::<u32>("compression_level")
                .expect("compression_level must be an int");
            if comp_level > 11 {
                panic!("compression_level must be in [0 .. 11]");
            }
            config.with_compression_level(comp_level).unwrap();
        }
    }

    config
}

fn destination_from_output_argument(output_argument: &PathBuf) -> Result<OutputTypes, MlarError> {
    let destination = if output_argument.as_os_str() != "-" {
        let path = Path::new(&output_argument);
        OutputTypes::File {
            file: File::create(path)?,
        }
    } else {
        OutputTypes::Stdout
    };
    Ok(destination)
}

/// Return an ArchiveWriter corresponding to provided arguments
fn writer_from_matches<'a>(
    matches: &ArgMatches,
) -> Result<ArchiveWriter<'a, OutputTypes>, MlarError> {
    let config = config_from_matches(matches);

    // Safe to use unwrap() because the option is required()
    let output = matches.get_one::<PathBuf>("output").unwrap();

    let destination = destination_from_output_argument(output)?;

    // Instantiate output writer
    Ok(ArchiveWriter::from_config(destination, config)?)
}

/// Return the ArchiveReaderConfig corresponding to provided arguments and set
/// Layers::ENCRYPT if a key is provided
fn readerconfig_from_matches(matches: &ArgMatches) -> ArchiveReaderConfig {
    let mut config = ArchiveReaderConfig::new();

    if matches.contains_id("private_keys") {
        let private_keys = match open_private_keys(matches) {
            Ok(private_keys) => private_keys,
            Err(error) => {
                panic!("[ERROR] Unable to open private keys: {}", error);
            }
        };
        config.add_private_keys(&private_keys);
        config.layers_enabled.insert(Layers::ENCRYPT);
    }

    config
}

fn open_mla_file<'a>(matches: &ArgMatches) -> Result<ArchiveReader<'a, File>, MlarError> {
    let config = readerconfig_from_matches(matches);

    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let path = Path::new(&mla_file);
    let mut file = File::open(path)?;

    // If a decryption key is provided, assume the user expects the file to be encrypted
    // If not, avoid opening it
    file.rewind()?;
    let header = ArchiveHeader::from(&mut file)?;
    if config.layers_enabled.contains(Layers::ENCRYPT)
        && !header.config.layers_enabled.contains(Layers::ENCRYPT)
    {
        eprintln!("[-] A private key has been provided, but the archive is not encrypted");
        return Err(MlarError::PrivateKeyProvidedButNotUsed);
    }
    file.rewind()?;

    // Instantiate reader
    Ok(ArchiveReader::from_config(file, config)?)
}

// Utils: common code to load a mla_file from arguments, fail-safe mode
fn open_failsafe_mla_file<'a>(
    matches: &ArgMatches,
) -> Result<ArchiveFailSafeReader<'a, File>, MlarError> {
    let config = readerconfig_from_matches(matches);

    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let path = Path::new(&mla_file);
    let file = File::open(path)?;

    // Instantiate reader
    Ok(ArchiveFailSafeReader::from_config(file, config)?)
}

/// Arguments for action 'extract' to match file names in the archive
enum ExtractFileNameMatcher {
    /// Match a list of files, where the order does not matter
    Files(HashSet<String>),
    /// Match a list of glob patterns
    GlobPatterns(Vec<Pattern>),
    /// No matching argument has been provided, so match all files
    Anything,
}
impl ExtractFileNameMatcher {
    fn from_matches(matches: &ArgMatches) -> Self {
        let files = match matches.get_many::<String>("files") {
            Some(values) => values,
            None => return ExtractFileNameMatcher::Anything,
        };
        if matches.get_flag("glob") {
            // Use glob patterns
            ExtractFileNameMatcher::GlobPatterns(
                files
                    .map(|pat| {
                        Pattern::new(pat)
                            .map_err(|err| {
                                eprintln!("[!] Invalid glob pattern {pat:?} ({err:?})");
                            })
                            .expect("Invalid glob pattern")
                    })
                    .collect(),
            )
        } else {
            // Use file names
            ExtractFileNameMatcher::Files(files.map(|s| s.to_string()).collect())
        }
    }
    fn match_file_name(&self, file_name: &str) -> bool {
        match self {
            ExtractFileNameMatcher::Files(files) => files.is_empty() || files.contains(file_name),
            ExtractFileNameMatcher::GlobPatterns(patterns) => {
                patterns.is_empty() || patterns.iter().any(|pat| pat.matches(file_name))
            }
            ExtractFileNameMatcher::Anything => true,
        }
    }
}

/// Compute the full path of the final file, using defensive measures
/// similar as what tar-rs does for `Entry::unpack_in`:
/// https://github.com/alexcrichton/tar-rs/blob/0.4.26/src/entry.rs#L344
fn get_extracted_path(output_dir: &Path, file_name: &str) -> Option<PathBuf> {
    let mut file_dst = output_dir.to_path_buf();
    for part in Path::new(&file_name).components() {
        match part {
            // Leading '/' characters, root paths, and '.'
            // components are just ignored and treated as "empty
            // components"
            Component::Prefix(..) | Component::RootDir | Component::CurDir => continue,

            // If any part of the filename is '..', then skip over
            // unpacking the file to prevent directory traversal
            // security issues.  See, e.g.: CVE-2001-1267,
            // CVE-2002-0399, CVE-2005-1918, CVE-2007-4131
            Component::ParentDir => {
                eprintln!("[!] Skipping file \"{file_name}\" because it contains \"..\"");
                return None;
            }

            Component::Normal(part) => file_dst.push(part),
        }
    }
    Some(file_dst)
}

/// In order to address MLA 1 or MLA 2 functions accordingly
fn get_mla_version(matches: &ArgMatches) -> Result<MlaVersion, Error> {
    // safe to use unwrap() because the option is required()
    let input = matches.get_one::<PathBuf>("input").unwrap();
    let mut file = File::open(input)?;
    let mut buffer = [0u8; 4];
    file.read_exact(&mut buffer)?;

    // check MLA magic and version at the same time
    let version = match &buffer {
        b"MLA1" => Some(MlaVersion::V1),
        b"MLA2" => Some(MlaVersion::V2),
        _ => None,
    };
    version.ok_or(mla::errors::Error::UnsupportedVersion)
}

/// Create a file and associate parent directories in a given output directory
fn create_file<P1: AsRef<Path>>(
    output_dir: P1,
    fname: &str,
) -> Result<Option<(File, PathBuf)>, MlarError> {
    let extracted_path = match get_extracted_path(output_dir.as_ref(), fname) {
        Some(p) => p,
        None => return Ok(None),
    };
    // Create all directories leading to the file
    let containing_directory = match extracted_path.parent() {
        Some(p) => p,
        None => {
            eprintln!(
                "[!] Skipping file \"{}\" because it does not have a parent (from {})",
                &fname,
                extracted_path.display()
            );
            return Ok(None);
        }
    };
    if !containing_directory.exists() {
        fs::create_dir_all(containing_directory).map_err(|err| {
            eprintln!(
                " [!] Error while creating output directory path for \"{}\" ({:?})",
                output_dir.as_ref().display(),
                err
            );
            err
        })?;
    }

    // Ensure that the containing directory is in the output dir
    let containing_directory = fs::canonicalize(containing_directory).map_err(|err| {
        eprintln!(
            " [!] Error while canonicalizing extracted file output directory path \"{}\" ({:?})",
            containing_directory.display(),
            err
        );
        err
    })?;
    if !containing_directory.starts_with(output_dir) {
        eprintln!(
            " [!] Skipping file \"{}\" because it would be extracted outside of the output directory, in {}",
            fname,
            containing_directory.display()
        );
        return Ok(None);
    }
    Ok(Some((
        File::create(&extracted_path).map_err(|err| {
            eprintln!(" [!] Unable to create \"{fname}\" ({err:?})");
            err
        })?,
        extracted_path,
    )))
}

/// Wrapper with Write, to append data to a file
///
/// This wrapper is used to avoid opening all files simultaneously, potentially
/// reaching the filesystem limit, but rather appending to file on-demand
///
/// A limited pool of active file, in a LRU cache, is used to avoid too many open-close
struct FileWriter<'a> {
    /// Target file for data appending
    path: PathBuf,
    /// Reference on the cache
    // A `Mutex` is used instead of a `RefCell` as `FileWriter` can be `Send`
    cache: &'a Mutex<LruCache<PathBuf, File>>,
    /// Is verbose mode enabled
    verbose: bool,
    /// Filename in the archive
    fname: &'a str,
}

/// Max number of fd simultaneously opened
pub const FILE_WRITER_POOL_SIZE: usize = 1000;

impl Write for FileWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Only one thread is using the FileWriter, safe to `.unwrap()`
        let mut cache = self.cache.lock().unwrap();
        if !cache.contains(&self.path) {
            let file = fs::OpenOptions::new().append(true).open(&self.path)?;
            cache.put(self.path.clone(), file);
            if self.verbose {
                println!("{}", self.fname);
            }
        }
        // Safe to `unwrap` here cause we ensure the element is in the cache (mono-threaded)
        let file = cache.get_mut(&self.path).unwrap();
        file.write(buf)

        // `file` will be closed on deletion from the cache
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ----- Commands ------

fn extract_v1(matches: &ArgMatches) -> Result<(), MlarError> {
    let file_name_matcher = ExtractFileNameMatcher::from_matches(matches);
    let output_dir = Path::new(matches.get_one::<PathBuf>("outputdir").unwrap());
    let verbose = matches.get_flag("verbose");

    let mut mla = open_mla_file(matches)?;

    // Create the output directory, if it does not exist
    if !output_dir.exists() {
        fs::create_dir(output_dir).map_err(|err| {
            eprintln!(
                " [!] Error while creating output directory \"{}\" ({:?})",
                output_dir.display(),
                err
            );
            err
        })?;
    }
    let output_dir = fs::canonicalize(output_dir).map_err(|err| {
        eprintln!(
            " [!] Error while canonicalizing output directory path \"{}\" ({:?})",
            output_dir.display(),
            err
        );
        err
    })?;

    let mut iter: Vec<String> = mla.list_files()?.cloned().collect();
    iter.sort();

    if let ExtractFileNameMatcher::Anything = file_name_matcher {
        // Optimisation: use linear extraction
        if verbose {
            println!("Extracting the whole archive using a linear extraction");
        }
        let cache = Mutex::new(LruCache::new(
            NonZeroUsize::new(FILE_WRITER_POOL_SIZE).unwrap(),
        ));
        let mut export: HashMap<&String, FileWriter> = HashMap::new();
        for fname in &iter {
            match create_file(&output_dir, fname)? {
                Some((_file, path)) => {
                    export.insert(
                        fname,
                        FileWriter {
                            path,
                            cache: &cache,
                            verbose,
                            fname,
                        },
                    );
                }
                None => continue,
            }
        }
        return Ok(linear_extract(&mut mla, &mut export)?);
    }

    for fname in iter {
        // Filter files according to glob patterns or files given as parameters
        if !file_name_matcher.match_file_name(&fname) {
            continue;
        }

        // Look for the file in the archive
        let mut sub_file = match mla.get_file(fname.clone()) {
            Err(err) => {
                eprintln!(" [!] Error while looking up subfile \"{fname}\" ({err:?})");
                continue;
            }
            Ok(None) => {
                eprintln!(" [!] Subfile \"{fname}\" indexed in metadata could not be found");
                continue;
            }
            Ok(Some(subfile)) => subfile,
        };
        let (mut extracted_file, _path) = match create_file(&output_dir, &fname)? {
            Some(file) => file,
            None => continue,
        };

        if verbose {
            println!("{fname}");
        }
        io::copy(&mut sub_file.data, &mut extracted_file).map_err(|err| {
            eprintln!(" [!] Unable to extract \"{fname}\" ({err:?})");
            err
        })?;
    }
    Ok(())
}

fn extract(matches: &ArgMatches) -> Result<(), MlarError> {
    let file_name_matcher = ExtractFileNameMatcher::from_matches(matches);
    let output_dir = Path::new(matches.get_one::<PathBuf>("outputdir").unwrap());
    let verbose = matches.get_flag("verbose");

    let mut mla = open_mla_file(matches)?;

    // Create the output directory, if it does not exist
    if !output_dir.exists() {
        fs::create_dir(output_dir).map_err(|err| {
            eprintln!(
                " [!] Error while creating output directory \"{}\" ({:?})",
                output_dir.display(),
                err
            );
            err
        })?;
    }
    let output_dir = fs::canonicalize(output_dir).map_err(|err| {
        eprintln!(
            " [!] Error while canonicalizing output directory path \"{}\" ({:?})",
            output_dir.display(),
            err
        );
        err
    })?;

    let mut iter: Vec<String> = mla.list_files()?.cloned().collect();
    iter.sort();

    if let ExtractFileNameMatcher::Anything = file_name_matcher {
        // Optimisation: use linear extraction
        if verbose {
            println!("Extracting the whole archive using a linear extraction");
        }
        let cache = Mutex::new(LruCache::new(
            NonZeroUsize::new(FILE_WRITER_POOL_SIZE).unwrap(),
        ));
        let mut export: HashMap<&String, FileWriter> = HashMap::new();
        for fname in &iter {
            match create_file(&output_dir, fname)? {
                Some((_file, path)) => {
                    export.insert(
                        fname,
                        FileWriter {
                            path,
                            cache: &cache,
                            verbose,
                            fname,
                        },
                    );
                }
                None => continue,
            }
        }
        return Ok(linear_extract(&mut mla, &mut export)?);
    }

    for fname in iter {
        // Filter files according to glob patterns or files given as parameters
        if !file_name_matcher.match_file_name(&fname) {
            continue;
        }

        // Look for the file in the archive
        let mut sub_file = match mla.get_file(fname.clone()) {
            Err(err) => {
                eprintln!(" [!] Error while looking up subfile \"{fname}\" ({err:?})");
                continue;
            }
            Ok(None) => {
                eprintln!(" [!] Subfile \"{fname}\" indexed in metadata could not be found");
                continue;
            }
            Ok(Some(subfile)) => subfile,
        };
        let (mut extracted_file, _path) = match create_file(&output_dir, &fname)? {
            Some(file) => file,
            None => continue,
        };

        if verbose {
            println!("{fname}");
        }
        io::copy(&mut sub_file.data, &mut extracted_file).map_err(|err| {
            eprintln!(" [!] Unable to extract \"{fname}\" ({err:?})");
            err
        })?;
    }
    Ok(())
}

fn repair_v1(matches: &ArgMatches) -> Result<(), MlarError> {
    let mut mla = open_failsafe_mla_file(matches)?;
    let mut mla_out = writer_from_matches(matches)?;

    // Convert
    let status = mla.convert_to_archive(&mut mla_out)?;
    match status {
        FailSafeReadError::NoError => {}
        FailSafeReadError::EndOfOriginalArchiveData => {
            eprintln!("[WARNING] The whole archive has been recovered");
        }
        _ => {
            eprintln!("[WARNING] Conversion ends with {status}");
        }
    };
    Ok(())
}

fn repair(matches: &ArgMatches) -> Result<(), MlarError> {
    let mut mla = open_failsafe_mla_file(matches)?;
    let mut mla_out = writer_from_matches(matches)?;

    // Convert
    let status = mla.convert_to_archive(&mut mla_out)?;
    match status {
        FailSafeReadError::NoError => {}
        FailSafeReadError::EndOfOriginalArchiveData => {
            eprintln!("[WARNING] The whole archive has been recovered");
        }
        _ => {
            eprintln!("[WARNING] Conversion ends with {status}");
        }
    };
    Ok(())
}

pub struct ArchiveInfoReader {
    /// MLA Archive format Reader
    //
    /// User's reading configuration
    pub config: ArchiveReaderConfig,
    /// Compressed sizes from CompressionLayer
    pub compressed_size: Option<u64>,
    /// Metadata (from footer if any)
    metadata: Option<ArchiveFooter>,
}

impl ArchiveInfoReader {
    pub fn from_config<'a, R>(
        mut src: R,
        mut config: ArchiveReaderConfig,
    ) -> Result<Self, MlarError>
    where
        R: 'a + InnerReaderTrait,
    {
        // Make sure we read the archive header from the start
        src.rewind()?;
        let header = ArchiveHeader::from(&mut src)?;
        config.load_persistent(header.config)?;

        // Pin the current position (after header) as the new 0
        let mut raw_src = Box::new(RawLayerReader::new(src));
        raw_src.reset_position()?;

        // Enable layers depending on user option. Order is relevant
        let mut src: Box<dyn 'a + LayerReader<'a, R>> = raw_src;
        if config.layers_enabled.contains(Layers::ENCRYPT) {
            src = Box::new(EncryptionLayerReader::new(src, &config.encrypt)?)
        }
        let compressed_size = if config.layers_enabled.contains(Layers::COMPRESS) {
            let mut src_compress = Box::new(CompressionLayerReader::new(src)?);
            src_compress.initialize()?;
            let size = src_compress
                .sizes_info
                .as_ref()
                .map(|v| v.get_compressed_size());
            src = src_compress;
            size
        } else {
            src.initialize()?;
            None
        };

        let metadata = Some(ArchiveFooter::deserialize_from(&mut src)?);

        src.rewind()?;
        Ok(ArchiveInfoReader {
            config,
            compressed_size,
            metadata,
        })
    }

    pub fn get_files_size(&self) -> Result<u64, MlarError> {
        if let Some(ArchiveFooter { files_info, .. }) = &self.metadata {
            Ok(files_info.values().map(|f| f.size).sum())
        } else {
            Err(Error::MissingMetadata.into())
        }
    }
}

fn info_v1(matches: &ArgMatches) -> Result<(), MlarError> {
    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let path = Path::new(&mla_file);
    let mut file = File::open(path)?;

    // Get Header
    let header = ArchiveHeader::from(&mut file)?;

    let encryption = header.config.layers_enabled.contains(Layers::ENCRYPT);
    let compression = header.config.layers_enabled.contains(Layers::COMPRESS);

    // Instantiate reader as needed
    let mla = if compression {
        let config = readerconfig_from_matches(matches);
        Some(ArchiveInfoReader::from_config(file, config)?)
    } else {
        None
    };

    // Format Version
    println!("Format version: {}", header.format_version);

    // Encryption config
    println!("Encryption: {encryption}");
    if encryption && matches.get_flag("verbose") {
        let encrypt_config = header.config.encrypt.expect("Encryption config not found");
        println!(
            "  Recipients: {}",
            encrypt_config
                .hybrid_multi_recipient_encapsulate_key
                .count_keys()
        );
    }

    // Compression config
    println!("Compression: {compression}");
    if compression && matches.get_flag("verbose") {
        let mla_ = mla.expect("MLA is required for verbose compression info");
        let output_size = mla_.get_files_size()?;
        let compressed_size: u64 = mla_.compressed_size.expect("Missing compression size");
        let compression_rate = output_size as f64 / compressed_size as f64;
        println!("  Compression rate: {compression_rate:.2}");
    }

    Ok(())
}

fn info(matches: &ArgMatches) -> Result<(), MlarError> {
    // Safe to use unwrap() because the option is required()
    let mla_file = matches.get_one::<PathBuf>("input").unwrap();
    let path = Path::new(&mla_file);
    let mut file = File::open(path)?;

    // Get Header
    let header = ArchiveHeader::from(&mut file)?;

    let encryption = header.config.layers_enabled.contains(Layers::ENCRYPT);
    let compression = header.config.layers_enabled.contains(Layers::COMPRESS);

    // Instantiate reader as needed
    let mla = if compression {
        let config = readerconfig_from_matches(matches);
        Some(ArchiveInfoReader::from_config(file, config)?)
    } else {
        None
    };

    // Format Version
    println!("Format version: {}", header.format_version);

    // Encryption config
    println!("Encryption: {encryption}");
    if encryption && matches.get_flag("verbose") {
        let encrypt_config = header.config.encrypt.expect("Encryption config not found");
        println!(
            "  Recipients: {}",
            encrypt_config
                .hybrid_multi_recipient_encapsulate_key
                .count_keys()
        );
    }

    // Compression config
    println!("Compression: {compression}");
    if compression && matches.get_flag("verbose") {
        let mla_ = mla.expect("MLA is required for verbose compression info");
        let output_size = mla_.get_files_size()?;
        let compressed_size: u64 = mla_.compressed_size.expect("Missing compression size");
        let compression_rate = output_size as f64 / compressed_size as f64;
        println!("  Compression rate: {compression_rate:.2}");
    }

    Ok(())
}

fn app() -> clap::Command {
    // Common arguments list, for homogeneity
    let input_args = vec![
        Arg::new("input")
            .help("Archive path")
            .long("input")
            .short('i')
            .num_args(1)
            .value_parser(value_parser!(PathBuf))
            .required(true),
        Arg::new("private_keys")
            .long("private_keys")
            .short('k')
            .help("Candidates ED25519 or hybrid private key or paths (DER or PEM format)")
            .num_args(1)
            .action(ArgAction::Append)
            .value_parser(value_parser!(PathBuf)),
    ];
    let output_args = vec![
        Arg::new("output")
            .help("Output file path. Use - for stdout")
            .long("output")
            .short('o')
            .value_parser(value_parser!(PathBuf))
            .required(true),
        Arg::new("public_keys")
            .help("ED25519 or hybrid public key paths (DER or PEM format)")
            .long("pubkey")
            .short('p')
            .num_args(1)
            .action(ArgAction::Append)
            .value_parser(value_parser!(PathBuf)),
    ];

    // Main parsing
    Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            Command::new("list")
                .about("List files inside a MLA Archive")
                .args(&input_args)
                .arg(
                    Arg::new("verbose")
                        .short('v')
                        .action(ArgAction::Count)
                        .help("Verbose listing, with additional information"),
                ),
        )
        .subcommand(
            Command::new("extract")
                .about("Extract files from a MLA Archive")
                .args(&input_args)
                .arg(
                    Arg::new("outputdir")
                        .help("Output directory where files are extracted")
                        .long("output")
                        .short('o')
                        .num_args(1)
                        .value_parser(value_parser!(PathBuf))
                        .default_value("."),
                )
                .arg(
                    Arg::new("glob")
                        .long("glob")
                        .short('g')
                        .action(ArgAction::SetTrue)
                        .help("Treat specified files as glob patterns"),
                )
                .arg(Arg::new("files").help("List of extracted files (all if none given)"))
                .arg(
                    Arg::new("verbose")
                        .long("verbose")
                        .short('v')
                        .action(ArgAction::SetTrue)
                        .help("List files as they are extracted"),
                ),
        )
        .subcommand(
            Command::new("repair")
                .about("Try to repair a MLA Archive into a fresh MLA Archive")
                .args(&input_args)
                .args(&output_args),
        )
        .subcommand(
            Command::new("info")
                .about("Get info on a MLA Archive")
                .args(&input_args)
                .arg(
                    Arg::new("verbose")
                        .long("verbose")
                        .short('v')
                        .action(ArgAction::SetTrue)
                        .help("Get extra info for encryption and compression layers"),
                ),
        )
}

fn main() {
    let mut app = app();

    // Launch sub-command
    let help = app.render_long_help();
    let matches = app.get_matches();
    // in order to address MLA 1 or MLA 2 functions accordingly

    let mla_version = get_mla_version(&matches).map_err(|_| mla::errors::Error::UnsupportedVersion);

    let res = match mla_version {
        Ok(MlaVersion::V1) => matches.subcommand().map_or_else(
            || {
                eprintln!("Error: at least one command required.");
                eprintln!("{}", &help);
                std::process::exit(1);
            },
            |(cmd, matches)| match cmd {
                "extract" => extract_v1(matches),
                "repair" => repair_v1(matches),
                "info" => info_v1(matches),

                _ => {
                    eprintln!("Error: unknown command.");
                    eprintln!("{}", &help);
                    std::process::exit(1);
                }
            },
        ),

        Ok(MlaVersion::V2) => matches.subcommand().map_or_else(
            || {
                eprintln!("Error: at least one command required.");

                eprintln!("{}", &help);

                std::process::exit(1);
            },
            |(cmd, matches)| match cmd {
                "extract" => extract(matches),
                "repair" => repair(matches),
                "info" => info(matches),

                _ => {
                    eprintln!("Error: unknown command.");
                    eprintln!("{}", &help);
                    std::process::exit(1);
                }
            },
        ),
        _ => Ok(()),
    };

    if let Err(err) = res {
        eprintln!("[!] Command ended with error: {err:?}");
        std::process::exit(1);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::env;

    #[test]
    fn verify_app() {
        app().debug_assert();
    }

    #[test]
    fn check_archive_format_v1() {
        // temporary directory for output as we don't know if we can write in current one
        let temp_dir = env::temp_dir();

        // mlar-legacy args
        let input = "archive_v1.mla";
        let private_keys = "test_x25519_archive_v1.pem";

        // temporary locations
        let temp_input = temp_dir.join(input);
        let temp_private_keys = temp_dir.join(private_keys);

        // copy input, private_keys, public_keys to temp_dir
        fs::copy(format!("../../samples/{input}"), &temp_input).unwrap();
        fs::copy(format!("../../samples/{private_keys}"), &temp_private_keys).unwrap();

        env::set_current_dir(&temp_dir).unwrap();

        // subcommand not relevant
        let matches =
            app().get_matches_from(["mlar-legacy", "info", "-k", private_keys, "-i", input]);
        let matches = matches.subcommand_matches("info").expect("info subcommand required");

        assert_eq!(MlaVersion::V1, get_mla_version(matches).unwrap());

        // Clean up
        fs::remove_file(temp_input).unwrap();
        fs::remove_file(temp_private_keys).unwrap();
    }

    #[test]
    fn check_archive_format_v2() {
        // use get_mla_version() to detect MLA 1
        // temporary directory for output as we don't know if we can write in current one
        let temp_dir = env::temp_dir();

        // mlar-legacy args
        let input = "archive_v2.mla";
        let private_keys = "test_mlakey_archive_v2.pem";

        // temporary locations
        let temp_input = temp_dir.join(input);
        let temp_private_keys = temp_dir.join(private_keys);

        // copy input, private_keys, public_keys to temp_dir
        fs::copy(format!("../../samples/{input}"), &temp_input).unwrap();
        fs::copy(format!("../../samples/{private_keys}"), &temp_private_keys).unwrap();

        env::set_current_dir(&temp_dir).unwrap();

        // subcommand not relevant
        let matches =
            app().get_matches_from(["mlar-legacy", "info", "-k", private_keys, "-i", input]);
        let matches = matches.subcommand_matches("info").expect("info subcommand required");

        assert_eq!(MlaVersion::V2, get_mla_version(matches).unwrap());

        // Clean up
        fs::remove_file(temp_input).unwrap();
        fs::remove_file(temp_private_keys).unwrap();
    }


    #[test]
    fn test_extract_v1() {
        // temporary directory for output as we don't know if we can write in current one
        let temp_dir = env::temp_dir();

        // mlar-legacy args
        let input = "archive_v1.mla";
        let private_keys = "test_x25519_archive_v1.pem";

        // temporary locations
        let temp_input = temp_dir.join(input);
        let temp_private_keys = temp_dir.join(private_keys);

        // copy input, private_keys, public_keys to temp_dir
        fs::copy(format!("../../samples/{input}"), &temp_input).unwrap();
        fs::copy(format!("../../samples/{private_keys}"), &temp_private_keys).unwrap();

        env::set_current_dir(&temp_dir).unwrap();

        let matches =
            app().get_matches_from(["mlar-legacy", "extract", "-k", private_keys, "-i", input]);
        let matches = matches.subcommand_matches("extract").expect("extract subcommand required");

        assert!(extract_v1(matches).is_ok());

        // Clean up
        fs::remove_file(temp_input).unwrap();
        fs::remove_file(temp_private_keys).unwrap();
    }

    #[test]
    fn test_extract() {
        // temporary directory for output as we don't know if we can write in current one
        let temp_dir = env::temp_dir();

        // mlar-legacy args
        let input = "archive_v2.mla";
        let private_keys = "test_mlakey_archive_v2.pem";

        // temporary locations
        let temp_input = temp_dir.join(input);
        let temp_private_keys = temp_dir.join(private_keys);

        // copy input, private_keys, public_keys to temp_dir
        fs::copy(format!("../../samples/{input}"), &temp_input).unwrap();
        fs::copy(format!("../../samples/{private_keys}"), &temp_private_keys).unwrap();

        env::set_current_dir(&temp_dir).unwrap();

        let matches =
            app().get_matches_from(["mlar-legacy", "extract", "-k", private_keys, "-i", input]);
        let matches = matches.subcommand_matches("extract").expect("extract subcommand required");

        assert!(extract(matches).is_ok());

        // Clean up
        fs::remove_file(temp_input).unwrap();
        fs::remove_file(temp_private_keys).unwrap();
    }

    #[test]
    fn test_repair_v1() {
        // temporary directory for output as we don't know if we can write in current one
        let temp_dir = env::temp_dir();

        // mlar-upgrade args
        let input = "archive_v1.mla";
        let output = temp_dir.join("archive_v1_repaired.mla");
        let private_keys = "test_x25519_archive_v1.pem";
        let public_keys = "test_x25519_archive_v1_pub.pem";

        // temporary locations
        let temp_input = temp_dir.join(input);
        let temp_private_keys = temp_dir.join(private_keys);
        let temp_public_keys = temp_dir.join(public_keys);

        // copy input, private_keys, public_keys to temp_dir
        fs::copy(format!("../../samples/{input}"), &temp_input).unwrap();
        fs::copy(format!("../../samples/{private_keys}"), &temp_private_keys).unwrap();
        fs::copy(format!("../../samples/{public_keys}"), &temp_public_keys).unwrap();

        env::set_current_dir(&temp_dir).unwrap();

        let matches = app().get_matches_from([
            "mlar-legacy",
            "repair",
            "-k",
            private_keys,
            "-i",
            input,
            "-o",
            output.to_str().unwrap(),
            "-p",
            public_keys,
        ]);
        let matches = matches.subcommand_matches("repair").expect("repair subcommand required");

        assert!(repair_v1(matches).is_ok());

        // Clean up
        fs::remove_file(temp_input).unwrap();
        fs::remove_file(temp_private_keys).unwrap();
        fs::remove_file(temp_public_keys).unwrap();
    }

    #[test]
    fn test_repair() {
        // temporary directory for output as we don't know if we can write in current one
        let temp_dir = env::temp_dir();

        // mlar-upgrade args
        let input = "archive_v2.mla";
        let output = temp_dir.join("archive_v2_repaired.mla");
        let private_keys = "test_mlakey_archive_v2.pem";
        let public_keys = "test_mlakey_archive_v2_pub.pem";

        // temporary locations
        let temp_input = temp_dir.join(input);
        let temp_private_keys = temp_dir.join(private_keys);
        let temp_public_keys = temp_dir.join(public_keys);

        // copy input, private_keys, public_keys to temp_dir
        fs::copy(format!("../../samples/{input}"), &temp_input).unwrap();
        fs::copy(format!("../../samples/{private_keys}"), &temp_private_keys).unwrap();
        fs::copy(format!("../../samples/{public_keys}"), &temp_public_keys).unwrap();

        env::set_current_dir(&temp_dir).unwrap();

        let matches = app().get_matches_from([
            "mlar-legacy",
            "repair",
            "-k",
            private_keys,
            "-i",
            input,
            "-o",
            output.to_str().unwrap(),
            "-p",
            public_keys,
        ]);
        let matches = matches.subcommand_matches("repair").expect("repair subcommand required");

        assert!(repair(matches).is_ok());

        // Clean up
        fs::remove_file(temp_input).unwrap();
        fs::remove_file(temp_private_keys).unwrap();
        fs::remove_file(temp_public_keys).unwrap();
    }

    #[test]
    fn test_info_v1() {
        // temporary directory for output as we don't know if we can write in current one
        let temp_dir = env::temp_dir();

        // mlar-upgrade args
        let input = "archive_v1.mla";
        let private_keys = "test_x25519_archive_v1.pem";

        // temporary locations
        let temp_input = temp_dir.join(input);
        let temp_private_keys = temp_dir.join(private_keys);

        // copy input, private_keys, public_keys to temp_dir
        fs::copy(format!("../../samples/{input}"), &temp_input).unwrap();
        fs::copy(format!("../../samples/{private_keys}"), &temp_private_keys).unwrap();

        env::set_current_dir(&temp_dir).unwrap();

        let matches =
            app().get_matches_from(["mlar-legacy", "info", "-k", private_keys, "-i", input]);
        let matches = matches.subcommand_matches("info").expect("info subcommand required");

        assert!(info_v1(matches).is_ok());

        // Clean up
        fs::remove_file(temp_input).unwrap();
        fs::remove_file(temp_private_keys).unwrap();
    }

    #[test]
    fn test_info() {
        // temporary directory for output as we don't know if we can write in current one
        let temp_dir = env::temp_dir();

        // mlar-upgrade args
        let input = "archive_v2.mla";
        let private_keys = "test_mlakey_archive_v2.pem";

        // temporary locations
        let temp_input = temp_dir.join(input);
        let temp_private_keys = temp_dir.join(private_keys);

        // copy input, private_keys, public_keys to temp_dir
        fs::copy(format!("../../samples/{input}"), &temp_input).unwrap();
        fs::copy(format!("../../samples/{private_keys}"), &temp_private_keys).unwrap();

        env::set_current_dir(&temp_dir).unwrap();

        let matches =
            app().get_matches_from(["mlar-legacy", "info", "-k", private_keys, "-i", input]);
        let matches = matches.subcommand_matches("info").expect("info subcommand required");

        assert!(info(matches).is_ok());

        // Clean up
        fs::remove_file(temp_input).unwrap();
        fs::remove_file(temp_private_keys).unwrap();
    }
}
