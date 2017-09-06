#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(unused_variables)]

#[macro_use]
extern crate nom;

use std::ascii::AsciiExt;
use std::collections::HashMap;
use std::fs::File;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io;
use std::io::prelude::*;
use std::num::ParseIntError;
use std::str;
use std::str::Utf8Error;
use std::string::FromUtf8Error;

use nom::IResult;

#[derive(Debug)]
struct BdError(String);

type Warnings = Option<Vec<String>>;

#[derive(Debug, Eq, PartialEq)]
enum PluggableTransport {
    Obfs2,
    Obfs3,
    Obfs4,
    Scramblesuit,
}

impl PluggableTransport {
    fn from_bytes(bytes: &[u8]) -> Result<PluggableTransport, ()> {
        let transport = match bytes {
            b"obfs2" => PluggableTransport::Obfs2,
            b"obfs3" => PluggableTransport::Obfs3,
            b"obfs4" => PluggableTransport::Obfs4,
            b"scramblesuit" => PluggableTransport::Scramblesuit,
            _ => return Err(())
        };

        Ok(transport)
    }
}

#[derive(Debug)]
struct ExtraInfo {
    nick: Option<String>,
    fp: Option<String>,
    identity_ed25519: Option<String>,
    published: Option<String>,
    write_history: Option<(String, u32, Vec<u64>)>,
    read_history: Option<(String, u32, Vec<u64>)>,
    dirreq_write_history: Option<(String, u32, Vec<u64>)>,
    dirreq_read_history: Option<(String, u32, Vec<u64>)>,
    geoip_db_digest: Option<String>,
    geoip6_db_digest: Option<String>,
    dirreq_stats_end: Option<(String, u32)>,
    dirreq_ips_per_country: Option<HashMap<String, u32>>,
    dirreq_reqs_per_country: Option<HashMap<String, u32>>,
    dirreq_v3_resp: Option<HashMap<String, u32>>,
    dirreq_v3_direct_dl: Option<HashMap<String, u32>>,
    dirreq_v3_tunneled_dl: Option<HashMap<String, u32>>,
    hidserv_stats_end: Option<(String, u32)>,
    hidserv_rend_relayed_cells: Option<(i32, u32, f64, u32)>,
    hidserv_dir_onions_seen: Option<(i32, u32, f64, u32)>,
    // Each tuple in the `transport` vec represents: (transportname, (ip, port), [extra_args]).
    transport: Vec<(PluggableTransport, Option<(String, u16)>, Option<Vec<String>>)>,
    bridge_stats_end: Option<(String, u32)>,
    bridge_ips_per_country: Option<HashMap<String, u32>>,
    bridge_ip_versions: Option<HashMap<String, u32>>,
    bridge_ip_transports: Option<HashMap<String, u32>>,
    router_sig_ed25519: Option<String>,
    router_signature: Option<String>,
}

impl Default for ExtraInfo {
    fn default() -> Self {
        ExtraInfo {
            nick: None,
            fp: None,
            identity_ed25519: None,
            published: None,
            write_history: None,
            read_history: None,
            dirreq_write_history: None,
            dirreq_read_history: None,
            geoip_db_digest: None,
            geoip6_db_digest: None,
            dirreq_stats_end: None,
            dirreq_ips_per_country: None,
            dirreq_reqs_per_country: None,
            dirreq_v3_resp: None,
            dirreq_v3_direct_dl: None,
            dirreq_v3_tunneled_dl: None,
            hidserv_stats_end: None,
            hidserv_rend_relayed_cells: None,
            hidserv_dir_onions_seen: None,
            transport: vec![],
            bridge_stats_end: None,
            bridge_ips_per_country: None,
            bridge_ip_versions: None,
            bridge_ip_transports: None,
            router_sig_ed25519: None,
            router_signature: None,
        }
    }
}

impl ExtraInfo {
    fn from_file(path: &str) -> Result<Self, BdError> {
        let file_bytes = read_file(path)?;
        run_extra_info_parser(&file_bytes)
    }
}

fn read_file(path: &str) -> Result<Vec<u8>, BdError> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            let why = format!("Encountered the following `std::io` error while opening the file: `{:?}`.", e);
            return Err(BdError(why));
        }
    };

    let mut buf = Vec::new();
    if let Err(e) = f.read_to_end(&mut buf) {
        let why = format!("Encountered the following `std::io` error while reading the file: `{:?}`.", e);
        return Err(BdError(why));
    }

    // Check that the file contains only printable-ascii bytes.
    check_file_bytes(&buf)?;
    Ok(buf)
}

/// Returns Ok() if the given bytes contain only printable ascii characters.
///
/// TODO:
///     - Should the ascii tab contol byte (\t, 0x09) be allowed?
///
fn check_file_bytes(file_bytes: &[u8]) -> Result<(), BdError> {
    let n_chars_in_error_msg = 10;

    for (i, byte) in file_bytes.iter().enumerate() {
        // Check if the byte is an ascii control byte but is not a linefeed character (ascii-code 10).
        if *byte <= 31 && *byte != 10 {
            let mut start = 0;
            let stop = i + 1;

            if i > n_chars_in_error_msg {
                start = i - n_chars_in_error_msg;
            }

            // We know that `byte` is valid Utf8 (an ascii controll character) so we can use .unwrap() here.
            let snippet = str::from_utf8(&file_bytes[start..stop]).unwrap();

            let why = format!(
                "The following snippet from the descriptor file contains a non-printable ascii byte: `{}`. \
                Descriptor files may contain only printable ascii characters.",
                snippet
            );
            return Err(BdError(why));
        }

        // Check that the byte is a "simple" ascii byte. Ascii code 127 is `DEL`, which in non-printable.
        if *byte >= 127 {
            let mut start = 0;
            let stop = i + 1;

            if i > n_chars_in_error_msg {
                start = i - n_chars_in_error_msg;
            }

            // We know that `byte` is not a valid simple ascii character, but we don't know that
            // `byte` is valid Utf8. Therefore, we should use `.from_utf8_lossy()` here. If the
            // final byte in the snippet is not a valid Utf8 character, then it will be replace
            // with a '�' character.
            let snippet = String::from_utf8_lossy(&file_bytes[start..stop]);

            let why = format!(
                "The following snippet from the descriptor file contains a non-ascii byte: `{}`. \
                Descriptor files may contain only printable ascii characters.",
                snippet
            );
            return Err(BdError(why));
        }
    }

    Ok(())
}

fn run_extra_info_parser(bytes: &[u8]) -> Result<ExtraInfo, BdError> {
    let mut desc = ExtraInfo::default();
    let mut remaining = bytes;
    let mut field_index = 0;

    loop {
        let (keyword, field_bytes, bytes_after_field) = get_next_keyword_and_field(remaining)?;
        field_index += 1;

        match keyword {
            b"extra-info" => {
                let (nick, fp) = parse_extra_info_field(field_bytes)?;
                desc.nick = Some(nick);
                desc.fp = Some(fp);
            },
            b"identity-ed25519" => {
                let cert = parse_identity_ed25519_field(field_bytes)?;
                desc.identity_ed25519 = Some(cert);
            },
            b"published" => {
                let published_datestring = parse_published_field(field_bytes)?;
                desc.published = Some(published_datestring);
            },
            b"write-history" => {
                let write_history = parse_write_history_field(field_bytes)?;
                desc.write_history = Some(write_history);
            },
            b"read-history" => {
                let read_history = parse_read_history_field(field_bytes)?;
                desc.read_history = Some(read_history);
            },
            b"dirreq-write-history" => {
                let dirreq_write_history = parse_dirreq_write_history_field(field_bytes)?;
                desc.dirreq_write_history = Some(dirreq_write_history);
            },
            b"dirreq-read-history" => {
                let dirreq_read_history = parse_dirreq_read_history_field(field_bytes)?;
                desc.dirreq_read_history = Some(dirreq_read_history);
            },
            b"dirreq-v3-ips" => {
                let ips_per_country = parse_dirreq_v3_ips_field(field_bytes)?;
                desc.dirreq_ips_per_country = Some(ips_per_country);
            },
            b"dirreq-v3-reqs" => {
                let reqs_per_country = parse_dirreq_v3_reqs_field(field_bytes)?;
                desc.dirreq_reqs_per_country = Some(reqs_per_country);
            },
            b"dirreq-v3-resp" => {
                let resp_counter = parse_dirreq_v3_resp_field(field_bytes)?;
                desc.dirreq_v3_resp = Some(resp_counter);
            },
            b"dirreq-v3-direct-dl" => {
                let dl_counter = parse_dirreq_v3_direct_dl_field(field_bytes)?;
                desc.dirreq_v3_direct_dl = Some(dl_counter);
            },
            b"dirreq-v3-tunneled-dl" => {
                let dl_status_counter = parse_dirreq_v3_tunneled_dl_field(field_bytes)?;
                desc.dirreq_v3_tunneled_dl = Some(dl_status_counter);
            },
            b"bridge-ips" => {
                let ips_per_country = parse_bridge_ips_field(field_bytes)?;
                desc.bridge_ips_per_country = Some(ips_per_country);
            },
            b"bridge-ip-versions" => {
                let ip_versions_counter = parse_bridge_ip_versions_field(field_bytes)?;
                desc.bridge_ip_versions = Some(ip_versions_counter);
            },
            b"bridge-ip-transports" => {
                let ip_versions_counter = parse_bridge_ip_transports_field(field_bytes)?;
                desc.bridge_ip_transports = Some(ip_versions_counter);
            },
            b"dirreq-stats-end" => {
                let stats = parse_stats_end_field(field_bytes, "dirreq-stats-end")?;
                desc.dirreq_stats_end = Some(stats);
            },
            b"hidserv-stats-end" => {
                let stats = parse_stats_end_field(field_bytes, "hidserv-stats-end")?;
                desc.hidserv_stats_end = Some(stats);
            },
            b"bridge-stats-end" => {
                let stats = parse_stats_end_field(field_bytes, "bridge-stats-end")?;
                desc.bridge_stats_end = Some(stats);
            },
            b"hidserv-rend-relayed-cells" => {
                let stats = parse_hidserv_stats_field(field_bytes, "hidserv-rend-relayed-cells")?;
                desc.hidserv_rend_relayed_cells = Some(stats);
            },
            b"hidserv-dir-onions-seen" => {
                let stats = parse_hidserv_stats_field(field_bytes, "hidserv-dir-onions-seen")?;
                desc.hidserv_dir_onions_seen = Some(stats);
            },
            b"transport" => {
                let parsed_transport_data = parse_transport_field(field_bytes)?;
                desc.transport.push(parsed_transport_data);
            },
            b"geoip-db-digest" => {
                let digest = parse_geoip_db_digest_field(field_bytes)?;
                desc.geoip_db_digest = Some(digest);
            },
            b"geoip6-db-digest" => {
                let digest = parse_geoip6_db_digest_field(field_bytes)?;
                desc.geoip6_db_digest = Some(digest);
            },
            b"router-sig-ed25519" => {
                let sig = parse_router_sig_ed25519_field(field_bytes)?;
                desc.router_sig_ed25519 = Some(sig);
            },
            b"router-signature" => {
                let router_signature = parse_router_signature_field(field_bytes)?;
                desc.router_signature = Some(router_signature);
            },
            _ => {
                let why = format!("Encountered unknown keyword: `{}`.", str::from_utf8(keyword).unwrap());
                return Err(BdError(why));
            }
        };

        if bytes_after_field.is_empty() || bytes_after_field == b"\n" {
            break;
        }

        remaining = bytes_after_field;
    }

    Ok(desc)
}

named!(
    nom_parse_next_word,
    ws!(
        take_until_either!(" \n")
    )
);

/// Wraps the Nom parser `nom_parse_next_word` to return a BdError if the parser fails.
///
fn parse_next_word(bytes: &[u8]) -> Result<(&[u8], &[u8]), BdError> {
    if let IResult::Done(remaining, word_bytes) = nom_parse_next_word(bytes) {
        Ok((word_bytes, remaining))
    } else {
        let why = format!(
            "Error while parsing the next word from the following line: `{}`. \
            The line must contain a space or newline character.",
            str::from_utf8(bytes).unwrap()
        );
        Err(BdError(why))
    }
}

fn byte_to_true(byte: u8) -> bool {
    true
}

named!(
    nom_parse_until_extra_info_keyword,
    ws!(
        alt_complete!(
            take_until!("extra-info") |
            take_until!("\nidentity-ed25519") |
            take_until!("\npublished") |
            take_until!("\nwrite-history") |
            take_until!("\nread-history") |
            take_until!("\ndirreq-write-history") |
            take_until!("\ndirreq-read-history") |
            take_until!("\ngeoip-db-digest") |
            take_until!("\ngeoip6-db-digest") |
            take_until!("\ndirreq-stats-end") |
            take_until!("\ndirreq-v3-ips") |
            take_until!("\ndirreq-v3-reqs") |
            take_until!("\ndirreq-v3-resp") |
            take_until!("\ndirreq-v3-direct-dl") |
            take_until!("\ndirreq-v3-tunneled-dl") |
            take_until!("\nhidserv-stats-end") |
            take_until!("\nhidserv-rend-relayed-cells") |
            take_until!("\nhidserv-dir-onions-seen") |
            take_until!("\ntransport") |
            take_until!("\nbridge-stats-end") |
            take_until!("\nbridge-ips") |
            take_until!("\nbridge-ip-versions") |
            take_until!("\nbridge-ip-transports") |
            take_until!("\nrouter-sig-ed25519") |
            take_until!("\nrouter-signature") |
            take_while!(byte_to_true)
        )
    )
);

/// Wraps the Nom parser `nom_parse_until_extra_info_keyword` so that a BdError is returned when the parser fails.
///
fn parse_until_extra_info_keyword(bytes: &[u8]) -> Result<(&[u8], &[u8]), BdError> {
    if let IResult::Done(remaining, matched) = nom_parse_until_extra_info_keyword(bytes) {
        Ok((matched, remaining))
    } else {
        let why = format!(
            "Error while parsing until the next extra-info keyword from the following line: `{}`.",
            str::from_utf8(bytes).unwrap()
        );
        Err(BdError(why))
    }
}

/// Returns Ok() if the given ascii bytes contain only characters from the set: {-, 0...9, a...z, A...Z}.
///
fn check_keyword_bytes(keyword_bytes: &[u8]) -> Result<(), BdError> {
    for byte in keyword_bytes {
        match *byte {
            // Valid keyword character set: {-, 0...9, a...z, A...Z}.
            45 | 48...57 | 65...90 | 97...122 => continue,
            _ => {
                let why = format!(
                    "The following keyword contains an invalid keyword-character: `{}`. \
                    All keyword characters must be from the set: {-, 0...9, a...z, A...Z}.",
                    str::from_utf8(keyword_bytes).unwrap()
                );
                return Err(BdError(why));
            }
        }
    }

    Ok(())
}

fn get_next_keyword_and_field(bytes: &[u8]) -> Result<(&[u8], &[u8], &[u8]), BdError> {
    let (keyword_bytes, bytes_after_keyword) = parse_next_word(bytes)?;
    check_keyword_bytes(keyword_bytes)?;
    let (field_bytes, bytes_after_field) = parse_until_extra_info_keyword(bytes_after_keyword)?;
    Ok((keyword_bytes, field_bytes, bytes_after_field))
}

fn split_bytes_at_char(bytes: &[u8], sep: char) -> Vec<&[u8]> {
    bytes.split(|byte| *byte as char == sep).collect()
}

fn strip_char_from_bytes(bytes: &[u8], strip_char: char) -> Vec<u8> {
    let mut result = vec![];
    for byte in bytes {
        if *byte as char != strip_char {
            result.push(*byte);
        }
    }
    result
}

fn parse_extra_info_field(field_bytes: &[u8]) -> Result<(String, String), BdError> {
    let args = split_bytes_at_char(field_bytes, ' ');
    let n_args = args.len();

    if n_args != 2 {
        let why = format!(
            "Error while parsing the following line: `extra-info {}`. \
            This field must have 2 arguments, but {} where given.",
            str::from_utf8(field_bytes).unwrap(),
            n_args
        );
        return Err(BdError(why));
    }

    let nick = str::from_utf8(args[0]).unwrap().to_string();
    let fp = str::from_utf8(args[1]).unwrap().to_string();
    Ok((nick, fp))
}

named_args!(
    nom_parse_enveloped_block(prefix: String, suffix: String)<&[u8]>,
    delimited!(
        tag!(&prefix[..]),
        take_until!(&suffix[..]),
        tag!(&suffix[..])
    )
);

fn parse_identity_ed25519_field(field_bytes: &[u8]) -> Result<String, BdError> {
    let prefix = "-----BEGIN ED25519 CERT-----\n".to_string();
    let suffix = "\n-----END ED25519 CERT-----".to_string();

    let cert_bytes = match nom_parse_enveloped_block(field_bytes, prefix, suffix) {
        IResult::Done(_, cert_bytes) => cert_bytes,
        _ => {
            let why = format!(
                "Error while parsing the following field: `identity-ed25519\n{}`. \
                This field must start with `-----BEGIN ED25519 CERT-----` and end with `-----END ED25519 CERT-----`.",
                str::from_utf8(field_bytes).unwrap()
            );
            return Err(BdError(why));
        }
    };

    let cert_bytes_by_line = split_bytes_at_char(cert_bytes, '\n');

    // Check the number of lines.
    let n_lines = cert_bytes_by_line.len();
    if n_lines != 3 {
        let why = format!(
            "Error while parsing the following field: `identity-ed25519\n{}`. \
            The certificate body in this field must contain 3 lines of bytes, {} were found.",
            str::from_utf8(field_bytes).unwrap()
            n_lines
        );
        return Err(BdError(why));
    }

    // Join the certificate bytes into a String.
    let mut cert = String::new();
    for line_bytes in cert_bytes_by_line {
        let n_bytes_in_line = line_bytes.len();
        let line_str = str::from_utf8(line_bytes).unwrap();

        // Certs must line-wrap after the 64th character.
        if n_bytes_in_line > 64 {
            let why = format!(
                "Error while parsing the following field: `identity-ed25519\n{}`. \
                Certificate lines must line-wrap after the 64th byte, the following line contains {} bytes: `{}`.",
                str::from_utf8(field_bytes).unwrap(),
                n_bytes_in_line,
                line_str
            );
            return Err(BdError(why));
        }

        cert.push_str(line_str);
    }

    Ok(cert)

    // TODO:
    //   - Validation:
    //      * Number of chars should be 188.
    //      * Last char should be '='.
    //      * Check b64.
}

fn parse_published_field(field_bytes: &[u8]) -> Result<(String, Warnings), BdError> {
    let args = split_bytes_at_char(field_bytes, ' ');
    let n_args = args.len();

    if n_args < 2 {
        let why = format!(
            "Error while parsing the following field: `published {}`. \
            This field must have at least 2 arguments, {} were found.",
            str::from_utf8(field_bytes).unwrap(),
            n_args
        );
        return Err(BdError(why));
    }

    // Ignore any extra arguments, but include a warning.
    let mut warnings: Warnings = None;
    if n_args > 2 {
        let warn = format!(
            "Warning while parsing the following field: `published {}`. \
            This field should have exactly 2 arguments, {} were found.",
            str::from_utf8(field_bytes).unwrap(),
            n_args
        );
        warnings = Some(vec![warn]);
    }

    let datestring = format!(
        "{} {}",
        str::from_utf8(args[0]).unwrap(),
        str::from_utf8(args[1]).unwrap()
    );
    Ok((datestring, warnings))
}

/// Parser for the fields: `hidserv-rend-relayed-cells` and `hidserv-dir-onions-seen`.
///
/// # Example
/// ```
/// let (n_relay_cells, delta_f, epsilon, bin_size, warnings) = parse_hidserv_stats_field(field_bytes, "hidserv-rend-relayed-cells")?;
/// ```
///
fn parse_hidserv_stats_field(field_bytes: &[u8], keyword: &str) -> Result<(i32, u32, f64, u32, Warnings), BdError> {
    let args = split_bytes_at_char(field_bytes, ' ');
    let n_args = args.len();

    // This field must have at least 4 arguments.
    if n_args < 4 {
        let why = format!(
            "Error while parsing the following field: `{} {}`. \
            This field must have at least 4 arguments, {} were found.",
            keyword,
            str::from_utf8(field_bytes).unwrap(),
            n_args
        );
        return Err(BdError(why));
    }

    // Ignore any extra arguments, but include a warning.
    let mut warnings: Vec<String> = vec![];
    if n_args > 4 {
        let warn = format!(
            "Warning while parsing the following field: `{} {}`. \
            This field should have exactly 4 arguments, {} were found.",
            keyword,
            str::from_utf8(field_bytes).unwrap(),
            n_args
        );
        warnings.push(warn);
    }

    // Approximate number of RELAY cells seen in either direction on a it after receiving and
    // successfully processing a RENDEZVOUS1 cell. This can be negative!
    let n_relay_cells: i32 = match str::from_utf8(args[0]).unwrap().parse() {
        Ok(num) => num,
        Err(ParseIntError) => {
            let why = format!(
                "Error while parsing the following field: `{} {}`. \
                The first argument in this field `{}` could not be converted to an i32.",
                keyword,
                str::from_utf8(field_bytes).unwrap(),
                str::from_utf8(args[0]).unwrap()
            );
            return Err(BdError(why));
        }
    };

    let mut delta_f: Option<u32> = None;
    let mut epsilon: Option<f64> = None;
    let mut bin_size: Option<u32> = None;

    for arg in &args[1..] {
        let key_val_vec = split_bytes_at_char(arg, '=');

        // Ignore any malformed arguments, but include a warning.
        if key_val_vec.len() != 2 {
            let warn = format!(
                "Warning while parsing the following field: `{} {}`. \
                Encountered a malformed key-value argument, key-value pairs must contain one `=` character",
                keyword,
                str::from_utf8(field_bytes).unwrap()
            );
            warnings.push(warn);
            continue;
        }

        let key_bytes = key_val_vec[0];
        let value_bytes = key_val_vec[1];

        match key_bytes {
            b"delta_f" => {
                delta_f = match str::from_utf8(value_bytes).unwrap().parse::<u32>() {
                    Ok(num) => Some(num),
                    Err(ParseIntError) => {
                        let why = format!(
                            "Error while parsing the following field: `{} {}`. \
                            The `delta_f` value `{}` not be converted to a u32.",
                            keyword,
                            str::from_utf8(field_bytes).unwrap(),
                            str::from_utf8(value_bytes).unwrap()
                        );
                        return Err(BdError(why));
                    }
                };
            },
            b"epsilon" => {
                epsilon = match str::from_utf8(value_bytes).unwrap().parse::<f64>() {
                    Ok(num) => Some(num),
                    Err(ParseIntError) => {
                        let why = format!(
                            "Error while parsing the following field: `{} {}`. \
                            The `epsilon` value `{}` not be converted to an f64.",
                            keyword,
                            str::from_utf8(field_bytes).unwrap(),
                            str::from_utf8(value_bytes).unwrap()
                        );
                        return Err(BdError(why));
                    }
                };
            },
            b"bin_size" => {
                bin_size = match str::from_utf8(value_bytes).unwrap().parse::<u32>() {
                    Ok(num) => Some(num),
                    Err(ParseIntError) => {
                        let why = format!(
                            "Error while parsing the following field: `{} {}`. \
                            The `bin_size` value `{}` not be converted to a u32.",
                            keyword,
                            str::from_utf8(field_bytes).unwrap(),
                            str::from_utf8(value_bytes).unwrap()
                        );
                        return Err(BdError(why));
                    }
                };
            },
            // Skip unrecognized key-value pairs, but add a warning.
            _ => {
                let warn = format!(
                    "Warning while parsing the following field: `{} {}`. \
                    Encountered an unrecognized key: `{}`.",
                    keyword,
                    str::from_utf8(field_bytes).unwrap(),
                    str::from_utf8(key_bytes).unwrap()
                );
                warnings.push(warn);
                continue;
            }
        };
    }

    if delta_f == None || epsilon == None || bin_size == None {
        let why = format!(
            "Error while parsing the following field: `{} {}`. \
            Field must contain key-value pairs for all of the following keys: delta_f, epsilon, and bin_size.",
            keyword,
            str::from_utf8(field_bytes).unwrap()
        );
        return Err(BdError(why));
    }

    let w: Warnings = match warnings.is_empty() {
        true => None,
        false => Some(warnings)
    };
    Ok((n_relay_cells, delta_f.unwrap(), epsilon.unwrap(), bin_size.unwrap(), w))
}

named!(
    nom_parse_datestring_interval_field<(&[u8], &[u8], &[u8])>,
    ws!(
        do_parse!(
            ymd: take_until!(" ") >>
            hms: take_until!(" ") >>
            n_secs_per_interval: delimited!(
                tag!("("),
                take_until!(" "),
                tag!("s)")
            ) >>
            (ymd, hms, n_secs_per_interval)
        )
    )
);

/// Parser for the fields: `dirreq-stats-end`, `hidserv-stats-end`, and `bridge-stats-end`.
///
/// # Example
/// ```
/// let (datestring, n_secs_per_interval, warnings) = parse_stats_end_field(field_bytes, "dirreq-stats-end")?;
/// ```
///
fn parse_stats_end_field(field_bytes: &[u8], keyword: &str) -> Result<(String, u32, Warnings), BdError> {
    let mut warnings = vec![];

    // Wrap the Nom Parser `nom_parse_datestring_interval_field` to return a BdError if it fails.
    let (remaining, ymd, hms, nsecs) = match nom_parse_datestring_interval_field(field_bytes) {
        IResult::Done(remaining, (ymd, hms, nsecs)) => (remaining, ymd, hms, nsecs),
        _ => {
            let why = format!(
                "Error while parsing the following field: `{} {}`. \
                This field must follow the format: YYYY-MM-DD HH:MM:SS (NSEC s).",
                keyword,
                str::from_utf8(field_bytes).unwrap()
            );
            return Err(BdError(why));
        }
    };

    // Ignore any extra bytes, but add a warning.
    if !remaining.is_empty() {
        let warn = format!(
            "Warning while parsing the following field: `{} {}`. \
            This field contained unrecognized bytes following the format: YYYY-MM-DD HH:MM:SS (NSEC s).",
            keyword,
            str::from_utf8(field_bytes).unwrap()
        );
        warnings.push(warn);
    }

    let datestring = format!("{} {}", str::from_utf8(ymd).unwrap(), str::from_utf8(hms).unwrap());
    let nsecs_str = str::from_utf8(nsecs).unwrap();

    let n_secs_per_interval: u32 = match nsecs_str.parse() {
        Ok(num) => num,
        Err(ParserIntError) => {
            let why = format!(
                "Error while parsing the following field: `{} {}`. \
                The argument `{}` could not be parsed to a u32.",
                keyword,
                str::from_utf8(field_bytes).unwrap(),
                nsecs_str
            );
            return Err(BdError(why));
        }
    };

    let w: Warnings = match warnings.is_empty() {
        true => None,
        false => Some(warnings)
    };
    Ok((datestring, n_secs_per_interval, w))
}

fn parse_bw_history_field(field_bytes: &[u8], keyword: &str) -> Result<(String, u32, Vec<u64>, Warnings), BdError> {
    let mut warnings = vec![];

    // Wrap the Nom Parser `nom_parse_datestring_interval_field` to return a BdError if it fails.
    let (remaining, ymd, hms, nsecs) = match nom_parse_datestring_interval_field(field_bytes) {
        IResult::Done(remaining, (ymd, hms, nsecs)) => (remaining, ymd, hms, nsecs),
        _ => {
            let why = format!(
                "Error while parsing the following field: `{} {}`. \
                This field must follow the format: YYYY-MM-DD HH:MM:SS (NSEC s) NUM,NUM,NUM....",
                keyword,
                str::from_utf8(field_bytes).unwrap()
            );
            return Err(BdError(why));
        }
    };

    let datestring = format!("{} {}", str::from_utf8(ymd).unwrap(), str::from_utf8(hms).unwrap());
    let nsecs_str = str::from_utf8(nsecs).unwrap();

    let n_secs_per_interval: u32 = match nsecs_str.parse() {
        Ok(num) => num,
        Err(ParserIntError) => {
            let why = format!(
                "Error while parsing the following field: `{} {}`. \
                The argument `{}` could not be parsed to a u32.",
                keyword,
                str::from_utf8(field_bytes).unwrap(),
                nsecs_str
            );
            return Err(BdError(why));
        }
    };

    // Throw an error if the field is missing the required `n_bytes_per_interval` argument.
    if remaining.is_empty() {
        let why = format!(
            "Error while parsing the following field: `{} {}`. \
            Missing the 3rd required argument of the form: NUM,NUM,NUM....
            This field must follow the format: YYYY-MM-DD HH:MM:SS (NSEC s) NUM,NUM,NUM....",
            keyword,
            str::from_utf8(field_bytes).unwrap()
        );
        return Err(BdError(why));
    }

    let stripped = strip_char_from_bytes(remaining, '\n');
    let mut n_bytes_per_interval: Vec<u64> = vec![];

    // TODO:
    //   - Should add warning for extra argument after the NUM,NUM....

    for interval_bytes in split_bytes_at_char(&stripped, ',') {
        let interval_str = str::from_utf8(interval_bytes).unwrap();
        let n_bytes: u64= match interval_str.parse() {
            Ok(num) => num,
            Err(ParserIntError) => {
                let why = format!(
                    "Error while parsing the following field: `{} {}`. \
                    Could not convert `{}` to a u64.",
                    keyword,
                    str::from_utf8(field_bytes).unwrap(),
                    interval_str
                );
                return Err(BdError(why));
            }
        };
        n_bytes_per_interval.push(n_bytes);
    }

    let w: Warnings = match warnings.is_empty() {
        true => None,
        false => Some(warnings)
    };
    Ok((datestring, n_secs_per_interval, n_bytes_per_interval, w))
}

/// A wrapper around `parse_bw_history_field` for the `write-history` field.
///
fn parse_write_history_field(field_bytes: &[u8]) -> Result<(String, u32, Vec<u64>, Warnings), BdError> {
    parse_bw_history_field(field_bytes, "write-history")
}

/// A wrapper around `parse_bw_history_field` for the `read-history` field.
///
fn parse_read_history_field(field_bytes: &[u8]) -> Result<(String, u32, Vec<u64>, Warnings), BdError> {
    parse_bw_history_field(field_bytes, "read-history")
}

/// A wrapper around `parse_bw_history_field` for the `dirreq-write-history` field.
///
fn parse_dirreq_write_history_field(field_bytes: &[u8]) -> Result<(String, u32, Vec<u64>, Warnings), BdError> {
    parse_bw_history_field(field_bytes, "dirreq-write-history")
}

/// A wrapper around `parse_bw_history_field` for the `dirreq-read-history` field.
///
fn parse_dirreq_read_history_field(field_bytes: &[u8]) -> Result<(String, u32, Vec<u64>, Warnings), BdError> {
    parse_bw_history_field(field_bytes, "dirreq-read-history")
}

/// Parser for the fields: `geoip-db-digest` and `geoip6-db-digest`.
///
/// # Example
/// ```
/// let (digest, warnings) = parse_geoip_digest_field(field_bytes, "geoip-db-digest")?;
/// ```
///
fn parse_geoip_digest_field(field_bytes: &[u8], keyword: &str) -> Result<(String, Warnings), BdError> {
    let field_str = str::from_utf8(field_bytes).unwrap();
    let mut warnings = vec![];
    let args = split_bytes_at_char(field_bytes, ' ');
    let n_args = args.len();

    if n_args > 1 {
        let warn = format!(
            "Warning while parsing the following field: `{} {}`. \
            This field should have 1 argument, {} arguments were found.",
            keyword,
            field_str,
            n_args
        );
        warnings.push(warn);
    }

    let digest = str::from_utf8(args[0]).unwrap().to_string();
    let digest_length = digest.chars().count();

    if digest_length != 40 {
        let why = format!(
            "Error while parsing the following field: `{} {}`. \
            The digest must be 40 characaters long, {} characters were found.",
            keyword,
            field_str,
            digest_length
        );
        return Err(BdError(why));
    }

    let w: Warnings = match warnings.is_empty() {
        true => None,
        false => Some(warnings)
    };
    Ok((digest, w))
}

/// A wrapper around `parse_geoip_digest_field` for the `geoip-db-digest` field.
///
fn parse_geoip_db_digest_field(field_bytes: &[u8]) -> Result<(String, Warnings), BdError> {
    parse_geoip_digest_field(field_bytes, "geoip-db-digest")
}

/// A wrapper around `parse_geoip_digest_field` for the `geoip6-db-digest` field.
///
fn parse_geoip6_db_digest_field(field_bytes: &[u8]) -> Result<(String, Warnings), BdError> {
    parse_geoip_digest_field(field_bytes, "geoip6-db-digest")
}

fn parse_string_u32_key_value_field(field_bytes: &[u8], keyword: &str, check_country_codes: bool) -> Result<(HashMap<String, u32>, Warnings), BdError> {
    let mut warnings = vec![];
    let field_str = str::from_utf8(field_bytes).unwrap();

    // TODO:
    //   - Should you you check key-value pairs for valid country codes?
    //
    // let check_country_codes = match keyword {
    //     "dirreq-v3-ips" | "dirreq-v3-reqs" | "bridge-ips" => true,
    //     _ => false
    // };

    let stripped = strip_char_from_bytes(field_bytes, '\n');
    let mut counts = HashMap::new();

    for key_val_bytes in split_bytes_at_char(&stripped, ',') {
        let key_val_vec = split_bytes_at_char(key_val_bytes, '=');

        // Skip any malformed key-value pairs, but give a warning.
        if key_val_vec.len() != 2 {
            let warn = format!(
                "Warning while parsing the following field: `{} {}`. \
                Malformed key-value pair: `{}`",
                keyword,
                field_str,
                str::from_utf8(key_val_bytes).unwrap()
            );
            warnings.push(warn);
        }

        let key = str::from_utf8(key_val_vec[0]).unwrap().to_string();

        // Skip any malformed country-codes if you are parsing a country-code field.
        if check_country_codes {
            if key.chars().count() != 2 || key.contains('$') {
                let warn = format!(
                    "Warning while parsing the following field: `{} {}`. \
                    Malformed country-code: `{}`.",
                    keyword,
                    field_str,
                    key
                );
                warnings.push(warn);
                continue;
            }
        }

        // Skip any malformed values that could no be converted to a u32.
        let count_str = str::from_utf8(key_val_vec[1]).unwrap();
        let count: u32 = match count_str.parse() {
            Ok(value) => value,
            Err(ParseIntError) => {
                let warn = format!(
                    "Warning while parsing the following field: `{} {}`. \
                    The the value `{}` could not be converted to a u32.",
                    keyword,
                    field_str,
                    count_str
                );
                warnings.push(warn);
                continue;
            }
        };

        counts.insert(key, count);
    }

    let w: Warnings = match warnings.is_empty() {
        true => None,
        false => Some(warnings)
    };
    Ok((counts, w))
}

fn parse_dirreq_v3_ips_field(field_bytes: &[u8]) -> Result<(HashMap<String, u32>, Warnings), BdError> {
    parse_string_u32_key_value_field(field_bytes, "dirreq-v3-ips", true)
}

fn parse_dirreq_v3_reqs_field(field_bytes: &[u8]) -> Result<(HashMap<String, u32>, Warnings), BdError> {
    parse_string_u32_key_value_field(field_bytes, "dirreq-v3-reqs", true)
}

fn parse_dirreq_v3_resp_field(field_bytes: &[u8]) -> Result<(HashMap<String, u32>, Warnings), BdError> {
    parse_string_u32_key_value_field(field_bytes, "dirreq-v3-resp", false)
}

fn parse_dirreq_v3_direct_dl_field(field_bytes: &[u8]) -> Result<(HashMap<String, u32>, Warnings), BdError> {
    parse_string_u32_key_value_field(field_bytes, "dirreq-v3-direct-dl", false)
}

fn parse_dirreq_v3_tunneled_dl_field(field_bytes: &[u8]) -> Result<(HashMap<String, u32>, Warnings), BdError> {
    parse_string_u32_key_value_field(field_bytes, "dirreq-v3-tunneled-dl", false)
}

fn parse_bridge_ips_field(field_bytes: &[u8]) -> Result<(HashMap<String, u32>, Warnings), BdError> {
    parse_string_u32_key_value_field(field_bytes, "bridge-v3-ips", true)
}

fn parse_bridge_ip_versions_field(field_bytes: &[u8]) -> Result<(HashMap<String, u32>, Warnings), BdError> {
    parse_string_u32_key_value_field(field_bytes, "bridge-v3-versions", false)
}

fn parse_bridge_ip_transports_field(field_bytes: &[u8]) -> Result<(HashMap<String, u32>, Warnings), BdError> {
    parse_string_u32_key_value_field(field_bytes, "bridge-v3-transports", false)
}

fn parse_transport_field(field_bytes: &[u8]) -> Result<(PluggableTransport, Option<(String, u16)>, Option<Vec<String>>, Warnings), BdError> {
    let field_str = str::from_utf8(field_bytes).unwrap();
    let mut warnings = vec![];

    let mut ip_port: Option<(String, u16)> = None;
    let mut extra_args: Option<Vec<String>> = None;

    let args = split_bytes_at_char(field_bytes, ' ');
    let n_args = args.len();

    let transport = match PluggableTransport::from_bytes(args[0]) {
        Ok(transport) => transport,
        _ => {
            let why = format!(
                "Error while parsing the following field: `transport {}`. \
                `{}` is not a valid PluggableTransport.",
                field_str,
                str::from_utf8(args[0]).unwrap()
            );
            return Err(BdError(why));
        }
    };

    if n_args > 1 {
        let ip_port_vec = split_bytes_at_char(args[1], ':');

        if ip_port_vec.len() != 2 {
            let why = format!(
                "Error while parsing the following field: `transport {}`. \
                Malformed `ip:port` argument: `{}`.",
                field_str,
                str::from_utf8(args[1]).unwrap()
            );
            return Err(BdError(why));
        }

        let ip = str::from_utf8(ip_port_vec[0]).unwrap().to_string();
        let port: u16 = match str::from_utf8(ip_port_vec[1]).unwrap().parse() {
            Ok(num) => num,
            _ => {
                let why = format!(
                    "Error while parsing the following field: `transport {}`. \
                    The provided port in the `ip:port` argument could not be converted to a u16 `{}`.",
                    field_str,
                    str::from_utf8(args[1]).unwrap()
                );
                return Err(BdError(why));
            }
        };
        ip_port = Some((ip, port));
    }

    if n_args > 2 {
        let extra_args_as_strings: Vec<String> = split_bytes_at_char(args[2], ',').iter()
            .map(|bytes| str::from_utf8(bytes).unwrap().to_string())
            .collect();
        extra_args = Some(extra_args_as_strings);
    }

    let w: Warnings = match warnings.is_empty() {
        true => None,
        false => Some(warnings)
    };
    Ok((transport, ip_port, extra_args, w))
}

fn parse_router_sig_ed25519_field(field_bytes: &[u8]) -> Result<(String, Warnings), BdError> {
    let field_str = str::from_utf8(field_bytes).unwrap();
    let mut warnings = vec![];

    let args = split_bytes_at_char(field_bytes, ' ');
    let sig_length = args[0].len();

    if sig_length != 86 {
        let why = format!(
            "Error while parsing the following field: `router-sig-ed25519 {}`. \
            The signature must be 86 characaters long, {} characters were found.",
            field_str,
            sig_length
        );
        return Err(BdError(why));
    }

    let sig = str::from_utf8(args[0]).unwrap().to_string();
    let w: Warnings = match warnings.is_empty() {
        true => None,
        false => Some(warnings)
    };
    Ok((sig, w))
}

fn parse_router_signature_field(field_bytes: &[u8]) -> Result<(String, Warnings), BdError> {
    let field_str = str::from_utf8(field_bytes).unwrap();
    let mut warnings = vec![];

    let prefix = "-----BEGIN SIGNATURE-----\n".to_string();
    let suffix = "\n-----END SIGNATURE-----".to_string();

    let sig_bytes = match nom_parse_enveloped_block(field_bytes, prefix, suffix) {
        IResult::Done(remaining, sig_bytes) => {
            // Ignore any extra bytes following the signature, but give a warning.
            if !remaining.is_empty() {
                let warn = format!(
                    "Warning while parsing the following field: `router-signature\n{}`. \
                    Found extra bytes following the signature: `{}`.",
                    field_str,
                    str::from_utf8(remaining).unwrap()
                );
                warnings.push(warn);
            }
            sig_bytes
        },
        _ => {
            let why = format!(
                "Error while parsing the following field: `router-signature\n{}`. \
                This field must start with `-----BEGIN SIGNATURE-----` and must end with `-----END SIGNATURE-----`.",
                field_str
            );
            return Err(BdError(why));
        }
    };

    let sig_bytes_by_line = split_bytes_at_char(sig_bytes, '\n');
    let n_lines = sig_bytes_by_line.len();

    if n_lines != 3 {
        let why = format!(
            "Error while parsing the following field: `router-signature\n{}`. \
            The signature must be 3 lines long, {} were found.",
            field_str,
            n_lines
        );
        return Err(BdError(why));
    }

    let mut sig = String::new();
    for line_bytes in sig_bytes_by_line {
        let line_str = str::from_utf8(line_bytes).unwrap();
        let line_length = line_str.chars().count();

        // Certs must line-wrap after the 64th character.
        if line_length > 64 {
            let why = format!(
                "Error while parsing the following field: `router-signature\n{}`. \
                Each line in the signature must line-wrap after the 64th character, {} characters were found in a line.",
                field_str,
                line_length
            );
            return Err(BdError(why));
        }

        sig.push_str(line_str);
    }

    let w: Warnings = match warnings.is_empty() {
        true => None,
        false => Some(warnings)
    };
    Ok((sig, w))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_file_bytes_test() {
        let mut bytes = "should pass\n".as_bytes();
        assert_eq!(check_file_bytes(bytes), Ok(()));

        bytes = "should √ fail".as_bytes();
        assert!(check_file_bytes(bytes).is_err());
    }

    #[test]
    fn parse_hidserv_stats_field_test() {
        let bytes = "5079 delta_f=2048 epsilon=0.30 bin_size=1024".as_bytes();
        assert_eq!(
            parse_hidserv_stats_field(bytes, "hidserv-dir-onions-seen"),
            Ok((5079, 2048, 0.30, 1024, None))
        );
    }

    #[test]
    fn parse_stats_end_field_test() {
        let mut bytes = "2017-07-27 15:18:52 (86400 s)".as_bytes();
        assert_eq!(
            parse_stats_end_field(bytes, "hidserv-dir-onions-seen"),
            Ok(("2017-07-27 15:18:52".to_string(), 86400, None))
        );

        bytes = "2017-07-27 15:18:52 (86400".as_bytes();
        assert!(
            parse_stats_end_field(bytes, "hidserv-dir-onions-seen").is_err()
        );
    }

    #[test]
    fn parse_bw_history_field_test() {
        let mut bytes = "2017-07-27 16:13:50 (14400 s) 3975862272,2881896448".as_bytes();
        assert_eq!(
            parse_bw_history_field(bytes, "write-history"),
            Ok(("2017-07-27 16:13:50".to_string(), 14400, vec![3975862272, 2881896448], None))
        );

        bytes = "2017-07-27 16:13:50 (14400 3975862272,2881896448".as_bytes();
        assert!(
            parse_bw_history_field(bytes, "write-history").is_err()
        );
    }

    #[test]
    fn parse_geoip_db_digest_field_test() {
        let bytes = "AFD609025B66305AD9FA8E0B15AF4F2BC82271F1".as_bytes();
        assert_eq!(
            parse_geoip_db_digest_field(bytes),
            Ok(("AFD609025B66305AD9FA8E0B15AF4F2BC82271F1".to_string(), None))
        );
        assert!(
            parse_geoip_db_digest_field("AFD6".as_bytes()).is_err()
        );
    }
}
