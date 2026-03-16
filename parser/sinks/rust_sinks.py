"""
Rust security sinks, sources, and sanitizers.

Rust's ownership model eliminates most memory-safety bugs at compile time,
but security vulnerabilities still exist in:
  - `unsafe` blocks (raw pointer operations, FFI)
  - Command execution / shell injection
  - Path traversal in file operations
  - SQL injection via query builders
  - SSRF via HTTP client libraries
  - Deserialization vulnerabilities (serde, bincode, prost)
  - Weak or misused cryptography

Format: name -> (SecurityLabel_str, confidence, (cwe_ids,...))
"""
from __future__ import annotations

RUST_SINKS: dict[str, tuple[str, float, tuple[str, ...]]] = {

    # ── Command injection ──────────────────────────────────────────── CWE-78
    "Command::new":                   ("SINK", 0.85, ("CWE-78",)),
    "std::process::Command::new":     ("SINK", 0.85, ("CWE-78",)),
    "Command::arg":                   ("SINK", 0.70, ("CWE-78",)),
    "Command::args":                  ("SINK", 0.70, ("CWE-78",)),
    "Command::spawn":                 ("SINK", 0.80, ("CWE-78",)),
    "Command::output":                ("SINK", 0.80, ("CWE-78",)),
    "Command::status":                ("SINK", 0.80, ("CWE-78",)),
    "process::Command":               ("SINK", 0.85, ("CWE-78",)),

    # ── Unsafe memory operations ───────────────────────────────────── CWE-119
    "from_raw_parts":                 ("SINK", 0.80, ("CWE-119",)),
    "from_raw_parts_mut":             ("SINK", 0.80, ("CWE-119",)),
    "transmute":                      ("SINK", 0.90, ("CWE-119", "CWE-843")),
    "transmute_copy":                 ("SINK", 0.90, ("CWE-119", "CWE-843")),
    "unsafe":                         ("SINK", 0.60, ("CWE-119",)),
    "ptr::read":                      ("SINK", 0.75, ("CWE-119",)),
    "ptr::write":                     ("SINK", 0.75, ("CWE-119",)),
    "ptr::read_unaligned":            ("SINK", 0.80, ("CWE-119",)),
    "ptr::write_unaligned":           ("SINK", 0.80, ("CWE-119",)),
    "ptr::offset":                    ("SINK", 0.70, ("CWE-119",)),
    "ptr::add":                       ("SINK", 0.70, ("CWE-119",)),
    "ptr::sub":                       ("SINK", 0.70, ("CWE-119",)),
    "ptr::copy_nonoverlapping":       ("SINK", 0.75, ("CWE-119",)),
    "Box::from_raw":                  ("SINK", 0.80, ("CWE-119",)),
    "Arc::from_raw":                  ("SINK", 0.80, ("CWE-119",)),
    "Rc::from_raw":                   ("SINK", 0.80, ("CWE-119",)),
    "String::from_raw_parts":         ("SINK", 0.80, ("CWE-119",)),
    "Vec::from_raw_parts":            ("SINK", 0.80, ("CWE-119",)),
    "slice::from_raw_parts":          ("SINK", 0.80, ("CWE-119",)),

    # ── Path traversal ─────────────────────────────────────────────── CWE-22
    "File::open":                     ("SINK", 0.55, ("CWE-22",)),
    "File::create":                   ("SINK", 0.60, ("CWE-22",)),
    "File::options":                  ("SINK", 0.55, ("CWE-22",)),
    "OpenOptions::new":               ("SINK", 0.55, ("CWE-22",)),
    "fs::read":                       ("SINK", 0.55, ("CWE-22",)),
    "fs::read_to_string":             ("SINK", 0.55, ("CWE-22",)),
    "fs::write":                      ("SINK", 0.60, ("CWE-22",)),
    "fs::remove_file":                ("SINK", 0.65, ("CWE-22",)),
    "fs::remove_dir":                 ("SINK", 0.65, ("CWE-22",)),
    "fs::remove_dir_all":             ("SINK", 0.70, ("CWE-22",)),
    "fs::rename":                     ("SINK", 0.65, ("CWE-22",)),
    "fs::copy":                       ("SINK", 0.60, ("CWE-22",)),
    "Path::new":                      ("SINK", 0.40, ("CWE-22",)),
    "PathBuf::from":                  ("SINK", 0.40, ("CWE-22",)),
    "Path::join":                     ("SINK", 0.45, ("CWE-22",)),

    # ── SQL injection ──────────────────────────────────────────────── CWE-89
    "query":                          ("SINK", 0.65, ("CWE-89",)),
    "execute":                        ("SINK", 0.65, ("CWE-89",)),
    "sqlx::query":                    ("SINK", 0.75, ("CWE-89",)),
    "sqlx::query_as":                 ("SINK", 0.75, ("CWE-89",)),
    "diesel::sql_query":              ("SINK", 0.85, ("CWE-89",)),   # raw SQL in Diesel
    "conn.execute":                   ("SINK", 0.70, ("CWE-89",)),
    "pool.execute":                   ("SINK", 0.70, ("CWE-89",)),

    # ── Insecure deserialization ───────────────────────────────────── CWE-502
    "serde_json::from_str":           ("SINK", 0.40, ("CWE-502",)),
    "serde_json::from_slice":         ("SINK", 0.40, ("CWE-502",)),
    "serde_json::from_reader":        ("SINK", 0.40, ("CWE-502",)),
    "bincode::deserialize":           ("SINK", 0.70, ("CWE-502",)),
    "bincode::decode_from_slice":     ("SINK", 0.70, ("CWE-502",)),
    "prost::Message::decode":         ("SINK", 0.50, ("CWE-502",)),
    "postcard::from_bytes":           ("SINK", 0.60, ("CWE-502",)),
    "rmp_serde::decode::from_slice":  ("SINK", 0.70, ("CWE-502",)),

    # ── SSRF / outbound HTTP ──────────────────────────────────────── CWE-918
    "reqwest::get":                   ("SINK", 0.55, ("CWE-918",)),
    "reqwest::Client::get":           ("SINK", 0.55, ("CWE-918",)),
    "reqwest::Client::post":          ("SINK", 0.55, ("CWE-918",)),
    "reqwest::Client::request":       ("SINK", 0.55, ("CWE-918",)),
    "reqwest::blocking::get":         ("SINK", 0.55, ("CWE-918",)),
    "hyper::Client::get":             ("SINK", 0.55, ("CWE-918",)),
    "ureq::get":                      ("SINK", 0.55, ("CWE-918",)),
    "ureq::post":                     ("SINK", 0.55, ("CWE-918",)),
    "TcpStream::connect":             ("SINK", 0.45, ("CWE-918",)),

    # ── Weak cryptography ─────────────────────────────────────────── CWE-327
    "md5::compute":                   ("SINK", 0.70, ("CWE-327",)),
    "md5::Md5::new":                  ("SINK", 0.70, ("CWE-327",)),
    "sha1::Sha1::new":                ("SINK", 0.60, ("CWE-327",)),
    "des::Des::new":                  ("SINK", 0.90, ("CWE-327",)),
    "rc4::Rc4::new":                  ("SINK", 0.85, ("CWE-327",)),

    # ── Log injection ─────────────────────────────────────────────── CWE-117
    "log::info":                      ("SINK", 0.25, ("CWE-117",)),
    "log::warn":                      ("SINK", 0.25, ("CWE-117",)),
    "log::error":                     ("SINK", 0.25, ("CWE-117",)),
    "log::debug":                     ("SINK", 0.20, ("CWE-117",)),
    "tracing::info":                  ("SINK", 0.25, ("CWE-117",)),
    "tracing::warn":                  ("SINK", 0.25, ("CWE-117",)),
    "println!":                       ("SINK", 0.15, ("CWE-117",)),
    "eprintln!":                      ("SINK", 0.15, ("CWE-117",)),

    # ── Format injection ──────────────────────────────────────────── CWE-134
    "format!":                        ("SINK", 0.35, ("CWE-134",)),   # only dangerous with user fmt string
    "panic!":                         ("SINK", 0.30, ("CWE-117",)),
}

RUST_SOURCES: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── Environment / args ──────────────────────────────────────────────────
    "std::env::args":                 ("SOURCE", 0.90, ("CWE-88",)),
    "env::args":                      ("SOURCE", 0.90, ("CWE-88",)),
    "std::env::var":                  ("SOURCE", 0.70, ("CWE-214",)),
    "env::var":                       ("SOURCE", 0.70, ("CWE-214",)),
    "std::env::vars":                 ("SOURCE", 0.70, ("CWE-214",)),
    # ── Stdin ───────────────────────────────────────────────────────────────
    "stdin().read_line":              ("SOURCE", 0.90, ("CWE-20",)),
    "io::stdin":                      ("SOURCE", 0.85, ("CWE-20",)),
    "BufRead::lines":                 ("SOURCE", 0.75, ("CWE-20",)),
    "Read::read_to_string":           ("SOURCE", 0.75, ("CWE-20",)),
    # ── Actix-web ───────────────────────────────────────────────────────────
    "HttpRequest::query_string":      ("SOURCE", 0.95, ("CWE-20",)),
    "web::Query":                     ("SOURCE", 0.99, ("CWE-20",)),
    "web::Path":                      ("SOURCE", 0.95, ("CWE-20",)),
    "web::Form":                      ("SOURCE", 0.99, ("CWE-20",)),
    "web::Json":                      ("SOURCE", 0.99, ("CWE-20",)),
    "HttpRequest::headers":           ("SOURCE", 0.90, ("CWE-20",)),
    "HttpRequest::cookie":            ("SOURCE", 0.90, ("CWE-20",)),
    # ── Axum ────────────────────────────────────────────────────────────────
    "axum::extract::Path":            ("SOURCE", 0.95, ("CWE-20",)),
    "axum::extract::Query":           ("SOURCE", 0.99, ("CWE-20",)),
    "axum::extract::Form":            ("SOURCE", 0.99, ("CWE-20",)),
    "axum::extract::Json":            ("SOURCE", 0.99, ("CWE-20",)),
    "axum::extract::TypedHeader":     ("SOURCE", 0.90, ("CWE-20",)),
    # ── Rocket ──────────────────────────────────────────────────────────────
    "rocket::request::Request::param": ("SOURCE", 0.95, ("CWE-20",)),
    "rocket::form::Form":             ("SOURCE", 0.99, ("CWE-20",)),
    "rocket::serde::json::Json":      ("SOURCE", 0.99, ("CWE-20",)),
    "Request::body":                  ("SOURCE", 0.95, ("CWE-20",)),
    "request.param":                  ("SOURCE", 0.95, ("CWE-20",)),
    # ── Network reads ───────────────────────────────────────────────────────
    "TcpStream::read":                ("SOURCE", 0.75, ("CWE-20",)),
    "UdpSocket::recv_from":           ("SOURCE", 0.75, ("CWE-20",)),
}

RUST_SANITIZERS: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── XSS ─────────────────────────────────────────────────────────────────
    "html_escape::encode_text":       ("SANITIZER", 0.90, ("CWE-79",)),
    "html_escape::encode_safe":       ("SANITIZER", 0.85, ("CWE-79",)),
    "askama::Html":                   ("SANITIZER", 0.85, ("CWE-79",)),  # Askama auto-escape
    "ammonia::clean":                 ("SANITIZER", 0.95, ("CWE-79",)),  # HTML sanitizer
    "ammonia::Builder::clean":        ("SANITIZER", 0.95, ("CWE-79",)),
    # ── URL encoding ─────────────────────────────────────────────────────────
    "urlencoding::encode":            ("SANITIZER", 0.85, ("CWE-116",)),
    "percent_encoding::utf8_percent_encode": ("SANITIZER", 0.85, ("CWE-116",)),
    "url::form_urlencoded::Serializer": ("SANITIZER", 0.85, ("CWE-116",)),
    # ── SQL parameterisation ─────────────────────────────────────────────────
    "sqlx::query!":                   ("SANITIZER", 0.95, ("CWE-89",)),  # macro with compile-time check
    "sqlx::query_as!":                ("SANITIZER", 0.95, ("CWE-89",)),
    "diesel::QueryBuilder":           ("SANITIZER", 0.85, ("CWE-89",)),
    # ── Path canonicalisation ────────────────────────────────────────────────
    "Path::canonicalize":             ("SANITIZER", 0.70, ("CWE-22",)),
    "fs::canonicalize":               ("SANITIZER", 0.70, ("CWE-22",)),
    # ── Type coercion (eliminates string injection) ───────────────────────────
    "u64::from_str":                  ("SANITIZER", 0.70, ("CWE-20",)),
    "i64::from_str":                  ("SANITIZER", 0.70, ("CWE-20",)),
    "f64::from_str":                  ("SANITIZER", 0.65, ("CWE-20",)),
    # ── Generic ──────────────────────────────────────────────────────────────
    "validate":                       ("SANITIZER", 0.60, ()),
    "sanitize":                       ("SANITIZER", 0.65, ()),
    "validator::Validate":            ("SANITIZER", 0.80, ()),
    # ── Cryptographic ────────────────────────────────────────────────────────
    "sha2::Sha256":                   ("SANITIZER", 0.75, ("CWE-327",)),
    "sha2::Sha512":                   ("SANITIZER", 0.75, ("CWE-327",)),
    "sha3::Sha3_256":                 ("SANITIZER", 0.80, ("CWE-327",)),
    "argon2::hash_encoded":           ("SANITIZER", 0.90, ("CWE-327",)),
    "bcrypt::hash":                   ("SANITIZER", 0.90, ("CWE-327",)),
    "rand::rngs::OsRng":              ("SANITIZER", 0.85, ("CWE-338",)),
}


# Self-contained registry for Rust:
#   from prism.parser.sinks.rust_sinks import RUST_SINK_REGISTRY
RUST_SINK_REGISTRY: dict[str, dict] = {
    "sinks":      RUST_SINKS,
    "sources":    RUST_SOURCES,
    "sanitizers": RUST_SANITIZERS,
}