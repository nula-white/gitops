"""
Go security sinks, sources, and sanitizers.

Format: name -> (SecurityLabel_str, confidence, (cwe_ids,...))
"""
from __future__ import annotations

GO_SINKS: dict[str, tuple[str, float, tuple[str, ...]]] = {

    # ── Command injection ──────────────────────────────────────────── CWE-78
    "exec.Command":                   ("SINK", 0.90, ("CWE-78",)),
    "exec.CommandContext":            ("SINK", 0.90, ("CWE-78",)),
    "os.StartProcess":                ("SINK", 0.90, ("CWE-78",)),
    "syscall.Exec":                   ("SINK", 0.95, ("CWE-78",)),
    "syscall.ForkExec":               ("SINK", 0.90, ("CWE-78",)),

    # ── SQL injection ──────────────────────────────────────────────── CWE-89
    "db.Query":                       ("SINK", 0.85, ("CWE-89",)),
    "db.QueryContext":                ("SINK", 0.85, ("CWE-89",)),
    "db.Exec":                        ("SINK", 0.85, ("CWE-89",)),
    "db.ExecContext":                 ("SINK", 0.85, ("CWE-89",)),
    "db.QueryRow":                    ("SINK", 0.85, ("CWE-89",)),
    "db.QueryRowContext":             ("SINK", 0.85, ("CWE-89",)),
    "tx.Query":                       ("SINK", 0.85, ("CWE-89",)),
    "tx.Exec":                        ("SINK", 0.85, ("CWE-89",)),
    "tx.QueryRow":                    ("SINK", 0.85, ("CWE-89",)),
    "conn.Query":                     ("SINK", 0.85, ("CWE-89",)),
    "conn.Exec":                      ("SINK", 0.85, ("CWE-89",)),
    "gorm.Raw":                       ("SINK", 0.90, ("CWE-89",)),    # GORM raw SQL
    "gorm.Exec":                      ("SINK", 0.75, ("CWE-89",)),
    "sqlx.Query":                     ("SINK", 0.85, ("CWE-89",)),    # sqlx
    "sqlx.Exec":                      ("SINK", 0.85, ("CWE-89",)),

    # ── Path traversal ─────────────────────────────────────────────── CWE-22
    "os.Open":                        ("SINK", 0.55, ("CWE-22",)),
    "os.OpenFile":                    ("SINK", 0.60, ("CWE-22",)),
    "os.Create":                      ("SINK", 0.60, ("CWE-22",)),
    "os.Remove":                      ("SINK", 0.65, ("CWE-22",)),
    "os.Rename":                      ("SINK", 0.65, ("CWE-22",)),
    "os.ReadFile":                    ("SINK", 0.55, ("CWE-22",)),
    "os.WriteFile":                   ("SINK", 0.60, ("CWE-22",)),
    "ioutil.ReadFile":                ("SINK", 0.55, ("CWE-22",)),
    "ioutil.WriteFile":               ("SINK", 0.60, ("CWE-22",)),
    "ioutil.TempFile":                ("SINK", 0.50, ("CWE-22",)),
    "filepath.Join":                  ("SINK", 0.40, ("CWE-22",)),
    "filepath.Abs":                   ("SINK", 0.40, ("CWE-22",)),
    "filepath.EvalSymlinks":          ("SINK", 0.45, ("CWE-22",)),
    "http.ServeFile":                 ("SINK", 0.65, ("CWE-22",)),
    "http.FileServer":                ("SINK", 0.60, ("CWE-22",)),

    # ── XSS ───────────────────────────────────────────────────────── CWE-79
    "fmt.Fprintf":                    ("SINK", 0.45, ("CWE-79",)),
    "fmt.Fprintln":                   ("SINK", 0.45, ("CWE-79",)),
    "fmt.Fprint":                     ("SINK", 0.45, ("CWE-79",)),
    "w.Write":                        ("SINK", 0.50, ("CWE-79",)),
    "w.WriteString":                  ("SINK", 0.50, ("CWE-79",)),
    "io.WriteString":                 ("SINK", 0.45, ("CWE-79",)),
    "template.HTML":                  ("SINK", 0.80, ("CWE-79",)),   # unsafe HTML cast
    "template.JS":                    ("SINK", 0.80, ("CWE-79",)),
    "template.URL":                   ("SINK", 0.75, ("CWE-79",)),

    # ── Insecure deserialization ───────────────────────────────────── CWE-502
    "json.Unmarshal":                 ("SINK", 0.40, ("CWE-502",)),
    "json.NewDecoder":                ("SINK", 0.40, ("CWE-502",)),
    "gob.Decode":                     ("SINK", 0.70, ("CWE-502",)),
    "gob.NewDecoder":                 ("SINK", 0.70, ("CWE-502",)),
    "yaml.Unmarshal":                 ("SINK", 0.50, ("CWE-502",)),
    "xml.Unmarshal":                  ("SINK", 0.50, ("CWE-502",)),

    # ── SSRF / outbound HTTP ──────────────────────────────────────── CWE-918
    "http.Get":                       ("SINK", 0.55, ("CWE-918",)),
    "http.Post":                      ("SINK", 0.55, ("CWE-918",)),
    "http.Head":                      ("SINK", 0.55, ("CWE-918",)),
    "http.Do":                        ("SINK", 0.55, ("CWE-918",)),
    "http.NewRequest":                ("SINK", 0.55, ("CWE-918",)),
    "client.Get":                     ("SINK", 0.55, ("CWE-918",)),
    "client.Do":                      ("SINK", 0.55, ("CWE-918",)),

    # ── Weak cryptography ─────────────────────────────────────────── CWE-327
    "md5.New":                        ("SINK", 0.70, ("CWE-327",)),
    "md5.Sum":                        ("SINK", 0.70, ("CWE-327",)),
    "sha1.New":                       ("SINK", 0.60, ("CWE-327",)),
    "sha1.Sum":                       ("SINK", 0.60, ("CWE-327",)),
    "des.NewCipher":                  ("SINK", 0.90, ("CWE-327",)),
    "rc4.NewCipher":                  ("SINK", 0.85, ("CWE-327",)),

    # ── LDAP injection ────────────────────────────────────────────── CWE-90
    "ldap.Conn.Search":               ("SINK", 0.85, ("CWE-90",)),
    "l.Search":                       ("SINK", 0.80, ("CWE-90",)),
    "l.SearchWithPaging":             ("SINK", 0.80, ("CWE-90",)),

    # ── Log injection ─────────────────────────────────────────────── CWE-117
    "log.Print":                      ("SINK", 0.25, ("CWE-117",)),
    "log.Println":                    ("SINK", 0.25, ("CWE-117",)),
    "log.Printf":                     ("SINK", 0.25, ("CWE-117",)),
    "log.Fatal":                      ("SINK", 0.25, ("CWE-117",)),

    # ── Open redirect ─────────────────────────────────────────────── CWE-601
    "http.Redirect":                  ("SINK", 0.70, ("CWE-601",)),

    # ── Template injection ────────────────────────────────────────── CWE-94
    "text/template.Execute":          ("SINK", 0.70, ("CWE-94",)),   # unescaped output
    "template.Must":                  ("SINK", 0.50, ("CWE-94",)),
}

GO_SOURCES: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── net/http request inputs ─────────────────────────────────────────────
    "r.URL.Query":                    ("SOURCE", 0.99, ("CWE-20",)),
    "r.URL.Query().Get":              ("SOURCE", 0.99, ("CWE-20",)),
    "r.FormValue":                    ("SOURCE", 0.99, ("CWE-20",)),
    "r.PostFormValue":                ("SOURCE", 0.99, ("CWE-20",)),
    "r.Form.Get":                     ("SOURCE", 0.99, ("CWE-20",)),
    "r.PostForm.Get":                 ("SOURCE", 0.99, ("CWE-20",)),
    "r.MultipartForm":                ("SOURCE", 0.95, ("CWE-20",)),
    "r.Header.Get":                   ("SOURCE", 0.90, ("CWE-20",)),
    "r.Header":                       ("SOURCE", 0.90, ("CWE-20",)),
    "r.Cookie":                       ("SOURCE", 0.90, ("CWE-20",)),
    "r.Cookies":                      ("SOURCE", 0.90, ("CWE-20",)),
    "r.Body":                         ("SOURCE", 0.95, ("CWE-20",)),
    "r.URL.Path":                     ("SOURCE", 0.85, ("CWE-20",)),
    "r.URL.RawQuery":                 ("SOURCE", 0.90, ("CWE-20",)),
    "r.RemoteAddr":                   ("SOURCE", 0.70, ("CWE-20",)),
    # ── Environment ─────────────────────────────────────────────────────────
    "os.Getenv":                      ("SOURCE", 0.70, ("CWE-214",)),
    "os.LookupEnv":                   ("SOURCE", 0.70, ("CWE-214",)),
    # ── CLI / stdin ─────────────────────────────────────────────────────────
    "os.Args":                        ("SOURCE", 0.85, ("CWE-88",)),
    "flag.String":                    ("SOURCE", 0.75, ("CWE-88",)),
    "flag.Arg":                       ("SOURCE", 0.75, ("CWE-88",)),
    "bufio.NewScanner":               ("SOURCE", 0.80, ("CWE-20",)),
    "bufio.NewReader":                ("SOURCE", 0.80, ("CWE-20",)),
    "fmt.Scan":                       ("SOURCE", 0.80, ("CWE-20",)),
    "fmt.Scanln":                     ("SOURCE", 0.80, ("CWE-20",)),
    "fmt.Scanf":                      ("SOURCE", 0.75, ("CWE-20",)),
    # ── Framework-specific ──────────────────────────────────────────────────
    "c.Query":                        ("SOURCE", 0.99, ("CWE-20",)),   # Gin
    "c.Param":                        ("SOURCE", 0.99, ("CWE-20",)),
    "c.PostForm":                     ("SOURCE", 0.99, ("CWE-20",)),
    "c.GetHeader":                    ("SOURCE", 0.90, ("CWE-20",)),
    "c.Cookie":                       ("SOURCE", 0.90, ("CWE-20",)),
    "ctx.Query":                      ("SOURCE", 0.99, ("CWE-20",)),   # Echo/Fiber
    "ctx.Param":                      ("SOURCE", 0.99, ("CWE-20",)),
    "ctx.FormValue":                  ("SOURCE", 0.99, ("CWE-20",)),
    "ctx.Get":                        ("SOURCE", 0.80, ("CWE-20",)),
}

GO_SANITIZERS: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── XSS ─────────────────────────────────────────────────────────────────
    "html.EscapeString":              ("SANITIZER", 0.90, ("CWE-79",)),
    "template.HTMLEscapeString":      ("SANITIZER", 0.90, ("CWE-79",)),
    "template.JSEscapeString":        ("SANITIZER", 0.90, ("CWE-79",)),
    # ── URL encoding ─────────────────────────────────────────────────────────
    "url.QueryEscape":                ("SANITIZER", 0.85, ("CWE-116",)),
    "url.PathEscape":                 ("SANITIZER", 0.80, ("CWE-116",)),
    "url.Values.Encode":              ("SANITIZER", 0.85, ("CWE-116",)),
    # ── SQL parameterisation ─────────────────────────────────────────────────
    "db.Prepare":                     ("SANITIZER", 0.90, ("CWE-89",)),
    "db.PrepareContext":              ("SANITIZER", 0.90, ("CWE-89",)),
    "tx.Prepare":                     ("SANITIZER", 0.90, ("CWE-89",)),
    "sqlx.Preparex":                  ("SANITIZER", 0.90, ("CWE-89",)),
    # ── Path canonicalisation ────────────────────────────────────────────────
    "filepath.Clean":                 ("SANITIZER", 0.65, ("CWE-22",)),
    "filepath.Base":                  ("SANITIZER", 0.70, ("CWE-22",)),
    # ── Regex safety ─────────────────────────────────────────────────────────
    "regexp.QuoteMeta":               ("SANITIZER", 0.80, ("CWE-78",)),
    # ── Generic ──────────────────────────────────────────────────────────────
    "validate":                       ("SANITIZER", 0.60, ()),
    "sanitize":                       ("SANITIZER", 0.65, ()),
    "govalidator.IsURL":              ("SANITIZER", 0.80, ("CWE-601",)),
    "govalidator.IsEmail":            ("SANITIZER", 0.75, ("CWE-20",)),
}


# Self-contained registry for Go:
#   from prism.parser.sinks.go_sinks import GO_SINK_REGISTRY
GO_SINK_REGISTRY: dict[str, dict] = {
    "sinks":      GO_SINKS,
    "sources":    GO_SOURCES,
    "sanitizers": GO_SANITIZERS,
}