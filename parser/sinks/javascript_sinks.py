"""
JavaScript / TypeScript / TSX security sinks, sources, and sanitizers.

Covers browser DOM, Node.js server-side, and modern frameworks
(Express, Next.js, React, Vue, Angular — common sink patterns).

Format: name -> (SecurityLabel_str, confidence, (cwe_ids,...))
"""
from __future__ import annotations

JS_SINKS: dict[str, tuple[str, float, tuple[str, ...]]] = {

    # ── DOM XSS ───────────────────────────────────────────────────── CWE-79
    "innerHTML":                      ("SINK", 0.95, ("CWE-79",)),
    "outerHTML":                      ("SINK", 0.95, ("CWE-79",)),
    "document.write":                 ("SINK", 0.95, ("CWE-79",)),
    "document.writeln":               ("SINK", 0.95, ("CWE-79",)),
    "insertAdjacentHTML":             ("SINK", 0.90, ("CWE-79",)),
    "createContextualFragment":       ("SINK", 0.90, ("CWE-79",)),
    "srcdoc":                         ("SINK", 0.85, ("CWE-79",)),
    "dangerouslySetInnerHTML":        ("SINK", 0.95, ("CWE-79",)),  # React
    "v-html":                         ("SINK", 0.90, ("CWE-79",)),  # Vue
    "[innerHTML]":                    ("SINK", 0.90, ("CWE-79",)),  # Angular
    "bypassSecurityTrustHtml":        ("SINK", 0.90, ("CWE-79",)),  # Angular DomSanitizer bypass
    "bypassSecurityTrustScript":      ("SINK", 0.95, ("CWE-79",)),
    "bypassSecurityTrustResourceUrl": ("SINK", 0.90, ("CWE-79",)),
    "postMessage":                    ("SINK", 0.60, ("CWE-79",)),   # only dangerous if origin not checked

    # ── Code injection ────────────────────────────────────────────── CWE-94/95
    "eval":                           ("SINK", 0.98, ("CWE-78", "CWE-95")),
    "Function":                       ("SINK", 0.90, ("CWE-95",)),
    "new Function":                   ("SINK", 0.90, ("CWE-95",)),
    "setTimeout":                     ("SINK", 0.70, ("CWE-95",)),   # with string arg
    "setInterval":                    ("SINK", 0.70, ("CWE-95",)),
    "setImmediate":                   ("SINK", 0.65, ("CWE-95",)),
    "vm.runInNewContext":              ("SINK", 0.80, ("CWE-95",)),  # Node.js vm
    "vm.runInThisContext":            ("SINK", 0.80, ("CWE-95",)),

    # ── Command injection (Node.js) ───────────────────────────────── CWE-78
    "exec":                           ("SINK", 0.85, ("CWE-78",)),
    "execSync":                       ("SINK", 0.85, ("CWE-78",)),
    "execFile":                       ("SINK", 0.80, ("CWE-78",)),
    "execFileSync":                   ("SINK", 0.80, ("CWE-78",)),
    "spawn":                          ("SINK", 0.80, ("CWE-78",)),
    "spawnSync":                      ("SINK", 0.80, ("CWE-78",)),
    "fork":                           ("SINK", 0.65, ("CWE-78",)),
    "child_process.exec":             ("SINK", 0.90, ("CWE-78",)),
    "child_process.spawn":            ("SINK", 0.85, ("CWE-78",)),
    "shelljs.exec":                   ("SINK", 0.90, ("CWE-78",)),

    # ── SQL injection ─────────────────────────────────────────────── CWE-89
    "query":                          ("SINK", 0.75, ("CWE-89",)),
    "raw":                            ("SINK", 0.80, ("CWE-89",)),   # knex.raw
    "sequelize.query":                ("SINK", 0.85, ("CWE-89",)),
    "db.query":                       ("SINK", 0.80, ("CWE-89",)),
    "pool.query":                     ("SINK", 0.80, ("CWE-89",)),
    "connection.query":               ("SINK", 0.80, ("CWE-89",)),
    "$where":                         ("SINK", 0.90, ("CWE-89",)),   # MongoDB NoSQL injection
    "$regex":                         ("SINK", 0.75, ("CWE-89",)),

    # ── Path traversal (Node.js) ──────────────────────────────────── CWE-22
    "fs.readFile":                    ("SINK", 0.55, ("CWE-22",)),
    "fs.readFileSync":                ("SINK", 0.55, ("CWE-22",)),
    "fs.writeFile":                   ("SINK", 0.60, ("CWE-22",)),
    "fs.writeFileSync":               ("SINK", 0.60, ("CWE-22",)),
    "fs.appendFile":                  ("SINK", 0.60, ("CWE-22",)),
    "fs.unlink":                      ("SINK", 0.65, ("CWE-22",)),
    "fs.readdir":                     ("SINK", 0.50, ("CWE-22",)),
    "fs.createReadStream":            ("SINK", 0.60, ("CWE-22",)),
    "fs.createWriteStream":           ("SINK", 0.65, ("CWE-22",)),
    "path.join":                      ("SINK", 0.40, ("CWE-22",)),
    "path.resolve":                   ("SINK", 0.40, ("CWE-22",)),
    "require":                        ("SINK", 0.60, ("CWE-22",)),   # dynamic require()

    # ── Insecure deserialization ───────────────────────────────────── CWE-502
    "JSON.parse":                     ("SINK", 0.40, ("CWE-502",)),   # low conf, very common
    "deserialize":                    ("SINK", 0.85, ("CWE-502",)),
    "unserialize":                    ("SINK", 0.90, ("CWE-502",)),   # node-serialize
    "yaml.load":                      ("SINK", 0.90, ("CWE-502",)),   # js-yaml unsafe load
    "YAML.load":                      ("SINK", 0.90, ("CWE-502",)),
    "pickle.loads":                   ("SINK", 0.99, ("CWE-502",)),

    # ── SSRF / outbound HTTP ──────────────────────────────────────── CWE-918
    "fetch":                          ("SINK", 0.50, ("CWE-918",)),
    "axios.get":                      ("SINK", 0.50, ("CWE-918",)),
    "axios.post":                     ("SINK", 0.50, ("CWE-918",)),
    "axios.request":                  ("SINK", 0.50, ("CWE-918",)),
    "http.request":                   ("SINK", 0.55, ("CWE-918",)),
    "https.request":                  ("SINK", 0.55, ("CWE-918",)),
    "got":                            ("SINK", 0.50, ("CWE-918",)),
    "got.get":                        ("SINK", 0.50, ("CWE-918",)),
    "superagent.get":                 ("SINK", 0.50, ("CWE-918",)),
    "request.get":                    ("SINK", 0.50, ("CWE-918",)),
    "node-fetch":                     ("SINK", 0.50, ("CWE-918",)),
    "XMLHttpRequest.open":            ("SINK", 0.65, ("CWE-918",)),

    # ── Prototype pollution ───────────────────────────────────────── CWE-1321
    "Object.assign":                  ("SINK", 0.50, ("CWE-1321",)),
    "merge":                          ("SINK", 0.55, ("CWE-1321",)),
    "extend":                         ("SINK", 0.50, ("CWE-1321",)),
    "deepmerge":                      ("SINK", 0.60, ("CWE-1321",)),
    "_.merge":                        ("SINK", 0.65, ("CWE-1321",)),   # Lodash
    "$.extend":                       ("SINK", 0.65, ("CWE-1321",)),   # jQuery
    "assign":                         ("SINK", 0.45, ("CWE-1321",)),

    # ── Open redirect ─────────────────────────────────────────────── CWE-601
    "location.href":                  ("SINK", 0.75, ("CWE-601",)),
    "location.replace":               ("SINK", 0.75, ("CWE-601",)),
    "location.assign":                ("SINK", 0.75, ("CWE-601",)),
    "window.location":                ("SINK", 0.75, ("CWE-601",)),
    "res.redirect":                   ("SINK", 0.65, ("CWE-601",)),   # Express

    # ── Log injection ─────────────────────────────────────────────── CWE-117
    "console.log":                    ("SINK", 0.20, ("CWE-117",)),
    "console.error":                  ("SINK", 0.20, ("CWE-117",)),
    "console.warn":                   ("SINK", 0.20, ("CWE-117",)),
    "logger.info":                    ("SINK", 0.30, ("CWE-117",)),
    "logger.error":                   ("SINK", 0.30, ("CWE-117",)),

    # ── ReDoS ─────────────────────────────────────────────────────── CWE-1333
    "new RegExp":                     ("SINK", 0.55, ("CWE-1333",)),   # with user input
    "RegExp":                         ("SINK", 0.50, ("CWE-1333",)),

    # ── Weak crypto ───────────────────────────────────────────────── CWE-327
    "createHash":                     ("SINK", 0.50, ("CWE-327",)),   # bad with 'md5'/'sha1'
    "createCipher":                   ("SINK", 0.80, ("CWE-327",)),   # deprecated — no IV
    "crypto.createCipher":            ("SINK", 0.80, ("CWE-327",)),
}

JS_SOURCES: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── Express / Koa / Fastify request ─────────────────────────────────────
    "req.params":                     ("SOURCE", 0.99, ("CWE-20",)),
    "req.query":                      ("SOURCE", 0.99, ("CWE-20",)),
    "req.body":                       ("SOURCE", 0.99, ("CWE-20",)),
    "req.headers":                    ("SOURCE", 0.90, ("CWE-20",)),
    "req.cookies":                    ("SOURCE", 0.90, ("CWE-20",)),
    "req.files":                      ("SOURCE", 0.90, ("CWE-20",)),
    "req.url":                        ("SOURCE", 0.85, ("CWE-20",)),
    "req.path":                       ("SOURCE", 0.80, ("CWE-20",)),
    "request.params":                 ("SOURCE", 0.99, ("CWE-20",)),
    "request.query":                  ("SOURCE", 0.99, ("CWE-20",)),
    "request.body":                   ("SOURCE", 0.99, ("CWE-20",)),
    "ctx.query":                      ("SOURCE", 0.99, ("CWE-20",)),   # Koa
    "ctx.params":                     ("SOURCE", 0.99, ("CWE-20",)),
    "ctx.request.body":               ("SOURCE", 0.99, ("CWE-20",)),
    # ── Browser DOM ─────────────────────────────────────────────────────────
    "location.search":                ("SOURCE", 0.90, ("CWE-20",)),
    "location.hash":                  ("SOURCE", 0.85, ("CWE-20",)),
    "location.href":                  ("SOURCE", 0.85, ("CWE-20",)),
    "document.cookie":                ("SOURCE", 0.90, ("CWE-20",)),
    "window.name":                    ("SOURCE", 0.80, ("CWE-20",)),
    "document.referrer":              ("SOURCE", 0.85, ("CWE-20",)),
    "document.URL":                   ("SOURCE", 0.80, ("CWE-20",)),
    "URLSearchParams.get":            ("SOURCE", 0.90, ("CWE-20",)),
    # ── Browser storage ─────────────────────────────────────────────────────
    "localStorage.getItem":           ("SOURCE", 0.75, ("CWE-20",)),
    "sessionStorage.getItem":         ("SOURCE", 0.75, ("CWE-20",)),
    # ── Event data ──────────────────────────────────────────────────────────
    "event.data":                     ("SOURCE", 0.75, ("CWE-20",)),   # postMessage
    "event.target.value":             ("SOURCE", 0.80, ("CWE-20",)),
    "e.target.value":                 ("SOURCE", 0.80, ("CWE-20",)),
    "message.data":                   ("SOURCE", 0.80, ("CWE-20",)),   # WebSocket
    # ── Node.js environment ─────────────────────────────────────────────────
    "process.env":                    ("SOURCE", 0.70, ("CWE-214",)),
    "process.argv":                   ("SOURCE", 0.85, ("CWE-88",)),
    "process.stdin":                  ("SOURCE", 0.80, ("CWE-20",)),
}

JS_SANITIZERS: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── XSS ─────────────────────────────────────────────────────────────────
    "DOMPurify.sanitize":             ("SANITIZER", 0.95, ("CWE-79",)),
    "sanitizeHtml":                   ("SANITIZER", 0.90, ("CWE-79",)),
    "xss":                            ("SANITIZER", 0.85, ("CWE-79",)),
    "xss.filterXSS":                  ("SANITIZER", 0.90, ("CWE-79",)),
    "striptags":                      ("SANITIZER", 0.80, ("CWE-79",)),
    "he.encode":                      ("SANITIZER", 0.90, ("CWE-79",)),   # he library
    "he.escape":                      ("SANITIZER", 0.90, ("CWE-79",)),
    "entities.encodeHTML":            ("SANITIZER", 0.85, ("CWE-79",)),
    "escape":                         ("SANITIZER", 0.80, ("CWE-79",)),
    "validator.escape":               ("SANITIZER", 0.90, ("CWE-79",)),
    "xss-filters":                    ("SANITIZER", 0.85, ("CWE-79",)),
    "textContent":                    ("SANITIZER", 0.75, ("CWE-79",)),   # safe DOM property
    "createTextNode":                 ("SANITIZER", 0.80, ("CWE-79",)),
    # ── URL encoding ─────────────────────────────────────────────────────────
    "encodeURIComponent":             ("SANITIZER", 0.85, ("CWE-116",)),
    "encodeURI":                      ("SANITIZER", 0.80, ("CWE-116",)),
    "URLSearchParams":                ("SANITIZER", 0.75, ("CWE-116",)),
    # ── SQL parameterisation ─────────────────────────────────────────────────
    "parameterized":                  ("SANITIZER", 0.95, ("CWE-89",)),
    "escape":                         ("SANITIZER", 0.80, ("CWE-89",)),   # mysql.escape
    "mysql.escape":                   ("SANITIZER", 0.90, ("CWE-89",)),
    "pg.escapeLiteral":               ("SANITIZER", 0.90, ("CWE-89",)),
    # ── Path sanitisation ────────────────────────────────────────────────────
    "path.basename":                  ("SANITIZER", 0.70, ("CWE-22",)),
    "path.normalize":                 ("SANITIZER", 0.55, ("CWE-22",)),
    # ── Validation ───────────────────────────────────────────────────────────
    "validator.isURL":                ("SANITIZER", 0.75, ("CWE-601",)),
    "validator.isEmail":              ("SANITIZER", 0.75, ("CWE-20",)),
    "validator.isAlphanumeric":       ("SANITIZER", 0.70, ("CWE-20",)),
    "Number":                         ("SANITIZER", 0.60, ("CWE-20",)),
    "parseInt":                       ("SANITIZER", 0.60, ("CWE-20",)),
    "parseFloat":                     ("SANITIZER", 0.60, ("CWE-20",)),
    # ── Security headers ─────────────────────────────────────────────────────
    "helmet":                         ("SANITIZER", 0.75, ()),
    "csp":                            ("SANITIZER", 0.70, ("CWE-79",)),
    # ── YAML safe loading ─────────────────────────────────────────────────────
    "yaml.safeLoad":                  ("SANITIZER", 0.90, ("CWE-502",)),
    "YAML.safeLoad":                  ("SANITIZER", 0.90, ("CWE-502",)),
}


# Self-contained registry for JavaScript/TypeScript/TSX:
#   from prism.parser.sinks.javascript_sinks import JS_SINK_REGISTRY
JS_SINK_REGISTRY: dict[str, dict] = {
    "sinks":      JS_SINKS,
    "sources":    JS_SOURCES,
    "sanitizers": JS_SANITIZERS,
}