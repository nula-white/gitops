"""
Python security sinks, sources, and sanitizers.

Each dict maps a function/attribute name to:
    (SecurityLabel_str, confidence: float, cwe_ids: tuple[str, ...])

Strings are used for SecurityLabel to avoid circular imports — the
SecurityAnnotator resolves them to SecurityLabel enum values at call time.

PYTHON_SINK_REGISTRY
--------------------
A self-contained registry for Python combining sinks, sources, and
sanitizers under one dict so any module can import this file directly:

    from prism.parser.sinks.python_sinks import PYTHON_SINK_REGISTRY

    sinks      = PYTHON_SINK_REGISTRY["sinks"]
    sources    = PYTHON_SINK_REGISTRY["sources"]
    sanitizers = PYTHON_SINK_REGISTRY["sanitizers"]

The master SINK_REGISTRY in sinks/__init__.py imports PYTHON_SINK_REGISTRY
and slots it under Language.PYTHON — no duplication.
"""
from __future__ import annotations

# Format: name -> (SecurityLabel_str, confidence, (cwe_ids,...))
# Strings for SecurityLabel avoid a circular import with models.py

PYTHON_SINKS: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── Command execution ──────────────────────────────────── CWE-78 / CWE-95
    "os.system":               ("SINK", 0.95, ("CWE-78",)),
    "os.popen":                ("SINK", 0.95, ("CWE-78",)),
    "os.execv":                ("SINK", 0.95, ("CWE-78",)),
    "os.execve":               ("SINK", 0.95, ("CWE-78",)),
    "subprocess.call":         ("SINK", 0.90, ("CWE-78",)),
    "subprocess.run":          ("SINK", 0.90, ("CWE-78",)),
    "subprocess.Popen":        ("SINK", 0.90, ("CWE-78",)),
    "subprocess.check_output": ("SINK", 0.90, ("CWE-78",)),
    "subprocess.check_call":   ("SINK", 0.90, ("CWE-78",)),
    "eval":                    ("SINK", 0.98, ("CWE-78", "CWE-95")),
    "exec":                    ("SINK", 0.98, ("CWE-78", "CWE-95")),
    "compile":                 ("SINK", 0.70, ("CWE-95",)),
    "__import__":              ("SINK", 0.70, ("CWE-95",)),
    "importlib.import_module": ("SINK", 0.65, ("CWE-95",)),
    # ── SQL injection ──────────────────────────────────────────────── CWE-89
    "cursor.execute":          ("SINK", 0.90, ("CWE-89",)),
    "cursor.executemany":      ("SINK", 0.90, ("CWE-89",)),
    "db.execute":              ("SINK", 0.90, ("CWE-89",)),
    "session.execute":         ("SINK", 0.85, ("CWE-89",)),
    "connection.execute":      ("SINK", 0.85, ("CWE-89",)),
    # ── Path traversal ────────────────────────────────────── CWE-22 / CWE-73
    "open":                    ("SINK", 0.55, ("CWE-22", "CWE-73")),
    "os.path.join":            ("SINK", 0.40, ("CWE-22",)),
    "os.path.abspath":         ("SINK", 0.35, ("CWE-22",)),
    "pathlib.Path":            ("SINK", 0.40, ("CWE-22",)),
    "shutil.copy":             ("SINK", 0.60, ("CWE-22",)),
    "shutil.move":             ("SINK", 0.60, ("CWE-22",)),
    "shutil.rmtree":           ("SINK", 0.65, ("CWE-22",)),
    # ── Insecure deserialization ───────────────────────────────────── CWE-502
    "pickle.loads":            ("SINK", 0.99, ("CWE-502",)),
    "pickle.load":             ("SINK", 0.99, ("CWE-502",)),
    "pickle.Unpickler":        ("SINK", 0.99, ("CWE-502",)),
    "yaml.load":               ("SINK", 0.95, ("CWE-502",)),
    "marshal.loads":           ("SINK", 0.95, ("CWE-502",)),
    "jsonpickle.decode":       ("SINK", 0.90, ("CWE-502",)),
    "shelve.open":             ("SINK", 0.80, ("CWE-502",)),
    # ── SSRF / outbound requests ───────────────────────────────────── CWE-918
    "requests.get":            ("SINK", 0.55, ("CWE-918",)),
    "requests.post":           ("SINK", 0.55, ("CWE-918",)),
    "requests.put":            ("SINK", 0.55, ("CWE-918",)),
    "requests.delete":         ("SINK", 0.55, ("CWE-918",)),
    "requests.request":        ("SINK", 0.55, ("CWE-918",)),
    "requests.Session.get":    ("SINK", 0.55, ("CWE-918",)),
    "urllib.request.urlopen":  ("SINK", 0.60, ("CWE-918",)),
    "urllib.request.urlretrieve": ("SINK", 0.60, ("CWE-918",)),
    "httpx.get":               ("SINK", 0.55, ("CWE-918",)),
    "httpx.post":              ("SINK", 0.55, ("CWE-918",)),
    "httpx.AsyncClient.get":   ("SINK", 0.55, ("CWE-918",)),
    "aiohttp.ClientSession.get": ("SINK", 0.55, ("CWE-918",)),
    # ── Template / code injection ──────────────────────────────────── CWE-94
    "render_template_string":  ("SINK", 0.85, ("CWE-94",)),
    "Jinja2.Template":         ("SINK", 0.80, ("CWE-94",)),
    "Template":                ("SINK", 0.60, ("CWE-94",)),
    "mako.template.Template":  ("SINK", 0.75, ("CWE-94",)),
    # ── XSS ───────────────────────────────────────────────────────── CWE-79
    "flask.Markup":            ("SINK", 0.75, ("CWE-79",)),
    "mark_safe":               ("SINK", 0.80, ("CWE-79",)),
    "format_html":             ("SINK", 0.50, ("CWE-79",)),
    # ── LDAP injection ────────────────────────────────────────────── CWE-90
    "ldap.search":             ("SINK", 0.85, ("CWE-90",)),
    "ldap3.Connection.search": ("SINK", 0.85, ("CWE-90",)),
    # ── XML / XXE ─────────────────────────────────────────────────── CWE-611
    "xml.etree.ElementTree.parse":   ("SINK", 0.70, ("CWE-611",)),
    "lxml.etree.parse":              ("SINK", 0.70, ("CWE-611",)),
    "defusedxml.ElementTree.parse":  ("SINK", 0.20, ("CWE-611",)),  # mitigated
    # ── Weak cryptography ─────────────────────────────────────────── CWE-327
    "hashlib.md5":             ("SINK", 0.70, ("CWE-327",)),
    "hashlib.sha1":            ("SINK", 0.60, ("CWE-327",)),
    "Crypto.Cipher.DES.new":   ("SINK", 0.80, ("CWE-327",)),
    "Crypto.Cipher.RC4.new":   ("SINK", 0.85, ("CWE-327",)),
    # ── Log injection ─────────────────────────────────────────────── CWE-117
    "logging.info":            ("SINK", 0.30, ("CWE-117",)),
    "logging.warning":         ("SINK", 0.30, ("CWE-117",)),
    "logging.error":           ("SINK", 0.30, ("CWE-117",)),
    "logging.debug":           ("SINK", 0.25, ("CWE-117",)),
    "print":                   ("SINK", 0.20, ("CWE-117",)),
    # ── Open redirect ─────────────────────────────────────────────── CWE-601
    "flask.redirect":          ("SINK", 0.55, ("CWE-601",)),
    "django.shortcuts.redirect": ("SINK", 0.55, ("CWE-601",)),
    "HTTPFound":               ("SINK", 0.55, ("CWE-601",)),
        # ── Filesystem manipulation ─────────────────────────────── CWE-22 / CWE-732
    "os.makedirs":            ("SINK", 0.60, ("CWE-22", "CWE-732")),
    "os.mkdir":               ("SINK", 0.60, ("CWE-22", "CWE-732")),
    "os.chmod":               ("SINK", 0.65, ("CWE-732",)),
    "os.chown":               ("SINK", 0.65, ("CWE-732",)),

    # ── Native code loading ─────────────────────────────────── CWE-114
    "ctypes.cdll.LoadLibrary": ("SINK", 0.85, ("CWE-114",)),
    "ctypes.CDLL":             ("SINK", 0.85, ("CWE-114",)),

    # ── Raw socket SSRF ─────────────────────────────────────── CWE-918
    "socket.connect":         ("SINK", 0.60, ("CWE-918",)),
    "socket.sendto":          ("SINK", 0.60, ("CWE-918",)),

    # ── Email header injection ───────────────────────────────── CWE-93
    "smtplib.SMTP.sendmail":  ("SINK", 0.70, ("CWE-93",)),

    # ── Archive extraction (Zip Slip / Tar Slip) ─────────────── CWE-22
    "tarfile.extract":        ("SINK", 0.80, ("CWE-22",)),
    "tarfile.extractall":     ("SINK", 0.85, ("CWE-22",)),
    "zipfile.ZipFile.extract":    ("SINK", 0.85, ("CWE-22",)),
    "zipfile.ZipFile.extractall": ("SINK", 0.85, ("CWE-22",)),

    # ── XML parsing (XXE) ────────────────────────────────────── CWE-611
    "xml.dom.minidom.parse":  ("SINK", 0.70, ("CWE-611",)),

    # ── Browser invocation / open redirect ───────────────────── CWE-601
    "webbrowser.open":        ("SINK", 0.55, ("CWE-601",)),

    # ── Weak cryptography / misuse ───────────────────────────── CWE-327
    "hashlib.new":            ("SINK", 0.65, ("CWE-327",)),
    "Crypto.Cipher.AES.new":  ("SINK", 0.60, ("CWE-327",)),  # ECB misuse potential

    # ── Weak PRNG ────────────────────────────────────────────── CWE-338
    "random.random":          ("SINK", 0.60, ("CWE-338",)),
    "random.randint":         ("SINK", 0.60, ("CWE-338",)),
    # ── File uploads / archive operations ───────────────────── CWE-22
    "tarfile.open":                   ("SINK", 0.75, ("CWE-22",)),
    "shutil.unpack_archive":          ("SINK", 0.80, ("CWE-22",)),
    # ── Dynamic module loading ──────────────────────────────── CWE-94
    "importlib.reload":               ("SINK", 0.65, ("CWE-94",)),
    "pkgutil.get_loader":             ("SINK", 0.60, ("CWE-94",)),
    # ── Template rendering sinks ────────────────────────────── CWE-94
    "jinja2.Environment.from_string": ("SINK", 0.85, ("CWE-94",)),
    "jinja2.Template.render":         ("SINK", 0.75, ("CWE-94",)),
    # ── File serving APIs ───────────────────────────────────── CWE-22
    "flask.send_file":                ("SINK", 0.75, ("CWE-22",)),
    "flask.send_from_directory":      ("SINK", 0.80, ("CWE-22",)),
    "django.http.FileResponse":       ("SINK", 0.75, ("CWE-22",)),
    # ── File serving APIsHTTP redirects across frameworks ───── CWE-601
    "starlette.responses.RedirectResponse": ("SINK", 0.60, ("CWE-601",)),
    # ── Unsafe YAML loader variants──────────────────────────── CWE-502
    "yaml.full_load":                 ("SINK", 0.90, ("CWE-502",)),
    "yaml.unsafe_load":               ("SINK", 0.95, ("CWE-502",)),
    # ── Unsafe YAML loader variants──────────────────────────── CWE-94
    "types.FunctionType":             ("SINK", 0.70, ("CWE-94",)),
}

PYTHON_SOURCES: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── Flask ───────────────────────────────────────────────────────────────
    "request.args":            ("SOURCE", 0.99, ("CWE-20",)),
    "request.form":            ("SOURCE", 0.99, ("CWE-20",)),
    "request.data":            ("SOURCE", 0.99, ("CWE-20",)),
    "request.json":            ("SOURCE", 0.99, ("CWE-20",)),
    "request.files":           ("SOURCE", 0.99, ("CWE-20",)),
    "request.cookies":         ("SOURCE", 0.95, ("CWE-20",)),
    "request.headers":         ("SOURCE", 0.90, ("CWE-20",)),
    "request.values":          ("SOURCE", 0.99, ("CWE-20",)),
    "request.get_json":        ("SOURCE", 0.95, ("CWE-20",)),
    "request.url":             ("SOURCE", 0.85, ("CWE-20",)),
    "request.path":            ("SOURCE", 0.80, ("CWE-20",)),
    # ── Django ─────────────────────────────────────────────────────────────
    "request.GET":             ("SOURCE", 0.99, ("CWE-20",)),
    "request.POST":            ("SOURCE", 0.99, ("CWE-20",)),
    "request.body":            ("SOURCE", 0.99, ("CWE-20",)),
    "request.META":            ("SOURCE", 0.85, ("CWE-20",)),
    "request.session":         ("SOURCE", 0.80, ("CWE-20",)),
    # ── FastAPI / Starlette ─────────────────────────────────────────────────
    "Body":                    ("SOURCE", 0.85, ("CWE-20",)),
    "Query":                   ("SOURCE", 0.85, ("CWE-20",)),
    "Form":                    ("SOURCE", 0.85, ("CWE-20",)),
    "File":                    ("SOURCE", 0.85, ("CWE-20",)),
    "Header":                  ("SOURCE", 0.80, ("CWE-20",)),
    "Path":                    ("SOURCE", 0.80, ("CWE-20",)),
    # ── Environment ────────────────────────────────────────────────────────
    "os.environ":              ("SOURCE", 0.70, ("CWE-214",)),
    "os.getenv":               ("SOURCE", 0.70, ("CWE-214",)),
    "os.environ.get":          ("SOURCE", 0.70, ("CWE-214",)),
    # ── Standard input ─────────────────────────────────────────────────────
    "input":                   ("SOURCE", 0.90, ("CWE-20",)),
    "sys.argv":                ("SOURCE", 0.85, ("CWE-88",)),
    "sys.stdin":               ("SOURCE", 0.80, ("CWE-20",)),
    "sys.stdin.read":          ("SOURCE", 0.80, ("CWE-20",)),
    # ── File / network reads ────────────────────────────────────────────────
    "read":                    ("SOURCE", 0.50, ("CWE-20",)),
    "readline":                ("SOURCE", 0.50, ("CWE-20",)),
    "readlines":               ("SOURCE", 0.50, ("CWE-20",)),
    "recv":                    ("SOURCE", 0.75, ("CWE-20",)),
    "recvfrom":                ("SOURCE", 0.75, ("CWE-20",)),
    # ── Database reads ─────────────────────────────────────────────────────
    "fetchone":                ("SOURCE", 0.45, ("CWE-20",)),
    "fetchall":                ("SOURCE", 0.45, ("CWE-20",)),
    "fetchmany":               ("SOURCE", 0.45, ("CWE-20",)),
        # ── Bottle framework ──────────────────────────────────────────────
    "bottle.request.params":  ("SOURCE", 0.99, ("CWE-20",)),
    "bottle.request.json":    ("SOURCE", 0.99, ("CWE-20",)),

    # ── aiohttp (async framework) ─────────────────────────────────────
    "aiohttp.web.Request.query": ("SOURCE", 0.95, ("CWE-20",)),
    "aiohttp.web.Request.post":  ("SOURCE", 0.95, ("CWE-20",)),

    # ── Starlette / raw ASGI ──────────────────────────────────────────
    "Starlette.Request.query_params": ("SOURCE", 0.95, ("CWE-20",)),
    "scope.query_string":             ("SOURCE", 0.90, ("CWE-20",)),

    # ── Raw socket input ──────────────────────────────────────────────
    "socket.recv":            ("SOURCE", 0.80, ("CWE-20",)),

    # ── Binary protocol parsing ───────────────────────────────────────
    "struct.unpack":          ("SOURCE", 0.65, ("CWE-20",)),

    # ── CSV ingestion ─────────────────────────────────────────────────
    "csv.reader":             ("SOURCE", 0.65, ("CWE-20",)),
    "csv.DictReader":         ("SOURCE", 0.65, ("CWE-20",)),
    # ── URL parameters
    "request.query_params":           ("SOURCE", 0.95, ("CWE-20",)),
    "request.query_string":           ("SOURCE", 0.95, ("CWE-20",)),
    # ── Websocket input
    "websocket.recv":                 ("SOURCE", 0.90, ("CWE-20",)),
    # ── Message queue / broker input
    "kafka.Consumer.poll":            ("SOURCE", 0.80, ("CWE-20",)),
    "pika.Channel.basic_consume":     ("SOURCE", 0.80, ("CWE-20",)),
    # ── external data
    "configparser.ConfigParser.get":  ("SOURCE", 0.60, ("CWE-20",)),
    # ── File upload sources
    "werkzeug.FileStorage.stream":    ("SOURCE", 0.95, ("CWE-20",)),
}

PYTHON_SANITIZERS: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── XSS ────────────────────────────────────────────────────────────────
    "html.escape":             ("SANITIZER", 0.90, ("CWE-79",)),
    "escape":                  ("SANITIZER", 0.80, ("CWE-79",)),
    "bleach.clean":            ("SANITIZER", 0.95, ("CWE-79",)),
    "bleach.linkify":          ("SANITIZER", 0.85, ("CWE-79",)),
    "markupsafe.escape":       ("SANITIZER", 0.90, ("CWE-79",)),
    "cgi.escape":              ("SANITIZER", 0.80, ("CWE-79",)),
    # ── Shell ───────────────────────────────────────────────────────────────
    "shlex.quote":             ("SANITIZER", 0.90, ("CWE-78",)),
    "shlex.split":             ("SANITIZER", 0.80, ("CWE-78",)),
    "shlex.escape":            ("SANITIZER", 0.90, ("CWE-78",)),
    "re.escape":               ("SANITIZER", 0.80, ("CWE-78",)),
    # ── URL encoding ───────────────────────────────────────────────────────
    "urllib.parse.quote":      ("SANITIZER", 0.85, ("CWE-116",)),
    "urllib.parse.quote_plus": ("SANITIZER", 0.85, ("CWE-116",)),
    "urllib.parse.urlencode":  ("SANITIZER", 0.85, ("CWE-116",)),
    # ── SQL parameterisation ────────────────────────────────────────────────
    "parameterized":           ("SANITIZER", 0.95, ("CWE-89",)),
    # ── Path sanitizers ─────────────────────────────────────────────────────
    "os.path.basename":        ("SANITIZER", 0.60, ("CWE-22",)),
    "pathlib.Path.resolve":    ("SANITIZER", 0.55, ("CWE-22",)),
    # ── Type-cast sanitizers ────────────────────────────────────────────────
    "int":                     ("SANITIZER", 0.55, ("CWE-20",)),
    "float":                   ("SANITIZER", 0.55, ("CWE-20",)),
    "abs":                     ("SANITIZER", 0.40, ("CWE-20",)),
    # ── Generic ─────────────────────────────────────────────────────────────
    "validate":                ("SANITIZER", 0.60, ()),
    "sanitize":                ("SANITIZER", 0.65, ()),
    "clean":                   ("SANITIZER", 0.50, ()),
    "strip":                   ("SANITIZER", 0.30, ()),
    # ── Cryptographic ───────────────────────────────────────────────────────
    "hashlib.sha256":          ("SANITIZER", 0.70, ("CWE-327",)),
    "hashlib.sha512":          ("SANITIZER", 0.70, ("CWE-327",)),
    "hmac.new":                ("SANITIZER", 0.75, ("CWE-327",)),
    "secrets.token_hex":       ("SANITIZER", 0.80, ("CWE-338",)),
    "secrets.token_bytes":     ("SANITIZER", 0.80, ("CWE-338",)),
        # ── XML secure parsing ────────────────────────────────────────────
    "defusedxml.ElementTree.parse": ("SANITIZER", 0.90, ("CWE-611",)),

    # ── JWT validation ────────────────────────────────────────────────
    "jose.jwt.decode":        ("SANITIZER", 0.80, ("CWE-347",)),

    # ── Form validation frameworks ────────────────────────────────────
    "wtforms.validators":     ("SANITIZER", 0.80, ("CWE-20",)),

    # ── Schema validators ─────────────────────────────────────────────
    "cerberus.Validator.validate": ("SANITIZER", 0.85, ("CWE-20",)),
    "marshmallow.Schema.load":     ("SANITIZER", 0.90, ("CWE-20",)),

    # ── Pydantic validation (high-value sanitizer) ────────────────────
    "pydantic.BaseModel":     ("SANITIZER", 0.95, ("CWE-20",)),

    # ── Django HTML escaping ──────────────────────────────────────────
    "django.utils.html.conditional_escape": ("SANITIZER", 0.90, ("CWE-79",)),
    # ── Django security helpers
    "django.utils.html.escape":       ("SANITIZER", 0.90, ("CWE-79",)),
    "django.utils.http.urlquote":     ("SANITIZER", 0.85, ("CWE-116",)),
    # ── Email sanitization
    "email.utils.parseaddr":          ("SANITIZER", 0.60, ("CWE-93",)),
    # ── Cryptographic password hashing
    "bcrypt.hashpw":                  ("SANITIZER", 0.90, ("CWE-327",)),
    "passlib.hash.bcrypt":            ("SANITIZER", 0.90, ("CWE-327",)),
}


# ── Per-language registry ─────────────────────────────────────────────────────
# Self-contained registry for Python.  Import directly when you only need
# Python entries without loading the full multi-language SINK_REGISTRY:
#
#   from prism.parser.sinks.python_sinks import PYTHON_SINK_REGISTRY
#
# Structure mirrors the master SINK_REGISTRY in sinks/__init__.py so any
# code consuming a per-language registry works identically with both.
PYTHON_SINK_REGISTRY: dict[str, dict[str, tuple[str, float, tuple[str, ...]]]] = {
    "sinks":      PYTHON_SINKS,
    "sources":    PYTHON_SOURCES,
    "sanitizers": PYTHON_SANITIZERS,
}