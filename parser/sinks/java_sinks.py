"""
Java security sinks, sources, and sanitizers.

Format: name -> (SecurityLabel_str, confidence, (cwe_ids,...))
Strings for SecurityLabel avoid a circular import with models.py.

Coverage:
  JDBC / JPA / Hibernate SQL              CWE-89
  Command execution                       CWE-78
  Path traversal                          CWE-22
  Insecure deserialization                CWE-502
  XSS                                     CWE-79
  XXE / XML injection                     CWE-611
  LDAP injection                          CWE-90
  SSRF / outbound HTTP                    CWE-918
  Weak cryptography                       CWE-327
  Log injection                           CWE-117
  Open redirect                           CWE-601
  Server-side template injection          CWE-94
"""
from __future__ import annotations

JAVA_SINKS: dict[str, tuple[str, float, tuple[str, ...]]] = {

    # ── SQL injection ──────────────────────────────────────────────── CWE-89
    # JDBC
    "executeQuery":                   ("SINK", 0.90, ("CWE-89",)),
    "executeUpdate":                  ("SINK", 0.90, ("CWE-89",)),
    "execute":                        ("SINK", 0.80, ("CWE-89",)),
    "executeBatch":                   ("SINK", 0.85, ("CWE-89",)),
    "addBatch":                       ("SINK", 0.75, ("CWE-89",)),
    "Statement.execute":              ("SINK", 0.90, ("CWE-89",)),
    "Statement.executeQuery":         ("SINK", 0.90, ("CWE-89",)),
    "Statement.executeUpdate":        ("SINK", 0.90, ("CWE-89",)),
    "createStatement":                ("SINK", 0.70, ("CWE-89",)),
    "connection.execute":             ("SINK", 0.85, ("CWE-89",)),
    # JPA / Hibernate
    "createNativeQuery":              ("SINK", 0.90, ("CWE-89",)),
    "createQuery":                    ("SINK", 0.75, ("CWE-89",)),  # safe with named params
    "entityManager.createNativeQuery":("SINK", 0.90, ("CWE-89",)),
    "session.createQuery":            ("SINK", 0.75, ("CWE-89",)),
    "session.createSQLQuery":         ("SINK", 0.90, ("CWE-89",)),
    "session.createNativeQuery":      ("SINK", 0.90, ("CWE-89",)),

    # ── Command injection ──────────────────────────────────────────── CWE-78
    "Runtime.exec":                   ("SINK", 0.99, ("CWE-78",)),
    "Runtime.getRuntime().exec":      ("SINK", 0.99, ("CWE-78",)),
    "ProcessBuilder.command":         ("SINK", 0.95, ("CWE-78",)),
    "ProcessBuilder.start":           ("SINK", 0.90, ("CWE-78",)),
    "new ProcessBuilder":             ("SINK", 0.85, ("CWE-78",)),

    # ── Path traversal ─────────────────────────────────────────────── CWE-22
    "new File":                       ("SINK", 0.60, ("CWE-22",)),
    "new FileInputStream":            ("SINK", 0.65, ("CWE-22",)),
    "new FileOutputStream":           ("SINK", 0.65, ("CWE-22",)),
    "new FileReader":                 ("SINK", 0.65, ("CWE-22",)),
    "new FileWriter":                 ("SINK", 0.65, ("CWE-22",)),
    "new RandomAccessFile":           ("SINK", 0.70, ("CWE-22",)),
    "Files.readAllBytes":             ("SINK", 0.60, ("CWE-22",)),
    "Files.readAllLines":             ("SINK", 0.60, ("CWE-22",)),
    "Files.write":                    ("SINK", 0.65, ("CWE-22",)),
    "Files.copy":                     ("SINK", 0.65, ("CWE-22",)),
    "Files.delete":                   ("SINK", 0.70, ("CWE-22",)),
    "Files.move":                     ("SINK", 0.65, ("CWE-22",)),
    "Paths.get":                      ("SINK", 0.55, ("CWE-22",)),
    "Path.resolve":                   ("SINK", 0.55, ("CWE-22",)),
    "getResourceAsStream":            ("SINK", 0.55, ("CWE-22",)),

    # ── Insecure deserialization ───────────────────────────────────── CWE-502
    "ObjectInputStream.readObject":   ("SINK", 0.99, ("CWE-502",)),
    "new ObjectInputStream":          ("SINK", 0.90, ("CWE-502",)),
    "deserialize":                    ("SINK", 0.90, ("CWE-502",)),
    "XMLDecoder.readObject":          ("SINK", 0.99, ("CWE-502",)),
    "new XMLDecoder":                 ("SINK", 0.95, ("CWE-502",)),
    "XStream.fromXML":                ("SINK", 0.95, ("CWE-502",)),
    "kryo.readObject":                ("SINK", 0.85, ("CWE-502",)),
    "JSON.parseObject":               ("SINK", 0.70, ("CWE-502",)),  # Fastjson RCE vector
    "JSON.parse":                     ("SINK", 0.70, ("CWE-502",)),  # Fastjson
    "mapper.readValue":               ("SINK", 0.60, ("CWE-502",)),  # Jackson — safe w/ type filtering

    # ── XSS ───────────────────────────────────────────────────────── CWE-79
    "response.getWriter().print":     ("SINK", 0.80, ("CWE-79",)),
    "response.getWriter().println":   ("SINK", 0.80, ("CWE-79",)),
    "out.print":                      ("SINK", 0.60, ("CWE-79",)),
    "out.println":                    ("SINK", 0.60, ("CWE-79",)),
    "PrintWriter.print":              ("SINK", 0.70, ("CWE-79",)),
    "response.sendRedirect":          ("SINK", 0.75, ("CWE-601",)),  # also open redirect
    "response.setHeader":             ("SINK", 0.55, ("CWE-79",)),
    "setAttribute":                   ("SINK", 0.45, ("CWE-79",)),

    # ── XXE / XML ─────────────────────────────────────────────────── CWE-611
    "DocumentBuilder.parse":          ("SINK", 0.85, ("CWE-611",)),
    "SAXParser.parse":                ("SINK", 0.85, ("CWE-611",)),
    "XMLReader.parse":                ("SINK", 0.85, ("CWE-611",)),
    "TransformerFactory.newTransformer": ("SINK", 0.75, ("CWE-611",)),
    "SchemaFactory.newSchema":        ("SINK", 0.70, ("CWE-611",)),

    # ── LDAP injection ────────────────────────────────────────────── CWE-90
    "search":                         ("SINK", 0.70, ("CWE-90",)),
    "DirContext.search":              ("SINK", 0.90, ("CWE-90",)),
    "InitialDirContext.search":       ("SINK", 0.90, ("CWE-90",)),
    "InitialLdapContext.search":      ("SINK", 0.90, ("CWE-90",)),

    # ── SSRF / outbound HTTP ──────────────────────────────────────── CWE-918
    "HttpURLConnection.openConnection": ("SINK", 0.65, ("CWE-918",)),
    "URL.openConnection":             ("SINK", 0.65, ("CWE-918",)),
    "URL.openStream":                 ("SINK", 0.65, ("CWE-918",)),
    "new URL":                        ("SINK", 0.50, ("CWE-918",)),
    "HttpClient.send":                ("SINK", 0.60, ("CWE-918",)),
    "HttpClient.get":                 ("SINK", 0.60, ("CWE-918",)),
    "restTemplate.getForObject":      ("SINK", 0.60, ("CWE-918",)),
    "restTemplate.exchange":          ("SINK", 0.60, ("CWE-918",)),
    "webClient.get":                  ("SINK", 0.55, ("CWE-918",)),

    # ── Weak cryptography ─────────────────────────────────────────── CWE-327
    "MessageDigest.getInstance":      ("SINK", 0.55, ("CWE-327",)),  # only bad with MD5/SHA1
    "Cipher.getInstance":             ("SINK", 0.55, ("CWE-327",)),  # bad with DES/ECB
    "new DESKeySpec":                 ("SINK", 0.85, ("CWE-327",)),
    "SecretKeyFactory.getInstance":   ("SINK", 0.50, ("CWE-327",)),
    "KeyGenerator.getInstance":       ("SINK", 0.50, ("CWE-327",)),

    # ── Log injection ─────────────────────────────────────────────── CWE-117
    "logger.info":                    ("SINK", 0.30, ("CWE-117",)),
    "logger.warn":                    ("SINK", 0.30, ("CWE-117",)),
    "logger.error":                   ("SINK", 0.30, ("CWE-117",)),
    "logger.debug":                   ("SINK", 0.25, ("CWE-117",)),
    "log.info":                       ("SINK", 0.30, ("CWE-117",)),
    "log.error":                      ("SINK", 0.30, ("CWE-117",)),
    "System.out.println":             ("SINK", 0.20, ("CWE-117",)),
    "System.err.println":             ("SINK", 0.20, ("CWE-117",)),

    # ── Open redirect ─────────────────────────────────────────────── CWE-601
    "sendRedirect":                   ("SINK", 0.75, ("CWE-601",)),
    "ModelAndView":                   ("SINK", 0.50, ("CWE-601",)),
    "RedirectView":                   ("SINK", 0.65, ("CWE-601",)),
    "redirect:":                      ("SINK", 0.75, ("CWE-601",)),  # Spring MVC prefix

    # ── Server-side template injection ────────────────────────────── CWE-94
    "Template.process":               ("SINK", 0.80, ("CWE-94",)),  # Freemarker
    "VelocityEngine.evaluate":        ("SINK", 0.85, ("CWE-94",)),
    "new Velocity":                   ("SINK", 0.75, ("CWE-94",)),
}

JAVA_SOURCES: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── Servlet request parameters ──────────────────────────────────────────
    "request.getParameter":           ("SOURCE", 0.99, ("CWE-20",)),
    "request.getParameterValues":     ("SOURCE", 0.99, ("CWE-20",)),
    "request.getParameterMap":        ("SOURCE", 0.99, ("CWE-20",)),
    "request.getHeader":              ("SOURCE", 0.90, ("CWE-20",)),
    "request.getHeaders":             ("SOURCE", 0.90, ("CWE-20",)),
    "request.getCookies":             ("SOURCE", 0.90, ("CWE-20",)),
    "request.getInputStream":         ("SOURCE", 0.90, ("CWE-20",)),
    "request.getReader":              ("SOURCE", 0.90, ("CWE-20",)),
    "request.getQueryString":         ("SOURCE", 0.95, ("CWE-20",)),
    "request.getRequestURI":          ("SOURCE", 0.85, ("CWE-20",)),
    "request.getRequestURL":          ("SOURCE", 0.85, ("CWE-20",)),
    "request.getPathInfo":            ("SOURCE", 0.85, ("CWE-20",)),
    "request.getServletPath":         ("SOURCE", 0.80, ("CWE-20",)),
    "request.getRemoteAddr":          ("SOURCE", 0.70, ("CWE-20",)),
    "request.getRemoteHost":          ("SOURCE", 0.70, ("CWE-20",)),
    # ── Session attributes ──────────────────────────────────────────────────
    "session.getAttribute":           ("SOURCE", 0.70, ("CWE-20",)),
    "httpSession.getAttribute":       ("SOURCE", 0.70, ("CWE-20",)),
    # ── Environment / config ────────────────────────────────────────────────
    "System.getenv":                  ("SOURCE", 0.70, ("CWE-214",)),
    "System.getProperty":             ("SOURCE", 0.65, ("CWE-214",)),
    # ── Standard input / args ───────────────────────────────────────────────
    "args":                           ("SOURCE", 0.70, ("CWE-88",)),
    "scanner.nextLine":               ("SOURCE", 0.85, ("CWE-20",)),
    "scanner.next":                   ("SOURCE", 0.80, ("CWE-20",)),
    "BufferedReader.readLine":        ("SOURCE", 0.80, ("CWE-20",)),
    "System.in.read":                 ("SOURCE", 0.75, ("CWE-20",)),
    # ── Database results (may contain attacker-controlled data) ────────────
    "resultSet.getString":            ("SOURCE", 0.45, ("CWE-20",)),
    "resultSet.getObject":            ("SOURCE", 0.45, ("CWE-20",)),
    # ── Spring framework ────────────────────────────────────────────────────
    "@RequestParam":                  ("SOURCE", 0.99, ("CWE-20",)),
    "@PathVariable":                  ("SOURCE", 0.90, ("CWE-20",)),
    "@RequestBody":                   ("SOURCE", 0.99, ("CWE-20",)),
    "@RequestHeader":                 ("SOURCE", 0.85, ("CWE-20",)),
    "@CookieValue":                   ("SOURCE", 0.85, ("CWE-20",)),
    "BindingResult":                  ("SOURCE", 0.80, ("CWE-20",)),
}

JAVA_SANITIZERS: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── SQL parameterisation ────────────────────────────────────────────────
    "PreparedStatement":              ("SANITIZER", 0.95, ("CWE-89",)),
    "prepareStatement":               ("SANITIZER", 0.95, ("CWE-89",)),
    "setString":                      ("SANITIZER", 0.85, ("CWE-89",)),   # PreparedStatement.setString
    "setInt":                         ("SANITIZER", 0.85, ("CWE-89",)),
    "setParameter":                   ("SANITIZER", 0.80, ("CWE-89",)),   # JPA
    "NamedParameterJdbcTemplate":     ("SANITIZER", 0.90, ("CWE-89",)),
    # ── XSS encoders ────────────────────────────────────────────────────────
    "ESAPI.encoder":                  ("SANITIZER", 0.95, ("CWE-79",)),
    "ESAPI.encoder().encodeForHTML":  ("SANITIZER", 0.98, ("CWE-79",)),
    "ESAPI.encoder().encodeForJS":    ("SANITIZER", 0.98, ("CWE-79",)),
    "StringEscapeUtils.escapeHtml":   ("SANITIZER", 0.90, ("CWE-79",)),
    "StringEscapeUtils.escapeHtml4":  ("SANITIZER", 0.90, ("CWE-79",)),
    "HtmlUtils.htmlEscape":           ("SANITIZER", 0.90, ("CWE-79",)),   # Spring
    "Encode.forHtml":                 ("SANITIZER", 0.95, ("CWE-79",)),   # OWASP Java Encoder
    "Encode.forJavaScript":           ("SANITIZER", 0.95, ("CWE-79",)),
    "Encode.forUriComponent":         ("SANITIZER", 0.90, ("CWE-116",)),
    "HtmlEscapers.htmlEscaper":       ("SANITIZER", 0.90, ("CWE-79",)),   # Guava
    # ── XML hardening ───────────────────────────────────────────────────────
    "setFeature":                     ("SANITIZER", 0.60, ("CWE-611",)),  # disable XXE feature
    "disableExternalDTD":             ("SANITIZER", 0.90, ("CWE-611",)),
    # ── Path canonicalisation ───────────────────────────────────────────────
    "getCanonicalPath":               ("SANITIZER", 0.70, ("CWE-22",)),
    "normalize":                      ("SANITIZER", 0.60, ("CWE-22",)),
    "FilenameUtils.getName":          ("SANITIZER", 0.70, ("CWE-22",)),   # Commons IO
    # ── Generic validators ──────────────────────────────────────────────────
    "validate":                       ("SANITIZER", 0.60, ()),
    "sanitize":                       ("SANITIZER", 0.65, ()),
    "Validator.validate":             ("SANITIZER", 0.75, ()),
    "Pattern.matches":                ("SANITIZER", 0.55, ()),
    # ── URL encoding ────────────────────────────────────────────────────────
    "URLEncoder.encode":              ("SANITIZER", 0.85, ("CWE-116",)),
    "UriUtils.encodeQueryParam":      ("SANITIZER", 0.85, ("CWE-116",)),  # Spring
}


# Self-contained registry for Java — import directly without loading all languages:
#   from prism.parser.sinks.java_sinks import JAVA_SINK_REGISTRY
JAVA_SINK_REGISTRY: dict[str, dict] = {
    "sinks":      JAVA_SINKS,
    "sources":    JAVA_SOURCES,
    "sanitizers": JAVA_SANITIZERS,
}