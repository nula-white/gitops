"""
Terraform HCL and Kubernetes YAML (IaC) security sinks, sources, and sanitizers.

IaC "sinks" are resource attributes whose values directly determine
whether infrastructure is secure.  The CWE mapping reflects the
infrastructure-level weakness, not a code-level one.

Coverage:
  Public access / network exposure       CWE-284
  Encryption at rest disabled            CWE-311
  Encryption in transit disabled         CWE-319
  Weak TLS / cipher configuration        CWE-326
  Hardcoded secrets / credentials        CWE-798
  Audit logging disabled                 CWE-778
  Privilege escalation / overly broad IAM CWE-269
  Kubernetes container security          CWE-250 / CWE-269
  Missing authentication                 CWE-306
  Unrestricted ingress / egress          CWE-284

Format: name -> (SecurityLabel_str, confidence, (cwe_ids,...))
"""
from __future__ import annotations

IAC_SINKS: dict[str, tuple[str, float, tuple[str, ...]]] = {

    # ── Public access / network exposure ───────────────────────────── CWE-284
    # AWS
    "publicly_accessible":                  ("SINK", 0.90, ("CWE-284",)),
    "public_access_enabled":                ("SINK", 0.90, ("CWE-284",)),
    "enable_public_ip":                     ("SINK", 0.85, ("CWE-284",)),
    "associate_public_ip_address":          ("SINK", 0.85, ("CWE-284",)),
    "map_public_ip_on_launch":              ("SINK", 0.80, ("CWE-284",)),
    "assign_ipv6_address_on_creation":      ("SINK", 0.65, ("CWE-284",)),
    "bucket_acl":                           ("SINK", 0.80, ("CWE-284",)),   # s3 ACL
    "acl":                                  ("SINK", 0.70, ("CWE-284",)),   # public-read
    "access_control":                       ("SINK", 0.70, ("CWE-284",)),
    "block_public_acls":                    ("SINK", 0.75, ("CWE-284",)),
    "block_public_policy":                  ("SINK", 0.75, ("CWE-284",)),
    "ignore_public_acls":                   ("SINK", 0.70, ("CWE-284",)),
    "restrict_public_buckets":              ("SINK", 0.70, ("CWE-284",)),
    # Azure
    "allow_blob_public_access":             ("SINK", 0.90, ("CWE-284",)),
    "public_network_access_enabled":        ("SINK", 0.85, ("CWE-284",)),
    "enable_rbac_authorization":            ("SINK", 0.65, ("CWE-284",)),
    # GCP
    "uniform_bucket_level_access":          ("SINK", 0.70, ("CWE-284",)),
    "is_public":                            ("SINK", 0.80, ("CWE-284",)),

    # ── IAM / permissions ─────────────────────────────────────────── CWE-284 / CWE-269
    "actions":                              ("SINK", 0.60, ("CWE-284",)),   # IAM wildcard *
    "allow":                                ("SINK", 0.50, ("CWE-284",)),
    "effect":                               ("SINK", 0.50, ("CWE-284",)),
    "not_actions":                          ("SINK", 0.65, ("CWE-269",)),
    "not_resources":                        ("SINK", 0.65, ("CWE-269",)),
    "iam_policy":                           ("SINK", 0.60, ("CWE-269",)),
    "assume_role_policy":                   ("SINK", 0.65, ("CWE-269",)),
    "inline_policy":                        ("SINK", 0.65, ("CWE-269",)),
    "managed_policy_arns":                  ("SINK", 0.55, ("CWE-269",)),

    # ── Encryption at rest ─────────────────────────────────────────── CWE-311
    "encrypted":                            ("SINK", 0.70, ("CWE-311",)),
    "storage_encrypted":                    ("SINK", 0.80, ("CWE-311",)),
    "at_rest_encryption_enabled":           ("SINK", 0.85, ("CWE-311",)),
    "enable_disk_encryption":               ("SINK", 0.85, ("CWE-311",)),
    "disk_encryption_enabled":              ("SINK", 0.85, ("CWE-311",)),
    "encryption_at_rest_enabled":           ("SINK", 0.85, ("CWE-311",)),
    "kms_key_id":                           ("SINK", 0.50, ("CWE-311",)),
    "kms_master_key_id":                    ("SINK", 0.50, ("CWE-311",)),
    "server_side_encryption_configuration": ("SINK", 0.70, ("CWE-311",)),
    "sse_algorithm":                        ("SINK", 0.65, ("CWE-311",)),
    "enable_volume_encryption":             ("SINK", 0.85, ("CWE-311",)),
    "unencrypted_filesystem":               ("SINK", 0.90, ("CWE-311",)),

    # ── Encryption in transit / TLS ────────────────────────────────── CWE-319 / CWE-326
    "ssl_enforcement_enabled":              ("SINK", 0.85, ("CWE-319",)),
    "require_secure_transport":             ("SINK", 0.85, ("CWE-319",)),
    "ssl_policy":                           ("SINK", 0.70, ("CWE-319",)),
    "minimum_tls_version":                  ("SINK", 0.70, ("CWE-326",)),
    "min_tls_version":                      ("SINK", 0.70, ("CWE-326",)),
    "tls_config":                           ("SINK", 0.65, ("CWE-326",)),
    "https_only":                           ("SINK", 0.80, ("CWE-319",)),
    "enable_https_traffic_only":            ("SINK", 0.85, ("CWE-319",)),
    "insecure":                             ("SINK", 0.85, ("CWE-319",)),
    "skip_ssl_verification":                ("SINK", 0.90, ("CWE-295",)),
    "ssl_verify":                           ("SINK", 0.85, ("CWE-295",)),

    # ── Hardcoded secrets / credentials ───────────────────────────── CWE-798
    "password":                             ("SINK", 0.80, ("CWE-798",)),
    "secret":                               ("SINK", 0.80, ("CWE-798",)),
    "secret_key":                           ("SINK", 0.85, ("CWE-798",)),
    "api_key":                              ("SINK", 0.85, ("CWE-798",)),
    "access_key":                           ("SINK", 0.85, ("CWE-798",)),
    "access_key_id":                        ("SINK", 0.85, ("CWE-798",)),
    "secret_access_key":                    ("SINK", 0.90, ("CWE-798",)),
    "private_key":                          ("SINK", 0.90, ("CWE-798",)),
    "private_key_pem":                      ("SINK", 0.90, ("CWE-798",)),
    "token":                                ("SINK", 0.75, ("CWE-798",)),
    "auth_token":                           ("SINK", 0.80, ("CWE-798",)),
    "connection_string":                    ("SINK", 0.80, ("CWE-798",)),
    "client_secret":                        ("SINK", 0.90, ("CWE-798",)),
    "db_password":                          ("SINK", 0.85, ("CWE-798",)),
    "database_password":                    ("SINK", 0.85, ("CWE-798",)),

    # ── Audit / logging disabled ───────────────────────────────────── CWE-778
    "enable_logging":                       ("SINK", 0.65, ("CWE-778",)),
    "audit_log_config":                     ("SINK", 0.60, ("CWE-778",)),
    "cloud_watch_logs_enabled":             ("SINK", 0.70, ("CWE-778",)),
    "enable_cloudwatch_logs":               ("SINK", 0.70, ("CWE-778",)),
    "access_logs":                          ("SINK", 0.65, ("CWE-778",)),
    "log_retention_in_days":                ("SINK", 0.55, ("CWE-778",)),
    "flow_logs":                            ("SINK", 0.65, ("CWE-778",)),
    "audit_logs_enabled":                   ("SINK", 0.70, ("CWE-778",)),
    "threat_detection_enabled":             ("SINK", 0.65, ("CWE-778",)),
    "advanced_threat_protection_enabled":   ("SINK", 0.65, ("CWE-778",)),

    # ── Network exposure ───────────────────────────────────────────── CWE-284
    "cidr_blocks":                          ("SINK", 0.70, ("CWE-284",)),
    "ipv6_cidr_blocks":                     ("SINK", 0.65, ("CWE-284",)),
    "source_ranges":                        ("SINK", 0.70, ("CWE-284",)),
    "ingress":                              ("SINK", 0.55, ("CWE-284",)),
    "egress":                               ("SINK", 0.45, ("CWE-284",)),
    "from_port":                            ("SINK", 0.50, ("CWE-284",)),
    "to_port":                              ("SINK", 0.50, ("CWE-284",)),
    "protocol":                             ("SINK", 0.40, ("CWE-284",)),
    "allowed_ip_ranges":                    ("SINK", 0.70, ("CWE-284",)),
    "open_to_internet":                     ("SINK", 0.90, ("CWE-284",)),
    "unrestricted_ingress":                 ("SINK", 0.90, ("CWE-284",)),
    "network_access_rules":                 ("SINK", 0.65, ("CWE-284",)),

    # ── Kubernetes container security ──────────────────────────────── CWE-250 / CWE-269
    "privileged":                           ("SINK", 0.95, ("CWE-250",)),
    "allowPrivilegeEscalation":             ("SINK", 0.90, ("CWE-269",)),
    "runAsRoot":                            ("SINK", 0.90, ("CWE-250",)),
    "runAsNonRoot":                         ("SINK", 0.75, ("CWE-250",)),
    "runAsUser":                            ("SINK", 0.55, ("CWE-250",)),
    "hostNetwork":                          ("SINK", 0.85, ("CWE-284",)),
    "hostPID":                              ("SINK", 0.85, ("CWE-284",)),
    "hostIPC":                              ("SINK", 0.85, ("CWE-284",)),
    "readOnlyRootFilesystem":               ("SINK", 0.70, ("CWE-250",)),
    "capabilities.add":                     ("SINK", 0.80, ("CWE-250",)),
    "hostPath":                             ("SINK", 0.80, ("CWE-284",)),   # volume mount
    "automountServiceAccountToken":         ("SINK", 0.70, ("CWE-284",)),
    "defaultMode":                          ("SINK", 0.55, ("CWE-284",)),

    # ── Missing authentication ─────────────────────────────────────── CWE-306
    "authentication_enabled":              ("SINK", 0.80, ("CWE-306",)),
    "enable_authentication":               ("SINK", 0.80, ("CWE-306",)),
    "anonymous_auth":                      ("SINK", 0.90, ("CWE-306",)),
    "auth_enabled":                        ("SINK", 0.80, ("CWE-306",)),

    # ── Versioning / backup ────────────────────────────────────────── CWE-284
    "versioning_enabled":                  ("SINK", 0.60, ("CWE-284",)),
    "deletion_protection":                 ("SINK", 0.65, ("CWE-284",)),
    "backup_retention_period":             ("SINK", 0.55, ("CWE-284",)),
    "point_in_time_recovery_enabled":      ("SINK", 0.55, ("CWE-284",)),
}

IAC_SOURCES: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── Terraform variable interpolations ───────────────────────────────────
    "var":                                  ("SOURCE", 0.70, ("CWE-20",)),
    "variable":                             ("SOURCE", 0.70, ("CWE-20",)),
    "data":                                 ("SOURCE", 0.50, ("CWE-20",)),
    "${var.":                               ("SOURCE", 0.85, ("CWE-20",)),
    "${data.":                              ("SOURCE", 0.75, ("CWE-20",)),
    "${local.":                             ("SOURCE", 0.60, ("CWE-20",)),
    # ── Environment variable lookups ────────────────────────────────────────
    "env":                                  ("SOURCE", 0.65, ("CWE-214",)),
    "TF_VAR_":                              ("SOURCE", 0.80, ("CWE-214",)),
    # ── Kubernetes ConfigMap / Secret refs ───────────────────────────────────
    "valueFrom.secretKeyRef":              ("SOURCE", 0.75, ("CWE-20",)),
    "valueFrom.configMapKeyRef":           ("SOURCE", 0.65, ("CWE-20",)),
    "envFrom.secretRef":                   ("SOURCE", 0.75, ("CWE-20",)),
    "envFrom.configMapRef":                ("SOURCE", 0.65, ("CWE-20",)),
    # ── Dynamic lookups ─────────────────────────────────────────────────────
    "${each.value":                        ("SOURCE", 0.70, ("CWE-20",)),
    "${each.key":                          ("SOURCE", 0.70, ("CWE-20",)),
}

IAC_SANITIZERS: dict[str, tuple[str, float, tuple[str, ...]]] = {
    # ── Secrets management ───────────────────────────────────────────────────
    "key_vault_id":                        ("SANITIZER", 0.80, ("CWE-798",)),
    "key_vault_secret_id":                 ("SANITIZER", 0.85, ("CWE-798",)),
    "secret_id":                           ("SANITIZER", 0.80, ("CWE-798",)),
    "ssm_parameter":                       ("SANITIZER", 0.80, ("CWE-798",)),
    "secrets_manager_arn":                 ("SANITIZER", 0.85, ("CWE-798",)),
    "vault_addr":                          ("SANITIZER", 0.75, ("CWE-798",)),
    "aws_secretsmanager_secret":           ("SANITIZER", 0.85, ("CWE-798",)),
    # ── Encryption ───────────────────────────────────────────────────────────
    "kms_encrypted":                       ("SANITIZER", 0.85, ("CWE-311",)),
    "kms_key_arn":                         ("SANITIZER", 0.80, ("CWE-311",)),
    "customer_managed_key":                ("SANITIZER", 0.80, ("CWE-311",)),
    "cmk_enabled":                         ("SANITIZER", 0.80, ("CWE-311",)),
    # ── Network restrictions ─────────────────────────────────────────────────
    "private_endpoint":                    ("SANITIZER", 0.75, ("CWE-284",)),
    "service_endpoint":                    ("SANITIZER", 0.65, ("CWE-284",)),
    "network_acls":                        ("SANITIZER", 0.65, ("CWE-284",)),
    "security_group_id":                   ("SANITIZER", 0.60, ("CWE-284",)),
    # ── Kubernetes security contexts ────────────────────────────────────────
    "securityContext":                     ("SANITIZER", 0.60, ("CWE-250",)),
    "podSecurityPolicy":                   ("SANITIZER", 0.65, ("CWE-250",)),
    "networkPolicy":                       ("SANITIZER", 0.70, ("CWE-284",)),
    # ── Terraform validation ─────────────────────────────────────────────────
    "validation":                          ("SANITIZER", 0.70, ()),
    "precondition":                        ("SANITIZER", 0.65, ()),
    "lifecycle.prevent_destroy":           ("SANITIZER", 0.60, ("CWE-284",)),
}


# Self-contained registry for IaC (Terraform HCL + Kubernetes YAML):
#   from prism.parser.sinks.iac_sinks import IAC_SINK_REGISTRY
IAC_SINK_REGISTRY: dict[str, dict] = {
    "sinks":      IAC_SINKS,
    "sources":    IAC_SOURCES,
    "sanitizers": IAC_SANITIZERS,
}