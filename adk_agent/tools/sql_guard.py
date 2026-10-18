"""
SQL-injection and dataset-sandbox controls for the investigation queries.

Entity values are validated and bound as query parameters; the parts SQL cannot
parameterize (entity type, time window) come from fixed allow-lists; and every query
is checked for destructive statements and cross-dataset references before it runs.
"""

import os
import re

# Accepted entity_type spellings, normalised once so the cloud query and the local
# log scan always agree on what was asked for.
ENTITY_TYPE_ALIASES = {
    "user": "user",
    "user_id": "user",
    "device": "device",
    "device_id": "device",
    "ip": "ip",
    "source_ip": "ip",
}
ALLOWED_ENTITY_TYPES = set(ENTITY_TYPE_ALIASES)
ALLOWED_INTERVAL_WINDOWS = {
    "1 HOUR",
    "2 HOUR",
    "6 HOUR",
    "12 HOUR",
    "24 HOUR",
    "48 HOUR",
    "7 DAY",
    "30 DAY",
}
DEFAULT_MAX_BYTES_BILLED = int(
    os.getenv("BQ_MAX_BYTES_BILLED", "1073741824")
)  # 1 GB default scan ceiling
DESTRUCTIVE_SQL_TOKENS = {
    "DROP",
    "ALTER",
    "DELETE",
    "UPDATE",
    "INSERT",
    "TRUNCATE",
    "GRANT",
    "REVOKE",
    "MERGE",
}


def validate_dataset_sandboxing(
    sql: str, allowed_dataset: str, allow_metadata: bool = False
) -> None:
    """
    Validates that a SQL query strictly references the designated allowed dataset
    and does not access unauthorized tenant or project datasets.

    Raises:
        ValueError: If unauthorized cross-dataset references are detected.
    """
    if not sql or not allowed_dataset:
        return

    clean_sql = re.sub(r"--.*$", "", sql, flags=re.MULTILINE)
    clean_sql = re.sub(r"/\*.*?\*/", "", clean_sql, flags=re.DOTALL)

    # Extract CTE names from WITH clauses so local aliases are not mistaken for external tables
    cte_names = set(
        re.findall(r"(?:WITH|,)\s*([a-zA-Z0-9_]+)\s+AS\s*\(", clean_sql, re.IGNORECASE)
    )

    # Match tables in FROM, JOIN, or TABLE clauses
    table_candidates = re.findall(
        r"\b(?:FROM|JOIN)\s+(?:TABLE\s+)?([`'\"a-zA-Z0-9_\-\.]+)",
        clean_sql,
        re.IGNORECASE,
    )

    # Match backticked table/function qualifiers `dataset.table` or `project.dataset.table`
    backticked_candidates = re.findall(r"`([a-zA-Z0-9_\-\.]+)`", clean_sql)

    all_candidates = set(table_candidates) | set(backticked_candidates)

    for item in all_candidates:
        ident = item.strip("`'\" \t\n")
        if (
            not ident
            or ident.startswith("(")
            or ident.upper() == "UNNEST"
            or ident in cte_names
        ):
            continue
        if "." in ident:
            parts = ident.split(".")
            if len(parts) >= 2:
                dataset_name = parts[-2]
                if allow_metadata and "information_schema" in dataset_name.lower():
                    continue
                if dataset_name.lower() != allowed_dataset.lower():
                    raise ValueError(
                        f"Cross-dataset reference forbidden: query references dataset '{dataset_name}', "
                        f"but only '{allowed_dataset}' is permitted."
                    )


def validate_safe_sql_query(
    sql: str, allow_metadata: bool = False, allowed_dataset: str | None = None
) -> None:
    """
    Defense-in-depth pre-execution guardrail validating that SQL queries intended
    for read-only forensic analysis do not contain destructive DML/DDL operations,
    do not access unauthorized system metadata (INFORMATION_SCHEMA), and only reference
    authorized datasets in the GCP project.

    While standard tool methods use parameterized query templates, this validator
    serves as a secondary defense boundary against future dynamic SQL queries or
    custom analyst query extensions. Raises ValueError if violations are detected.
    """
    if not sql:
        return

    # Block unauthorized access to BigQuery INFORMATION_SCHEMA metadata views
    if "information_schema" in sql.lower() and not allow_metadata:
        raise ValueError("Access to INFORMATION_SCHEMA is restricted.")

    upper_sql = sql.upper()
    for token in DESTRUCTIVE_SQL_TOKENS:
        if re.search(rf"\b{token}\b", upper_sql):
            raise ValueError(
                f"Security Policy Violation: Destructive SQL operation '{token}' is strictly forbidden."
            )

    # Sandbox dataset references if an allowed dataset is enforced
    if allowed_dataset:
        validate_dataset_sandboxing(sql, allowed_dataset, allow_metadata=allow_metadata)


ENTITY_SAFE_PATTERN = re.compile(r"^[a-zA-Z0-9\._\-:@]+$")
SQL_INJECTION_DANGEROUS_PATTERNS = [
    re.compile(r"['\";\\]"),
    re.compile(r"--"),
    re.compile(r"/\*|\*/"),
    re.compile(
        r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|EXEC|EXECUTE)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(OR|AND)\b\s+['\"0-9\w]", re.IGNORECASE),
]


def sanitize_entity_value(value: str, field_name: str = "entity_id") -> str:
    """
    Validates and sanitizes entity values (user IDs, device IDs, IP addresses)
    to prevent SQL injection vulnerabilities.

    Raises:
        ValueError: If value contains illegal characters or SQL injection patterns.
    """
    if value is None or not isinstance(value, str):
        raise ValueError(f"{field_name} must be a non-empty string.")

    trimmed = value.strip()
    if not trimmed:
        raise ValueError(f"{field_name} cannot be empty or whitespace.")

    for pattern in SQL_INJECTION_DANGEROUS_PATTERNS:
        if pattern.search(trimmed):
            raise ValueError(
                f"SQL Injection attempt or illegal characters detected in {field_name}: {trimmed!r}"
            )

    if not ENTITY_SAFE_PATTERN.match(trimmed):
        raise ValueError(
            f"{field_name} contains invalid characters: {trimmed!r}. "
            "Only alphanumeric characters, dots, hyphens, underscores, colons, and '@' are permitted."
        )

    return trimmed


def normalize_entity_type(entity_type: str) -> str:
    """Maps an accepted entity_type spelling to "user", "device" or "ip"."""
    if not entity_type or not isinstance(entity_type, str):
        raise ValueError("entity_type must be a non-empty string.")
    clean_type = ENTITY_TYPE_ALIASES.get(entity_type.strip().lower())
    if clean_type is None:
        raise ValueError(
            f"Invalid entity_type '{entity_type}'. Must be one of {sorted(ALLOWED_ENTITY_TYPES)}."
        )
    return clean_type
