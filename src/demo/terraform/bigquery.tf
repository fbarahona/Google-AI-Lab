# BigQuery Dataset
resource "google_bigquery_dataset" "cyber_dataset" {
  # checkov:skip=CKV_GCP_81: "Default Google-managed encryption keys protect data at rest by default for zero-continuous-cost baseline; CMEK/CSEK is supported via var.kms_key_name"
  project                    = var.project_id
  dataset_id                 = var.dataset_id
  friendly_name              = "Cymbal Cyber Security Analytics"
  description                = "Streaming and correlated event data for near real-time AI threat detection."
  location                   = var.bigquery_location
  delete_contents_on_destroy = true

  dynamic "default_encryption_configuration" {
    for_each = var.kms_key_name != "" ? [var.kms_key_name] : []
    content {
      kms_key_name = default_encryption_configuration.value
    }
  }

  depends_on = [google_project_service.required]
}

# 1. user_access_events Table
resource "google_bigquery_table" "user_access_events" {
  # checkov:skip=CKV_GCP_80: "Default Google-managed encryption keys protect data at rest by default for zero-continuous-cost baseline; CMEK/CSEK is supported via var.kms_key_name"
  project                  = var.project_id
  dataset_id               = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id                 = "user_access_events"
  description              = "Logs user login attempts and session creation, linking users to assigned internal IPs."
  deletion_protection      = false
  require_partition_filter = false

  dynamic "encryption_configuration" {
    for_each = var.kms_key_name != "" ? [var.kms_key_name] : []
    content {
      kms_key_name = encryption_configuration.value
    }
  }

  time_partitioning {
    type  = "DAY"
    field = "event_timestamp"
  }

  clustering = ["user_id", "assigned_internal_ip", "event_type"]

  schema = jsonencode([
    { name = "event_timestamp", type = "TIMESTAMP", mode = "REQUIRED", description = "Timestamp of login or access event." },
    { name = "event_type", type = "STRING", mode = "REQUIRED", description = "login_success, login_failure, etc." },
    { name = "user_id", type = "STRING", mode = "REQUIRED", description = "Unique user identifier." },
    { name = "source_ip", type = "STRING", mode = "NULLABLE", description = "Client public source IP." },
    { name = "assigned_internal_ip", type = "STRING", mode = "NULLABLE", description = "VPN assigned internal IP." },
    { name = "device_id", type = "STRING", mode = "NULLABLE", description = "Device hardware identifier." },
    { name = "device_os", type = "STRING", mode = "NULLABLE", description = "Client operating system." },
    { name = "user_agent", type = "STRING", mode = "NULLABLE", description = "Browser / client user agent string." },
    { name = "application_name", type = "STRING", mode = "NULLABLE", description = "VPN / SSO application name." }
  ])
}

# 2. network_events Table
resource "google_bigquery_table" "network_events" {
  # checkov:skip=CKV_GCP_80: "Default Google-managed encryption keys protect data at rest by default for zero-continuous-cost baseline; CMEK/CSEK is supported via var.kms_key_name"
  project                  = var.project_id
  dataset_id               = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id                 = "network_events"
  description              = "Logs granular network activity like DNS queries, connections, and file transfers."
  deletion_protection      = false
  require_partition_filter = false

  dynamic "encryption_configuration" {
    for_each = var.kms_key_name != "" ? [var.kms_key_name] : []
    content {
      kms_key_name = encryption_configuration.value
    }
  }

  time_partitioning {
    type  = "DAY"
    field = "event_timestamp"
  }

  clustering = ["source_ip", "user_id", "event_type"]

  schema = jsonencode([
    { name = "event_timestamp", type = "TIMESTAMP", mode = "REQUIRED", description = "Event occurrence timestamp." },
    { name = "event_type", type = "STRING", mode = "REQUIRED", description = "dns_query, connection_established, file_transfer, policy_violation." },
    { name = "user_id", type = "STRING", mode = "NULLABLE", description = "User associated with socket/session." },
    { name = "source_ip", type = "STRING", mode = "REQUIRED", description = "Internal originating source IP." },
    { name = "source_port", type = "INT64", mode = "NULLABLE", description = "Source port." },
    { name = "destination_ip", type = "STRING", mode = "NULLABLE", description = "Destination IP." },
    { name = "destination_port", type = "INT64", mode = "NULLABLE", description = "Destination port." },
    { name = "protocol", type = "STRING", mode = "NULLABLE", description = "TCP, UDP, ICMP." },
    { name = "bytes_transferred", type = "INT64", mode = "NULLABLE", description = "Bytes transferred count." },
    { name = "source_process_name", type = "STRING", mode = "NULLABLE", description = "Process name initiating request." },
    { name = "network_domain", type = "STRING", mode = "NULLABLE", description = "Domain queried or visited." },
    { name = "file_name", type = "STRING", mode = "NULLABLE", description = "File name if file transfer." },
    { name = "file_type", type = "STRING", mode = "NULLABLE", description = "File extension." },
    { name = "command_line", type = "STRING", mode = "NULLABLE", description = "Command executed if policy violation." },
    { name = "permission_level_requested", type = "STRING", mode = "NULLABLE", description = "Permission level e.g. root/admin." },
    { name = "file_hash_sha256", type = "STRING", mode = "NULLABLE", description = "SHA256 payload hash." }
  ])
}

# 3. Threat Scoring UDF (Single Source of Truth)
resource "google_bigquery_routine" "calculate_threat_score" {
  project      = var.project_id
  dataset_id   = google_bigquery_dataset.cyber_dataset.dataset_id
  routine_id   = "calculate_threat_score"
  routine_type = "SCALAR_FUNCTION"
  language     = "SQL"

  arguments {
    name      = "event_type"
    data_type = "{\"typeKind\": \"STRING\"}"
  }
  arguments {
    name      = "permission_level"
    data_type = "{\"typeKind\": \"STRING\"}"
  }
  arguments {
    name      = "file_type"
    data_type = "{\"typeKind\": \"STRING\"}"
  }
  arguments {
    name      = "command_line"
    data_type = "{\"typeKind\": \"STRING\"}"
  }
  arguments {
    name      = "network_domain"
    data_type = "{\"typeKind\": \"STRING\"}"
  }
  arguments {
    name      = "user_agent"
    data_type = "{\"typeKind\": \"STRING\"}"
  }

  return_type = "{\"typeKind\": \"INT64\"}"

  definition_body = <<-EOF
    (
      CASE
        WHEN event_type = 'policy_violation' THEN 50
        WHEN event_type = 'dns_query' AND `${var.project_id}.${google_bigquery_dataset.cyber_dataset.dataset_id}.is_malicious_domain`(network_domain) THEN 60
        ELSE 0
      END
      + CASE WHEN permission_level IN ('root', 'admin') THEN 35 ELSE 0 END
      + CASE WHEN REGEXP_CONTAINS(user_agent, r'^(python-requests|curl|Go-http-client)') THEN 20 ELSE 0 END
      + CASE WHEN event_type = 'file_transfer' AND file_type IN ('exe', 'dll', 'ps1', 'bat', 'vbs') THEN 40 ELSE 0 END
      + CASE
          WHEN `${var.project_id}.${google_bigquery_dataset.cyber_dataset.dataset_id}.is_malicious_command`(command_line) THEN 100
          WHEN REGEXP_CONTAINS(command_line, r'^(ipconfig|ping|ls -la|df -h|hostname)') THEN 0
          WHEN command_line IS NOT NULL THEN 10
          ELSE 0
        END
    )
  EOF

  depends_on = [
    google_bigquery_routine.is_malicious_domain,
    google_bigquery_routine.is_malicious_command
  ]
}

resource "google_bigquery_routine" "is_malicious_domain" {
  project      = var.project_id
  dataset_id   = google_bigquery_dataset.cyber_dataset.dataset_id
  routine_id   = "is_malicious_domain"
  routine_type = "SCALAR_FUNCTION"
  language     = "SQL"

  arguments {
    name      = "network_domain"
    data_type = "{\"typeKind\": \"STRING\"}"
  }

  return_type = "{\"typeKind\": \"BOOL\"}"

  definition_body = <<-EOF
    REGEXP_CONTAINS(network_domain, r'(?i)(\.ru$|\.xyz$|bad-domain|payload-downloader|c2-server|apt-group-data-exfil\.org$)')
  EOF
}

resource "google_bigquery_routine" "is_malicious_command" {
  project      = var.project_id
  dataset_id   = google_bigquery_dataset.cyber_dataset.dataset_id
  routine_id   = "is_malicious_command"
  routine_type = "SCALAR_FUNCTION"
  language     = "SQL"

  arguments {
    name      = "command_line"
    data_type = "{\"typeKind\": \"STRING\"}"
  }

  return_type = "{\"typeKind\": \"BOOL\"}"

  definition_body = <<-EOF
    REGEXP_CONTAINS(command_line, r'(?i)(powershell -enc|IEX|DownloadString|mimikatz|payload)')
  EOF
}

# 4. adk_threat_assessment Table
resource "google_bigquery_table" "adk_threat_assessment" {
  # checkov:skip=CKV_GCP_80: "Default Google-managed encryption keys protect data at rest by default for zero-continuous-cost baseline; CMEK/CSEK is supported via var.kms_key_name"
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "adk_threat_assessment"
  description         = "Stores the final output and reasoning from the ADK agent workflow."
  deletion_protection = false

  dynamic "encryption_configuration" {
    for_each = var.kms_key_name != "" ? [var.kms_key_name] : []
    content {
      kms_key_name = encryption_configuration.value
    }
  }

  time_partitioning {
    type  = "DAY"
    field = "transaction_window_end"
  }

  clustering = ["user_id", "agent_decision"]

  schema = jsonencode([
    { name = "transaction_window_end", type = "TIMESTAMP", mode = "NULLABLE" },
    { name = "user_id", type = "STRING", mode = "NULLABLE" },
    { name = "device_id", type = "STRING", mode = "NULLABLE" },
    { name = "source_ip", type = "STRING", mode = "NULLABLE" },
    { name = "total_2_min_threat_score", type = "INT64", mode = "NULLABLE" },
    { name = "agent_decision", type = "STRING", mode = "NULLABLE" },
    { name = "agent_reason", type = "STRING", mode = "NULLABLE" },
    { name = "human_decision", type = "STRING", mode = "NULLABLE" },
    { name = "human_reason", type = "STRING", mode = "NULLABLE" },
    { name = "alert_payload", type = "STRING", mode = "NULLABLE" }
  ])
}

# 4. soc_tickets Table (append-only: every state change is a new row; read the latest
# state through soc_tickets_current)
resource "google_bigquery_table" "soc_tickets" {
  # checkov:skip=CKV_GCP_80: "Default Google-managed encryption keys protect data at rest by default for zero-continuous-cost baseline; CMEK/CSEK is supported via var.kms_key_name"
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "soc_tickets"
  description         = "Append-only ticket log for the SOC ticketing system. Query soc_tickets_current for the latest state."
  deletion_protection = false

  dynamic "encryption_configuration" {
    for_each = var.kms_key_name != "" ? [var.kms_key_name] : []
    content {
      kms_key_name = encryption_configuration.value
    }
  }

  time_partitioning {
    type  = "DAY"
    field = "created_at"
  }

  clustering = ["status", "user_id"]

  schema = jsonencode([
    { name = "ticket_id", type = "STRING", mode = "REQUIRED" },
    { name = "created_at", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "user_id", type = "STRING", mode = "REQUIRED" },
    { name = "device_id", type = "STRING", mode = "REQUIRED" },
    { name = "source_ip", type = "STRING", mode = "REQUIRED" },
    { name = "threat_score", type = "INT64", mode = "REQUIRED" },
    { name = "severity", type = "STRING", mode = "REQUIRED" },
    { name = "status", type = "STRING", mode = "REQUIRED" },
    { name = "agent_decision", type = "STRING", mode = "REQUIRED" },
    { name = "agent_reason", type = "STRING", mode = "REQUIRED" },
    { name = "mitre_tactics", type = "STRING", mode = "REPEATED" },
    { name = "indicators_of_compromise", type = "STRING", mode = "REPEATED" },
    { name = "screenshot_url", type = "STRING", mode = "NULLABLE" },
    { name = "structured_report", type = "STRING", mode = "REQUIRED" },
    { name = "human_decision", type = "STRING", mode = "NULLABLE" },
    { name = "human_comment", type = "STRING", mode = "NULLABLE" },
    { name = "adjudicated_at", type = "TIMESTAMP", mode = "NULLABLE" }
  ])
}

# 4b. Latest state of each ticket, deduplicated once here instead of in every query,
# plus the classifications the console's KPIs and charts group by.
resource "google_bigquery_table" "soc_tickets_current" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "soc_tickets_current"
  description         = "One row per ticket (its latest state) with dashboard classifications."
  deletion_protection = false

  view {
    query          = <<-SQL
      SELECT
        t.*,
        t.agent_decision = 'SIMULATED' AS is_simulated,
        t.agent_decision = 'FALSE_POSITIVE_AUTO_CLOSED' AS is_auto_closed,
        COALESCE(t.human_decision, '') != '' AS is_adjudicated,
        t.status IN ('OPEN', 'ESCALATED', 'UNDER_INVESTIGATION')
          AND COALESCE(t.human_decision, '') = '' AS is_pending,
        CASE
          WHEN t.status IN ('OPEN', 'ESCALATED', 'UNDER_INVESTIGATION')
            AND COALESCE(t.human_decision, '') = '' THEN 'Open'
          WHEN t.status = 'RESOLVED' AND t.human_decision = 'Genuine Threat' THEN 'Escalated'
          WHEN t.status = 'RESOLVED' THEN 'Closed'
          ELSE 'In Progress'
        END AS status_bucket,
        CASE
          WHEN t.status = 'RESOLVED' THEN 'Within SLA'
          WHEN TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), t.created_at, MINUTE) > 60 THEN 'Breached SLA'
          WHEN TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), t.created_at, MINUTE) > 30 THEN 'Approaching SLA'
          ELSE 'Within SLA'
        END AS sla_bucket
      FROM `${var.project_id}.${google_bigquery_dataset.cyber_dataset.dataset_id}.${google_bigquery_table.soc_tickets.table_id}` AS t
      WHERE TRUE
      -- An analyst verdict wins over any later agent row; otherwise the newest row wins.
      QUALIFY ROW_NUMBER() OVER (
        PARTITION BY t.ticket_id
        ORDER BY
          IF(COALESCE(t.human_decision, '') != '', 1, 2),
          COALESCE(t.adjudicated_at, t.created_at) DESC
      ) = 1
    SQL
    use_legacy_sql = false
  }
}

# 5. agent_events Table (for BigQuery Agent Analytics Plugin)
resource "google_bigquery_table" "agent_events" {
  # checkov:skip=CKV_GCP_80: "Default Google-managed encryption keys protect data at rest by default for zero-continuous-cost baseline; CMEK/CSEK is supported via var.kms_key_name"
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "agent_events"
  description         = "Stores tracing and execution events for ADK agents via BigQueryAgentAnalyticsPlugin."
  deletion_protection = false

  dynamic "encryption_configuration" {
    for_each = var.kms_key_name != "" ? [var.kms_key_name] : []
    content {
      kms_key_name = encryption_configuration.value
    }
  }

  time_partitioning {
    type = "DAY"
  }
}

# 6. BigLake object table over the screenshots bucket. BigQuery reads the bucket through
# the connection's own service account (granted objectViewer in iam.tf), so a new PNG is
# visible to the agent without any Terraform or SQL change.
resource "google_bigquery_connection" "screenshots" {
  project       = var.project_id
  connection_id = "cymbal_screenshots"
  location      = var.bigquery_location
  friendly_name = "Cymbal Cyber screenshots (object table)"
  description   = "Cloud resource connection BigQuery uses to list the screenshots bucket."
  cloud_resource {}

  depends_on = [google_project_service.required]
}

resource "google_bigquery_table" "user_screenshots_objects" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "user_screenshots_objects"
  description         = "Object table: one row per desktop screenshot in the screenshots bucket."
  deletion_protection = false

  external_data_configuration {
    connection_id   = google_bigquery_connection.screenshots.name
    autodetect      = false
    object_metadata = "SIMPLE"
    source_uris     = ["gs://${google_storage_bucket.screenshots.name}/*.png"]
  }

  # Object tables have a fixed schema that BigQuery fills in.
  lifecycle {
    ignore_changes = [schema]
  }

  depends_on = [google_storage_bucket_iam_member.screenshots_connection_reader]
}

# 7. View linking user_id to its screenshot (what get_gcs_uri_for_user queries).
resource "google_bigquery_table" "user_screenshots_view" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "user_screenshots_view"
  description         = "user_id -> screenshot GCS URI, derived from the user_screenshots_objects object table."
  deletion_protection = false

  view {
    query          = <<-SQL
      SELECT
        REGEXP_EXTRACT(uri, r'([^/]+)\.png$') AS user_id,
        uri AS gcs_uri,
        updated AS screenshot_updated_at
      FROM `${var.project_id}.${google_bigquery_dataset.cyber_dataset.dataset_id}.${google_bigquery_table.user_screenshots_objects.table_id}`
    SQL
    use_legacy_sql = false
  }
}

# 8. Detection Alerts Table (Partitioned by window_end, clustered by user_id)
resource "google_bigquery_table" "alerts" {
  # checkov:skip=CKV_GCP_80: "Default Google-managed encryption keys protect data at rest by default for zero-continuous-cost baseline; CMEK/CSEK is supported via var.kms_key_name"
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "alerts"
  description         = "De-duplicated alert events detected by scheduled micro-batch detector, Dataflow, or CQ."
  deletion_protection = false
  # Must remain false: adk_agent/threat_detector.py MERGE DML matches on target.alert_id without target partition filter
  require_partition_filter = false

  dynamic "encryption_configuration" {
    for_each = var.kms_key_name != "" ? [var.kms_key_name] : []
    content {
      kms_key_name = encryption_configuration.value
    }
  }

  time_partitioning {
    type  = "DAY"
    field = "window_end"
  }

  clustering = ["user_id", "status", "engine"]

  schema = jsonencode([
    { name = "alert_id", type = "STRING", mode = "REQUIRED", description = "Primary key: user_id|window_end" },
    { name = "incident_id", type = "STRING", mode = "NULLABLE", description = "alert_id of the window that opened this incident (correlated windows share it)" },
    { name = "engine", type = "STRING", mode = "REQUIRED", description = "Detection engine: scheduled, dataflow, cq" },
    { name = "user_id", type = "STRING", mode = "REQUIRED", description = "Target user identifier" },
    { name = "device_id", type = "STRING", mode = "REQUIRED", description = "Target device identifier" },
    { name = "source_ip", type = "STRING", mode = "REQUIRED", description = "Client public or internal IP" },
    { name = "window_start", type = "TIMESTAMP", mode = "REQUIRED", description = "Closed 2-minute aggregation window start" },
    { name = "window_end", type = "TIMESTAMP", mode = "REQUIRED", description = "Closed 2-minute aggregation window end" },
    { name = "total_2_min_threat_score", type = "INT64", mode = "REQUIRED", description = "Aggregated anomaly score" },
    { name = "high_privilege_request_count", type = "INT64", mode = "NULLABLE", description = "Count of high privilege requests" },
    { name = "malicious_command_count", type = "INT64", mode = "NULLABLE", description = "Count of suspicious commands" },
    { name = "malicious_dns_count", type = "INT64", mode = "NULLABLE", description = "Count of suspicious DNS queries" },
    { name = "status", type = "STRING", mode = "REQUIRED", description = "NEW | PUBLISHED | INVESTIGATING | RETRY_PENDING | DONE | DEAD_LETTERED | CORRELATED (folded into an open incident, never published)" },
    { name = "detected_at", type = "TIMESTAMP", mode = "REQUIRED", description = "Timestamp when alert was evaluated" },
    { name = "updated_at", type = "TIMESTAMP", mode = "REQUIRED", description = "Timestamp of last status transition" },
    { name = "payload", type = "JSON", mode = "REQUIRED", description = "Complete contract JSON payload" }
  ])
}

# 8b. Incidents: correlated alert windows rolled up, one row per incident.
resource "google_bigquery_table" "incidents" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "incidents"
  description         = "One row per incident: the published alert plus every window correlated into it."
  deletion_protection = false

  view {
    query          = <<-SQL
      SELECT
        incident_id,
        ANY_VALUE(user_id) AS user_id,
        MIN(window_start) AS first_seen,
        MAX(window_end) AS last_seen,
        COUNT(*) AS windows,
        SUM(total_2_min_threat_score) AS total_threat_score,
        MAX(total_2_min_threat_score) AS peak_window_score,
        SUM(malicious_command_count) AS malicious_commands,
        SUM(malicious_dns_count) AS malicious_dns_queries,
        SUM(high_privilege_request_count) AS high_privilege_requests,
        ANY_VALUE(IF(alert_id = incident_id, status, NULL)) AS published_alert_status
      FROM `${var.project_id}.${google_bigquery_dataset.cyber_dataset.dataset_id}.${google_bigquery_table.alerts.table_id}`
      WHERE incident_id IS NOT NULL
      GROUP BY incident_id
    SQL
    use_legacy_sql = false
  }
}

# 9. Alerts Dead Letter Table (Captures alerts that failed 5 delivery attempts)
resource "google_bigquery_table" "alerts_dead_letter" {
  # checkov:skip=CKV_GCP_80: "Default Google-managed encryption keys protect data at rest by default for zero-continuous-cost baseline; CMEK/CSEK is supported via var.kms_key_name"
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "alerts_dead_letter"
  description         = "Records all alert payloads delivered to cymbal_cyber_alerts_dlq after delivery failure."
  deletion_protection = false

  dynamic "encryption_configuration" {
    for_each = var.kms_key_name != "" ? [var.kms_key_name] : []
    content {
      kms_key_name = encryption_configuration.value
    }
  }

  time_partitioning {
    type  = "DAY"
    field = "publish_time"
  }

  # Schema required by Pub/Sub BigQuery subscriptions with write_metadata = true
  # and use_topic_schema = false. alert_id is read from the attributes JSON.
  schema = jsonencode([
    { name = "subscription_name", type = "STRING", mode = "NULLABLE", description = "Pub/Sub subscription name" },
    { name = "message_id", type = "STRING", mode = "NULLABLE", description = "Pub/Sub message ID" },
    { name = "publish_time", type = "TIMESTAMP", mode = "NULLABLE", description = "Time the message landed on the DLQ topic" },
    { name = "data", type = "STRING", mode = "NULLABLE", description = "Raw alert contract JSON body" },
    { name = "attributes", type = "STRING", mode = "NULLABLE", description = "JSON string of message attributes (includes alert_id)" }
  ])
}

