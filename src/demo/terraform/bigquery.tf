# BigQuery Dataset
resource "google_bigquery_dataset" "cyber_dataset" {
  project                    = var.project_id
  dataset_id                 = var.dataset_id
  friendly_name              = "Cymbal Cyber Security Analytics"
  description                = "Streaming and correlated event data for near real-time AI threat detection."
  location                   = var.bigquery_location
  delete_contents_on_destroy = true

  depends_on = [google_project_service.required]
}

# 1. user_access_events Table
resource "google_bigquery_table" "user_access_events" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "user_access_events"
  description         = "Logs user login attempts and session creation, linking users to assigned internal IPs."
  deletion_protection = false

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
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "network_events"
  description         = "Logs granular network activity like DNS queries, connections, and file transfers."
  deletion_protection = false

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
        WHEN event_type = 'dns_query' AND REGEXP_CONTAINS(network_domain, r'(?i)(\.ru$|\.xyz$|bad-domain|payload-downloader|c2-server)') THEN 60
        ELSE 0
      END
      + CASE WHEN permission_level IN ('root', 'admin') THEN 35 ELSE 0 END
      + CASE WHEN REGEXP_CONTAINS(user_agent, r'^(python-requests|curl|Go-http-client)') THEN 20 ELSE 0 END
      + CASE WHEN event_type = 'file_transfer' AND file_type IN ('exe', 'dll', 'ps1', 'bat', 'vbs') THEN 40 ELSE 0 END
      + CASE
          WHEN REGEXP_CONTAINS(command_line, r'(?i)(powershell -enc|IEX|DownloadString|mimikatz|payload)') THEN 100
          WHEN REGEXP_CONTAINS(command_line, r'^(ipconfig|ping|ls -la|df -h|hostname)') THEN 0
          WHEN command_line IS NOT NULL THEN 10
          ELSE 0
        END
    )
  EOF
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
    REGEXP_CONTAINS(network_domain, r'(?i)(\.ru$|\.xyz$|bad-domain|payload-downloader|c2-server)')
  EOF
}

# 4. adk_threat_assessment Table
resource "google_bigquery_table" "adk_threat_assessment" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "adk_threat_assessment"
  description         = "Stores the final output and reasoning from the ADK agent workflow."
  deletion_protection = false

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

# 4. soc_tickets Table
resource "google_bigquery_table" "soc_tickets" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "soc_tickets"
  description         = "Dedicated store for tickets passed to the SOC ticketing system."
  deletion_protection = false

  schema = jsonencode([
    { name = "ticket_id", type = "STRING", mode = "REQUIRED" },
    { name = "created_at", type = "STRING", mode = "REQUIRED" },
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
    { name = "adjudicated_at", type = "STRING", mode = "NULLABLE" }
  ])
}

# 5. agent_events Table (for BigQuery Agent Analytics Plugin)
resource "google_bigquery_table" "agent_events" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "agent_events"
  description         = "Stores tracing and execution events for ADK agents via BigQueryAgentAnalyticsPlugin."
  deletion_protection = false

  time_partitioning {
    type = "DAY"
  }
}

# 6. BigQuery Cloud Resource Connection for Object Tables
resource "google_bigquery_connection" "vertex_ai_connection" {
  project       = var.project_id
  connection_id = "continuous-query-vertex-ai-connection"
  location      = var.bigquery_location
  friendly_name = "Vertex AI & Cloud Storage Connection"
  description   = "Enables BigQuery object tables and ML remote models."

  cloud_resource {}

  depends_on = [google_project_service.required]
}

# Grant Connection SA permissions to read Cloud Storage and invoke Vertex AI
resource "google_project_iam_member" "connection_vertex_ai_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_bigquery_connection.vertex_ai_connection.cloud_resource[0].service_account_id}"
}

resource "google_storage_bucket_iam_member" "connection_storage_viewer" {
  bucket = google_storage_bucket.screenshots.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_bigquery_connection.vertex_ai_connection.cloud_resource[0].service_account_id}"
}

# 7. BigQuery View for User Screenshots
resource "google_bigquery_table" "user_screenshots_view" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.cyber_dataset.dataset_id
  table_id            = "user_screenshots_view"
  description         = "View linking user_id to screenshot GCS URI in cymbal-cyber-screenshots bucket."
  deletion_protection = false

  view {
    query          = <<-SQL
      SELECT
        REGEXP_EXTRACT(uri, r'([^/]+)\.png$') AS user_id,
        uri AS gcs_uri
      FROM (
        SELECT 'gs://${google_storage_bucket.screenshots.name}/' || user_id || '.png' AS uri
        FROM UNNEST([
          'j.doe', 'a.smith', 'm.jones', 'svc_backup', 'svc_monitoring', 'admin', 'guest', 'r.patel',
          's.chen', 'e.williams', 'k.brown', 'd.davis', 't.miller', 'c.wilson', 'b.moore', 'l.taylor',
          'o.anderson', 'p.thomas', 'j.jackson', 'h.white', 'v.martin', 'n.thompson', 'g.harris', 'u.lewis'
        ]) AS user_id
      )
    SQL
    use_legacy_sql = false
  }

  depends_on = [google_bigquery_dataset.cyber_dataset, google_storage_bucket.screenshots]
}

