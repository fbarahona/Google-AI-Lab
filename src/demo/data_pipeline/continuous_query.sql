/* =================================================================================
 * Cymbal Cyber - BigQuery Continuous Query for Real-Time Threat Correlation
 * Target Project: <PROJECT_ID>
 * Target Dataset: Cymbal_Cyber
 * Target Pub/Sub Topic: cymbal_cyber_alerts
 * =================================================================================
 */

EXPORT DATA
OPTIONS (
  format = CLOUD_PUBSUB,
  uri = "https://pubsub.googleapis.com/projects/<PROJECT_ID>/topics/cymbal_cyber_alerts"
)
AS (
  /* CTE 1: Correlate Access and Network Events using streaming APPENDS read */
  WITH CorrelatedEventScores AS (
    SELECT
      network._CHANGE_TIMESTAMP AS bq_changed_ts,
      access.user_id,
      access.device_id,
      access.source_ip,
      access.user_agent,
      network.event_type,
      network.permission_level_requested,
      network.file_type,
      network.command_line,
      network.network_domain,
      /* Threat Scoring Logic */
      (
        CASE
          WHEN network.event_type = 'policy_violation' THEN 50
          WHEN network.event_type = 'dns_query' AND REGEXP_CONTAINS(network.network_domain, r'(\.ru|\.xyz|\.org|bad-domain|payload-downloader|c2-server)') THEN 60
          ELSE 0
        END
        + CASE WHEN network.permission_level_requested IN ('root', 'admin') THEN 35 ELSE 0 END
        + CASE WHEN REGEXP_CONTAINS(access.user_agent, r'^(python-requests|curl|Go-http-client)') THEN 20 ELSE 0 END
        + CASE WHEN network.event_type = 'file_transfer' AND network.file_type IN ('exe', 'dll', 'ps1', 'bat', 'vbs') THEN 40 ELSE 0 END
        + CASE
            WHEN REGEXP_CONTAINS(network.command_line, r'(?i)(powershell -enc|IEX|DownloadString|mimikatz|payload)') THEN 100
            WHEN REGEXP_CONTAINS(network.command_line, r'^(ipconfig|ping|ls -la|df -h|hostname)') THEN 0
            WHEN network.command_line IS NOT NULL THEN 10
            ELSE 0
          END
      ) AS event_score
    FROM
      APPENDS(TABLE `Cymbal_Cyber.user_access_events`, CURRENT_TIMESTAMP() - INTERVAL 10 MINUTE) AS access
    INNER JOIN
      APPENDS(TABLE `Cymbal_Cyber.network_events`, CURRENT_TIMESTAMP() - INTERVAL 10 MINUTE) AS network
      ON access.assigned_internal_ip = network.source_ip
    WHERE
      access.event_type = 'login_success'
      AND network._CHANGE_TIMESTAMP BETWEEN TIMESTAMP_SUB(access._CHANGE_TIMESTAMP, INTERVAL 5 MINUTE) AND TIMESTAMP_ADD(access._CHANGE_TIMESTAMP, INTERVAL 60 MINUTE)
  ),

  /* CTE 2: Aggregate Correlated Events into 2-Minute Tumbling Windows */
  UserAggregates AS (
    SELECT
      window_end,
      user_id,
      ANY_VALUE(device_id) AS device_id,
      ANY_VALUE(source_ip) AS source_ip,
      SUM(event_score) AS total_2_min_threat_score,
      MAX(event_score) AS max_event_score,
      ROUND(AVG(event_score), 2) AS avg_event_score,
      COUNTIF(permission_level_requested IN ('root', 'admin')) AS high_privilege_request_count,
      COUNTIF(REGEXP_CONTAINS(user_agent, r'^(python-requests|curl|Go-http-client)')) AS suspicious_user_agent_count,
      COUNTIF(file_type IN ('exe', 'dll', 'ps1', 'bat', 'vbs')) AS risky_file_transfer_count,
      COUNTIF(REGEXP_CONTAINS(command_line, r'(?i)(powershell -enc|IEX|DownloadString|mimikatz|payload)')) AS malicious_command_count,
      COUNTIF(REGEXP_CONTAINS(network_domain, r'(\.ru|\.xyz|\.org|bad-domain|payload-downloader|c2-server)')) AS malicious_dns_count
    FROM
      TUMBLE(TABLE CorrelatedEventScores, "bq_changed_ts", INTERVAL 2 MINUTE)
    GROUP BY
      window_end,
      user_id
  )

/* Publish correlated alerts with score >= 100 to Pub/Sub */
SELECT
  TO_JSON_STRING(
    STRUCT(
      window_end,
      user_id,
      device_id,
      source_ip,
      total_2_min_threat_score,
      max_event_score,
      avg_event_score,
      high_privilege_request_count,
      suspicious_user_agent_count,
      risky_file_transfer_count,
      malicious_command_count,
      malicious_dns_count
    )
  ) AS data
FROM
  UserAggregates
WHERE
  total_2_min_threat_score >= 100
);

