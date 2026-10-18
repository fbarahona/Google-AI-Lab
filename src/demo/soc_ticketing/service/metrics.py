"""
Dashboard metrics from BigQuery: summary KPIs, ticket breakdowns, log and threat
trends, threat origins. Simulated tickets are left out of every figure.
"""

from typing import Any

from src.demo.soc_ticketing.models import AUTO_CLOSED_FP_DECISION, SIMULATED_DECISION
from src.demo.soc_ticketing.service.schema import logger


class DashboardMetricsMixin:
    """Dashboard KPIs of SocTicketingService."""

    def _build_time_clauses(self, time_range: str) -> tuple[str, str, str, str]:
        """
        Builds WHERE clauses for each table based on the selected time range.
        Returns: (access_clause, net_clause, alert_clause, ticket_clause)
        """
        interval_map = {
            "Last 24 Hours": ("INTERVAL 24 HOUR", 1),
            "Last 7 Days": ("INTERVAL 7 DAY", 7),
            "Last 30 Days": ("INTERVAL 30 DAY", 30),
            "Last 90 Days": ("INTERVAL 90 DAY", 90),
        }
        if time_range not in interval_map:
            return ("", "", "", "")

        interval_sql, days = interval_map[time_range]
        access_clause = (
            f"WHERE DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL {days} DAY) "
            f"AND event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), {interval_sql})"
        )
        net_clause = (
            f"WHERE DATE(event_timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL {days} DAY) "
            f"AND event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), {interval_sql})"
        )
        alert_clause = (
            f"WHERE DATE(window_end) >= DATE_SUB(CURRENT_DATE(), INTERVAL {days} DAY) "
            f"AND window_end >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), {interval_sql})"
        )
        ticket_clause = (
            f"WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), {interval_sql})"
        )
        return (access_clause, net_clause, alert_clause, ticket_clause)

    def fetch_dashboard_metrics(self, time_range: str = "All Time") -> dict[str, Any]:
        """
        Dynamically calculates all SOC dashboard metrics directly from BigQuery tables.
        Provides clean fallback / zero counts when tables are empty.
        Reads soc_tickets_current so metrics always reflect the latest state,
        and leaves out simulated tickets written by the console's demo controls.
        """
        metrics: dict[str, Any] = {
            "monitored_devices": 0,
            "monitored_endpoints": 0,
            "monitored_users": 0,
            "processed_logs": 0,
            "security_events": 0,
            "triaged_alerts": 0,
            "escalated_alerts": 0,
            "auto_closed_alerts": 0,
            "alerts_by_severity": [],
            "alerts_by_status": [],
            "alerts_by_sla": [],
            "alerts_by_category": [],
            "log_rate_trend": [],
            "log_breakdown": [],
            "threat_trend": [],
            "threat_points": [],
        }

        if self.bq_client is None:
            new_t = [
                t
                for t in self.fetch_new_tickets()
                if t.get("agent_decision") != SIMULATED_DECISION
            ]
            hist_t = [
                t
                for t in self.fetch_historic_tickets()
                if t.get("agent_decision") != SIMULATED_DECISION
            ]
            metrics["escalated_alerts"] = len(new_t)
            metrics["triaged_alerts"] = len(hist_t)
            metrics["auto_closed_alerts"] = sum(
                1 for t in hist_t if t.get("agent_decision") == AUTO_CLOSED_FP_DECISION
            )
            return metrics

        access_where, net_where, alert_where, ticket_where = self._build_time_clauses(
            time_range
        )

        tickets = f"`{self._current_tickets}`"
        ticket_filter = (
            f"{ticket_where + ' AND' if ticket_where else 'WHERE'} NOT is_simulated"
        )

        # 1. Summary KPIs
        try:
            summary_sql = f"""
            WITH access_stats AS (
              SELECT
                COUNT(*) AS total_access_logs,
                COUNT(DISTINCT user_id) AS distinct_users,
                COUNT(DISTINCT device_id) AS distinct_devices,
                COUNT(DISTINCT assigned_internal_ip) AS distinct_endpoints
              FROM `{self.project_id}.{self.dataset_id}.user_access_events`
              {access_where}
            ),
            network_stats AS (
              SELECT
                COUNT(*) AS total_net_logs
              FROM `{self.project_id}.{self.dataset_id}.network_events`
              {net_where}
            ),
            alert_stats AS (
              SELECT
                COUNT(*) AS total_security_events
              FROM `{self.project_id}.{self.dataset_id}.alerts`
              {alert_where}
            ),
            ticket_stats AS (
              SELECT
                COUNT(*) AS total_tickets,
                COUNTIF(status = 'RESOLVED' OR is_adjudicated) AS triaged_alerts,
                COUNTIF(is_pending) AS escalated_alerts,
                COUNTIF(is_auto_closed) AS auto_closed_alerts
              FROM {tickets}
              {ticket_filter}
            )
            SELECT *
            FROM access_stats
            CROSS JOIN network_stats
            CROSS JOIN alert_stats
            CROSS JOIN ticket_stats;
            """
            rows = list(self.bq_client.query(summary_sql).result())
            if rows:
                r = rows[0]
                total_access = r.get("total_access_logs") or 0
                total_net = r.get("total_net_logs") or 0
                metrics["processed_logs"] = total_access + total_net
                metrics["monitored_users"] = r.get("distinct_users") or 0
                metrics["monitored_devices"] = r.get("distinct_devices") or 0
                metrics["monitored_endpoints"] = r.get("distinct_endpoints") or 0
                metrics["security_events"] = r.get("total_security_events") or 0
                metrics["triaged_alerts"] = r.get("triaged_alerts") or 0
                metrics["escalated_alerts"] = r.get("escalated_alerts") or 0
                metrics["auto_closed_alerts"] = r.get("auto_closed_alerts") or 0
        except Exception as e:
            logger.warning("Error querying summary KPIs: %s", e)

        # 2-5. Severity, status and SLA breakdowns in one pass (GROUPING SETS), plus the
        # top MITRE tactics, all from soc_tickets_current.
        try:
            breakdown_sql = f"""
            SELECT
              CASE
                WHEN GROUPING(severity) = 0 THEN 'severity'
                WHEN GROUPING(status_bucket) = 0 THEN 'status'
                ELSE 'sla'
              END AS dimension,
              COALESCE(INITCAP(severity), status_bucket, sla_bucket) AS label,
              COUNT(*) AS count
            FROM {tickets}
            {ticket_filter}
            GROUP BY GROUPING SETS ((severity), (status_bucket), (sla_bucket))
            UNION ALL
            SELECT 'category' AS dimension, label, count FROM (
              SELECT tactic AS label, COUNT(*) AS count
              FROM {tickets}, UNNEST(mitre_tactics) AS tactic
              {ticket_filter}
              GROUP BY label
              ORDER BY count DESC
              LIMIT 6
            )
            """
            keys = {
                "severity": ("alerts_by_severity", "severity"),
                "status": ("alerts_by_status", "status"),
                "sla": ("alerts_by_sla", "sla"),
                "category": ("alerts_by_category", "category"),
            }
            for row in self.bq_client.query(breakdown_sql).result():
                metric, label_key = keys[row["dimension"]]
                metrics[metric].append({label_key: row["label"], "count": row["count"]})
        except Exception as e:
            logger.warning("Error querying ticket breakdowns: %s", e)

        # 6. Log Rate Trend
        try:
            rate_sql = f"""
            SELECT
              FORMAT_DATE('%m/%d', DATE(event_timestamp)) AS date,
              COUNT(*) AS count
            FROM (
              SELECT event_timestamp FROM `{self.project_id}.{self.dataset_id}.user_access_events`
              {access_where}
              UNION ALL
              SELECT event_timestamp FROM `{self.project_id}.{self.dataset_id}.network_events`
              {net_where}
            )
            GROUP BY date
            ORDER BY date ASC
            LIMIT 7
            """
            rate_rows = [
                dict(row.items()) for row in self.bq_client.query(rate_sql).result()
            ]
            metrics["log_rate_trend"] = [
                {
                    "date": r["date"],
                    "rate": round(r["count"] / 86400.0, 2) if r.get("count") else 0.0,
                }
                for r in rate_rows
            ]
        except Exception as e:
            logger.warning("Error querying log rate trend: %s", e)

        # 7. Log Collection Breakdown
        try:
            breakdown_sql = f"""
            SELECT
              FORMAT_DATE('%m/%d', DATE(event_timestamp)) AS date,
              event_type AS type,
              COUNT(*) AS volume
            FROM (
              SELECT event_timestamp, event_type FROM `{self.project_id}.{self.dataset_id}.user_access_events`
              {access_where}
              UNION ALL
              SELECT event_timestamp, event_type FROM `{self.project_id}.{self.dataset_id}.network_events`
              {net_where}
            )
            GROUP BY date, type
            ORDER BY date ASC
            LIMIT 25
            """
            metrics["log_breakdown"] = [
                dict(row.items())
                for row in self.bq_client.query(breakdown_sql).result()
            ]
        except Exception as e:
            logger.warning("Error querying log breakdown: %s", e)

        # 8. Threat Detection Trend
        try:
            trend_sql = f"""
            SELECT
              FORMAT_DATE('%m/%d', DATE(window_end)) AS date,
              COUNT(*) AS count
            FROM `{self.project_id}.{self.dataset_id}.alerts`
            {alert_where}
            GROUP BY date
            ORDER BY date ASC
            LIMIT 7
            """
            trend_rows = [
                dict(row.items()) for row in self.bq_client.query(trend_sql).result()
            ]
            metrics["threat_trend"] = [
                {"date": r["date"], "metric": "Security Events", "count": r["count"]}
                for r in trend_rows
            ]
        except Exception as e:
            logger.warning("Error querying threat trend: %s", e)

        # 9. Geographical Threat Origins (Threat Points)
        try:
            map_sql = f"""
            SELECT
              user_id,
              source_ip,
              threat_score,
              severity,
              agent_reason
            FROM {tickets}
            {ticket_filter}
            ORDER BY created_at DESC
            LIMIT 50
            """
            map_rows = [
                dict(row.items()) for row in self.bq_client.query(map_sql).result()
            ]
            points = []
            for r in map_rows:
                ip = r.get("source_ip", "")
                geo = self._resolve_ip_geo(ip, r.get("user_id", ""))
                points.append(
                    {
                        "name": f"{r.get('user_id')} ({geo['country']})",
                        "lat": geo["lat"],
                        "lon": geo["lon"],
                        "threat": str(r.get("agent_reason", "Perceived Threat"))[:60],
                        "score": r.get("threat_score", 100),
                        "color": [244, 67, 54, 220]
                        if r.get("severity") == "CRITICAL"
                        else [255, 152, 0, 200],
                    }
                )
            metrics["threat_points"] = points
        except Exception as e:
            logger.warning("Error querying threat points: %s", e)

        return metrics

    @staticmethod
    def _resolve_ip_geo(ip: str, user_id: str) -> dict[str, Any]:
        """Maps IP or user scenario to known geographic coordinates."""
        known_geos = {
            "175.45.176.10": {
                "country": "North Korea",
                "lat": 39.0392,
                "lon": 125.7625,
            },
            "175.45.177.32": {
                "country": "North Korea",
                "lat": 39.0392,
                "lon": 125.7625,
            },
            "194.26.135.68": {"country": "Russia", "lat": 55.7558, "lon": 37.6173},
            "185.220.101.5": {"country": "Germany", "lat": 52.5200, "lon": 13.4050},
            "74.125.70.93": {
                "country": "United States",
                "lat": 37.7749,
                "lon": -122.4194,
            },
            "74.125.10.15": {
                "country": "United States",
                "lat": 40.7128,
                "lon": -74.0060,
            },
        }
        if ip in known_geos:
            return known_geos[ip]
        if "u.lewis" in user_id or "g.harris" in user_id:
            return {"country": "North Korea", "lat": 39.0392, "lon": 125.7625}
        if "r.patel" in user_id:
            return {"country": "Russia", "lat": 55.7558, "lon": 37.6173}
        if "contractor" in user_id:
            return {"country": "Germany", "lat": 52.5200, "lon": 13.4050}
        return {"country": "External Origin", "lat": 20.0, "lon": 0.0}
