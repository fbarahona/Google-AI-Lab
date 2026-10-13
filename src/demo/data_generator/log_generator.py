"""
Unified Synthetic Log Generator & Threat Injector
=================================================
Replaces legacy Colab notebooks with a modular Python CLI and programmatic tool.

Usage Examples:
  # 1. Continuous benign streaming to BigQuery:
  python -m src.demo.data_generator.log_generator --mode benign --rate 50 --destination bigquery

  # 2. Upload batch benign logs to Google Cloud Storage:
  python -m src.demo.data_generator.log_generator --mode benign --batch-size 200 --destination gcs --bucket cymbal-cyber-raw-logs_<PROJECT_ID>

  # 3. Inject an ad-hoc MALICIOUS threat scenario:
  python -m src.demo.data_generator.log_generator --mode threat --threat-type malicious --user u.lewis --destination bigquery

  # 4. Inject an ad-hoc FALSE POSITIVE threat scenario:
  python -m src.demo.data_generator.log_generator --mode threat --threat-type false_positive --user l.taylor --destination bigquery

  # 5. Stream logs to Cloud Pub/Sub:
  python -m src.demo.data_generator.log_generator --mode benign --destination pubsub --topic cymbal_cyber_raw_logs
"""

import argparse
import logging
import os
import random
import time
from datetime import UTC, datetime
from typing import Any

from .sinks import BaseSink, BigQuerySink, GoogleCloudStorageSink, LocalSink, PubSubSink
from .threat_scenarios import (
    generate_false_positive_threat_scenario,
    generate_malicious_threat_scenario,
    generate_prompt_injection_threat_scenario,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SyntheticLogEngine")

# Enterprise Personas
BENIGN_USERS = [
    "j.doe",
    "a.smith",
    "m.jones",
    "svc_backup",
    "svc_monitoring",
    "admin",
    "guest",
    "r.patel",
    "s.chen",
    "e.williams",
    "k.brown",
    "d.davis",
    "t.miller",
    "c.wilson",
    "b.moore",
    "l.taylor",
    "o.anderson",
    "p.thomas",
    "j.jackson",
    "h.white",
    "v.martin",
    "n.thompson",
]
WINDOWS_DEVICES = [
    "ws-exec-01",
    "ws-exec-02",
    "ws-hr-01",
    "ws-hr-05",
    "ws-finance-03",
    "ws-dev-10",
    "ws-dev-11",
]
MACOS_DEVICES = ["ws-exec-mac-01", "ws-dev-mac-01"]
SERVER_DEVICES = [
    "srv-db-prod-01",
    "srv-db-prod-02",
    "srv-app-prod-01",
    "srv-app-prod-02",
    "srv-web-prod-02",
    "srv-dns-int-01",
    "srv-proxy-01",
    "srv-fileshare-01",
]
WINDOWS_PROCESSES = [
    "chrome.exe",
    "outlook.exe",
    "teams.exe",
    "powershell.exe",
    "svchost.exe",
    "explorer.exe",
]
MACOS_PROCESSES = ["chrome", "terminal", "slack", "vscode"]
LINUX_PROCESSES = ["sshd", "nginx", "apache2", "cron"]

BASE_ACTIVITY_WEIGHTS = {
    "dns_query": 0.70,
    "connection_established": 0.255,
    "file_transfer": 0.04,
    "policy_violation": 0.005,
}
BENIGN_DOMAINS = [
    "google.com",
    "office365.com",
    "salesforce.com",
    "github.com",
    "internal.wiki.com",
    "google-analytics.com",
]
BENIGN_COMMANDS = ["ipconfig /all", "ping 8.8.8.8", "ls -la /home", "df -h", "hostname"]


class SyntheticLogEngine:
    """Core simulation engine for generating enterprise user and device activity."""

    def __init__(self, project_id: str | None = None, dataset_id: str = "Cymbal_Cyber"):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo")
        self.dataset_id = dataset_id
        self.user_profiles: dict[str, dict[str, Any]] = {}
        self.available_internal_ips: set[str] = set()
        self._init_state()

    def _init_state(self):
        """Initializes internal IP pool and user profiles."""
        self.available_internal_ips = {
            f"10.1.{random.randint(0, 255)}.{random.randint(2, 254)}"
            for _ in range(250)
        }
        for user in BENIGN_USERS:
            if "svc_" in user or "admin" in user:
                device = random.choice(SERVER_DEVICES)
                os_type = "Linux"
            elif random.random() < 0.2:
                device = random.choice(MACOS_DEVICES)
                os_type = "macOS"
            else:
                device = random.choice(WINDOWS_DEVICES)
                os_type = "Windows"

            self.user_profiles[user] = {
                "primary_device": device,
                "os": os_type,
                "public_ip": f"74.125.{random.randint(0, 255)}.{random.randint(0, 255)}",
                "current_internal_ip": None,
                "last_login_time": None,
            }

    def generate_single_event_pair(
        self,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Generates a realistic single stateful access or network event."""
        user = random.choice(list(self.user_profiles.keys()))
        profile = self.user_profiles[user]
        now = datetime.now(UTC)

        # Logged in -> generate network traffic or occasional logout
        if profile["current_internal_ip"]:
            if random.random() < 0.05:  # 5% chance to log out
                self.available_internal_ips.add(profile["current_internal_ip"])
                profile["current_internal_ip"] = None
                profile["last_login_time"] = None
                return None, None

            event_type = random.choices(
                list(BASE_ACTIVITY_WEIGHTS.keys()),
                weights=list(BASE_ACTIVITY_WEIGHTS.values()),
                k=1,
            )[0]

            proc_name = (
                random.choice(WINDOWS_PROCESSES)
                if profile["os"] == "Windows"
                else (
                    random.choice(MACOS_PROCESSES)
                    if profile["os"] == "macOS"
                    else random.choice(LINUX_PROCESSES)
                )
            )

            net_event = {
                "event_timestamp": now.isoformat(),
                "event_type": event_type,
                "user_id": user,
                "source_ip": profile["current_internal_ip"],
                "source_port": random.randint(1024, 65535),
                "destination_ip": f"10.100.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "destination_port": random.choice([80, 443, 53, 22, 8080]),
                "protocol": "UDP" if event_type == "dns_query" else "TCP",
                "bytes_transferred": random.randint(64, 1500000),
                "source_process_name": proc_name,
                "network_domain": random.choice(BENIGN_DOMAINS)
                if event_type == "dns_query"
                else None,
                "file_name": "archive.zip" if event_type == "file_transfer" else None,
                "file_type": "zip" if event_type == "file_transfer" else None,
                "command_line": random.choice(BENIGN_COMMANDS)
                if event_type == "policy_violation"
                else None,
                "permission_level_requested": None,
                "file_hash_sha256": None,
            }
            return None, net_event

        # Logged out -> login attempt
        else:
            if not self.available_internal_ips:
                self.available_internal_ips.add(
                    f"10.1.{random.randint(0, 255)}.{random.randint(2, 254)}"
                )

            if random.random() < 0.01:
                # 1% benign login failure
                acc_event = {
                    "event_timestamp": now.isoformat(),
                    "event_type": "login_failure",
                    "user_id": user,
                    "source_ip": profile["public_ip"],
                    "assigned_internal_ip": None,
                    "device_id": profile["primary_device"],
                    "device_os": "Windows 11"
                    if profile["os"] == "Windows"
                    else "macOS Sonoma",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
                    "application_name": "Corporate-VPN",
                }
                return acc_event, None
            else:
                new_ip = self.available_internal_ips.pop()
                profile["current_internal_ip"] = new_ip
                profile["last_login_time"] = now
                acc_event = {
                    "event_timestamp": now.isoformat(),
                    "event_type": "login_success",
                    "user_id": user,
                    "source_ip": profile["public_ip"],
                    "assigned_internal_ip": new_ip,
                    "device_id": profile["primary_device"],
                    "device_os": "Windows 11"
                    if profile["os"] == "Windows"
                    else "macOS Sonoma",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
                    "application_name": "Corporate-VPN",
                }
                return acc_event, None

    def generate_benign_batch(
        self, count: int
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Generates a batch of benign access and network events."""
        access_batch = []
        network_batch = []
        attempts = 0
        max_attempts = count * 3
        while (
            len(access_batch) + len(network_batch) < count
        ) and attempts < max_attempts:
            attempts += 1
            acc, net = self.generate_single_event_pair()
            if acc:
                access_batch.append(acc)
            if net:
                network_batch.append(net)
        return access_batch, network_batch

    def inject_threat(
        self, threat_type: str = "malicious", user_id: str | None = None
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Ad-hoc method to inject synthetic threats."""
        if threat_type == "malicious":
            target = user_id or "u.lewis"
            logger.info("Injecting MALICIOUS attack scenario targeting %s...", target)
            return generate_malicious_threat_scenario(target_user=target)
        elif threat_type == "false_positive":
            target = user_id or "l.taylor"
            logger.info(
                "Injecting BENIGN FALSE POSITIVE scenario targeting %s...", target
            )
            return generate_false_positive_threat_scenario(target_user=target)
        elif threat_type == "injection":
            target = user_id or "c.wilson"
            logger.info(
                "Injecting PROMPT INJECTION attack scenario targeting %s...", target
            )
            return generate_prompt_injection_threat_scenario(target_user=target)
        else:
            raise ValueError(
                f"Unknown threat type '{threat_type}'. Must be 'malicious', 'false_positive', or 'injection'."
            )


def create_sink(args: argparse.Namespace) -> BaseSink:
    """Factory to instantiate the appropriate sink based on CLI arguments."""
    dest = args.destination.lower()
    if dest == "gcs":
        bucket = args.bucket or f"cymbal-cyber-raw-logs_{args.project_id}"
        logger.info("Writing output to Google Cloud Storage bucket: gs://%s", bucket)
        return GoogleCloudStorageSink(bucket_name=bucket)
    elif dest == "pubsub":
        topic = args.topic or "cymbal_cyber_raw_logs"
        logger.info(
            "Publishing output to Cloud Pub/Sub: projects/%s/topics/%s",
            args.project_id,
            topic,
        )
        return PubSubSink(project_id=args.project_id, topic_id=topic)
    elif dest == "bigquery":
        logger.info(
            "Streaming output directly to BigQuery dataset: %s.%s",
            args.project_id,
            args.dataset,
        )
        return BigQuerySink(project_id=args.project_id, dataset_id=args.dataset)
    else:
        out_dir = args.output_dir or "./output_logs"
        logger.info("Writing output to local destination: %s", out_dir)
        return LocalSink(output_dir=out_dir, print_stdout=args.stdout)


def main():
    parser = argparse.ArgumentParser(
        description="Synthetic Cybersecurity Event Generator & Threat Injector"
    )
    parser.add_argument(
        "--mode",
        choices=["benign", "threat", "continuous"],
        default="benign",
        help="Operating mode: benign batch, continuous stream, or ad-hoc threat injection.",
    )
    parser.add_argument(
        "--threat-type",
        choices=["malicious", "false_positive", "injection"],
        default="malicious",
        help="Threat scenario type when mode is 'threat' (malicious, false_positive, or injection).",
    )
    parser.add_argument(
        "--user",
        type=str,
        default=None,
        help="Target user ID for threat injection (e.g. u.lewis, g.harris, l.taylor).",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=50,
        help="Target events per second for continuous streaming.",
    )
    parser.add_argument(
        "--batch-size",
        "--count",
        dest="batch_size",
        type=int,
        default=100,
        help="Number of iterations or events to generate in batch mode.",
    )
    parser.add_argument(
        "--destination",
        "--sink",
        dest="destination",
        choices=["bigquery", "gcs", "pubsub", "local"],
        default="local",
        help="Destination sink for generated logs.",
    )
    parser.add_argument(
        "--project-id",
        type=str,
        default=os.getenv("GOOGLE_CLOUD_PROJECT", "local-demo"),
        help="GCP Project ID.",
    )
    parser.add_argument(
        "--dataset", type=str, default="Cymbal_Cyber", help="BigQuery dataset name."
    )
    parser.add_argument(
        "--bucket",
        type=str,
        default=None,
        help="GCS bucket name when destination is 'gcs'.",
    )
    parser.add_argument(
        "--topic",
        type=str,
        default="cymbal_cyber_raw_logs",
        help="Pub/Sub topic ID when destination is 'pubsub'.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./output_logs",
        help="Local output directory when destination is 'local'.",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print events to stdout when destination is 'local'.",
    )

    args = parser.parse_args()
    engine = SyntheticLogEngine(project_id=args.project_id, dataset_id=args.dataset)
    sink = create_sink(args)

    if args.mode == "threat":
        access_events, network_events = engine.inject_threat(
            threat_type=args.threat_type, user_id=args.user
        )
        total = sink.write_events(access_events, network_events)
        logger.info(
            "Successfully injected %d %s events (%d access, %d network).",
            total,
            args.threat_type.upper(),
            len(access_events),
            len(network_events),
        )
        if args.destination == "pubsub":
            logger.info(
                "Ingestion Notice: BigQuery managed subscriptions commit via Storage Write API. Allow ~60s for streaming buffer commits before invoking detection jobs."
            )

    elif args.mode == "continuous":
        logger.info(
            "Starting continuous benign stream at ~%d events/sec. Press Ctrl+C to stop.",
            args.rate,
        )
        total_streamed = 0
        try:
            while True:
                start_t = time.time()
                acc, net = engine.generate_benign_batch(args.rate)
                written = sink.write_events(acc, net)
                total_streamed += written
                elapsed = time.time() - start_t
                time.sleep(max(0.0, 1.0 - elapsed))
        except KeyboardInterrupt:
            logger.info(
                "Streaming stopped by user. Total events streamed: %d", total_streamed
            )

    else:  # benign batch
        acc, net = engine.generate_benign_batch(args.batch_size)
        total = sink.write_events(acc, net)
        logger.info(
            "Successfully generated %d benign events (%d access, %d network).",
            total,
            len(acc),
            len(net),
        )


if __name__ == "__main__":
    main()
