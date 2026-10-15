"""
The raw telemetry data contract (terraform/schemas/raw_security_event.proto).

Pub/Sub validates every message on cymbal_cyber_raw_logs against the schema, and the
BigQuery subscriptions write the same JSON into user_access_events and network_events.
These tests keep the three in step: the proto, the table schemas in bigquery.tf and
what the generator publishes. Messages are checked with protobuf's own JSON parser,
which is the check Pub/Sub applies at publish time.
"""

import json
import re
from pathlib import Path

import pytest
from google.protobuf import descriptor_pb2, descriptor_pool, json_format
from google.protobuf.message_factory import GetMessageClass

from src.demo.data_generator.log_generator import SyntheticLogEngine
from src.demo.data_generator.sinks import to_bq_subscription_row

TERRAFORM = Path(__file__).resolve().parents[2] / "terraform"
PROTO = (TERRAFORM / "schemas" / "raw_security_event.proto").read_text()
BIGQUERY_TF = (TERRAFORM / "bigquery.tf").read_text()

_FIELD = re.compile(r"^\s*(required|optional)\s+(\w+)\s+(\w+)\s*=\s*(\d+);", re.M)
PROTO_FIELDS = {
    name: (label, ptype, int(num)) for label, ptype, name, num in _FIELD.findall(PROTO)
}
BQ_TYPE_FOR = {"int64": {"INT64", "TIMESTAMP"}, "string": {"STRING"}}


def _table_columns(table_id: str) -> dict[str, tuple[str, str]]:
    block = re.search(
        rf'table_id\s*=\s*"{table_id}".*?schema = jsonencode\(\[(.*?)\]\)',
        BIGQUERY_TF,
        re.DOTALL,
    )
    assert block, f"{table_id} schema not found"
    return {
        name: (bq_type, mode)
        for name, bq_type, mode in re.findall(
            r'name = "(\w+)", type = "(\w+)", mode = "(\w+)"', block.group(1)
        )
    }


def _message_class():
    file_proto = descriptor_pb2.FileDescriptorProto(
        name="raw_security_event.proto", syntax="proto2"
    )
    message = file_proto.message_type.add(name="RawSecurityEvent")
    types = {
        "int64": descriptor_pb2.FieldDescriptorProto.TYPE_INT64,
        "string": descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
    }
    labels = {
        "required": descriptor_pb2.FieldDescriptorProto.LABEL_REQUIRED,
        "optional": descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL,
    }
    for name, (label, ptype, number) in PROTO_FIELDS.items():
        message.field.add(
            name=name, number=number, type=types[ptype], label=labels[label]
        )
    pool = descriptor_pool.DescriptorPool()
    pool.Add(file_proto)
    return GetMessageClass(pool.FindMessageTypeByName("RawSecurityEvent"))


RawSecurityEvent = _message_class()


def _parse(message: dict) -> None:
    """Raises if Pub/Sub would reject the message (proto2 JSON parse + required check)."""
    parsed = json_format.Parse(json.dumps(message), RawSecurityEvent())
    if not parsed.IsInitialized():
        raise json_format.ParseError(
            f"missing required: {parsed.FindInitializationErrors()}"
        )


@pytest.mark.parametrize("table_id", ["user_access_events", "network_events"])
def test_every_table_column_is_in_the_contract_with_a_compatible_type(table_id):
    for column, (bq_type, mode) in _table_columns(table_id).items():
        assert column in PROTO_FIELDS, f"{table_id}.{column} missing from the proto"
        label, ptype, _ = PROTO_FIELDS[column]
        assert bq_type in BQ_TYPE_FOR[ptype], f"{column}: {ptype} vs {bq_type}"
        if label == "required":
            assert mode == "REQUIRED", f"{column} is required in the proto only"


def test_every_contract_field_lands_in_a_table():
    columns = set(_table_columns("user_access_events")) | set(
        _table_columns("network_events")
    )
    assert set(PROTO_FIELDS) == columns


def test_generated_events_satisfy_the_contract():
    engine = SyntheticLogEngine(project_id="contract-test")
    access, network = engine.generate_benign_batch(100)
    for threat in ("malicious", "injection", "false_positive"):
        a, n = engine.inject_threat(threat_type=threat, user_id="u.lewis")
        access += a
        network += n
    for event in access + network:
        _parse(to_bq_subscription_row(event))


@pytest.mark.parametrize(
    "bad",
    [
        {"event_type": "login_success", "user_id": "u.lewis"},  # no event_timestamp
        {"event_timestamp": "yesterday", "event_type": "dns_query"},  # wrong type
        {"event_timestamp": 1, "event_type": "dns_query", "new_column": "x"},  # drift
    ],
)
def test_contract_rejects_bad_messages(bad):
    with pytest.raises(json_format.ParseError):
        _parse(bad)
