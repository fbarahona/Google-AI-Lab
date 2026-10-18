# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
In-memory dedup of Pub/Sub deliveries (at-least-once): messages in flight and
recently completed, with a TTL and a size cap so the tables cannot grow unbounded.
The durable check is alerts.status in BigQuery (alert_status.py).
"""

import os
import time
from collections import OrderedDict

MAX_DEDUP_CACHE_SIZE = int(os.getenv("MAX_DEDUP_CACHE_SIZE", "1000"))
_IN_PROGRESS_MESSAGES: OrderedDict[str, float] = OrderedDict()
_COMPLETED_MESSAGES: OrderedDict[str, float] = OrderedDict()
_DEDUP_TTL_SECONDS = 900.0  # 15 minutes deduplication window


def _cleanup_expired_messages():
    """Removes expired entries from memory dedup tables and enforces maximum capacity."""
    now = time.time()
    for store in (_IN_PROGRESS_MESSAGES, _COMPLETED_MESSAGES):
        expired = [k for k, ts in store.items() if now - ts > _DEDUP_TTL_SECONDS]
        for k in expired:
            store.pop(k, None)
        while len(store) > MAX_DEDUP_CACHE_SIZE:
            store.popitem(last=False)


def _record_completed_message(message_id: str):
    """Records completed message, evicting expired entries and enforcing capacity ceiling."""
    _cleanup_expired_messages()
    _COMPLETED_MESSAGES[message_id] = time.time()
    _COMPLETED_MESSAGES.move_to_end(message_id)
    while len(_COMPLETED_MESSAGES) > MAX_DEDUP_CACHE_SIZE:
        _COMPLETED_MESSAGES.popitem(last=False)


def _record_in_progress_message(message_id: str):
    """Records in-progress message, evicting expired entries and enforcing capacity ceiling."""
    _cleanup_expired_messages()
    _IN_PROGRESS_MESSAGES[message_id] = time.time()
    _IN_PROGRESS_MESSAGES.move_to_end(message_id)
    while len(_IN_PROGRESS_MESSAGES) > MAX_DEDUP_CACHE_SIZE:
        _IN_PROGRESS_MESSAGES.popitem(last=False)
