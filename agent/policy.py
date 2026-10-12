"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


_PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"
_CLASSIFICATIONS = frozenset({"public", "internal", "restricted"})


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    """Evaluate the mandatory data rule and the simulated OBO grant."""
    if context.data_classification not in _CLASSIFICATIONS:
        return False, f"unknown data classification: {context.data_classification!r}"

    # This invariant is deliberately evaluated before OBO fields: even a
    # fully-authorized principal may not combine restricted data and egress.
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "restricted data cannot be used by an egress-enabled tool call"

    if context.delegation_depth < 0:
        return False, "delegation_depth cannot be negative"
    if not context.agent_owner.strip():
        return False, "agent_owner is required"

    try:
        principals = json.loads(_PRINCIPALS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"principal registry unavailable: {type(exc).__name__}"

    principal = principals.get(context.principal_id)
    if principal is None:
        return False, f"unknown principal: {context.principal_id!r}"
    if not context.requested_tool:
        return False, "requested_tool is required"

    allowed_tools = set(principal.get("allowed_tools", ()))
    if context.requested_tool not in allowed_tools:
        return False, (
            f"principal {context.principal_id!r} is not allowed to use "
            f"{context.requested_tool!r}"
        )
    if context.requested_tool not in set(context.agent_scopes):
        return False, f"agent scope does not include {context.requested_tool!r}"
    if context.delegation_depth > 0 and context.requested_tool not in set(context.parent_scopes):
        return False, f"parent scope does not include {context.requested_tool!r}"

    purposes = set(principal.get("purposes", ()))
    if context.request_purpose not in purposes:
        return False, (
            f"purpose {context.request_purpose!r} is not allowed for principal "
            f"{context.principal_id!r}"
        )

    if not context.expires_at:
        return False, "expires_at is required"
    try:
        expires_at = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
    except ValueError:
        return False, f"expires_at is not valid ISO-8601 UTC: {context.expires_at!r}"
    if expires_at.tzinfo is None or expires_at.utcoffset() is None:
        return False, "expires_at must include a UTC offset"
    if expires_at.utcoffset() != timedelta(0):
        return False, "expires_at must be expressed in UTC"
    if expires_at.astimezone(timezone.utc) <= datetime.now(timezone.utc):
        return False, f"authorization expired at {context.expires_at}"

    return True, (
        f"principal {context.principal_id!r} may use {context.requested_tool!r} "
        f"for purpose {context.request_purpose!r} within effective scopes"
    )
