from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / ".github" / "agent-policy.json"
HARNESS_PATH = ROOT / ".github" / "AGENT_HARNESS.md"
TEAM_PATH = ROOT / ".github" / "AGENT_TEAM.md"
CODEOWNERS_PATH = ROOT / ".github" / "CODEOWNERS"
AUTONOMOUS_SOURCE = ROOT / ".github" / "workflows" / "daily-autonomous-maintainer.md"
AUTONOMOUS_LOCK = ROOT / ".github" / "workflows" / "daily-autonomous-maintainer.lock.yml"
AGENTS_DIR = ROOT / ".github" / "agents"


def fail(message: str) -> None:
    raise SystemExit(f"agent-governance validation failed: {message}")


def require_text(text: str, needle: str, where: str) -> None:
    if needle not in text:
        fail(f"missing {needle!r} in {where}")


def main() -> None:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    harness = HARNESS_PATH.read_text(encoding="utf-8")
    team = TEAM_PATH.read_text(encoding="utf-8")
    codeowners = CODEOWNERS_PATH.read_text(encoding="utf-8")
    source = AUTONOMOUS_SOURCE.read_text(encoding="utf-8")
    lock = AUTONOMOUS_LOCK.read_text(encoding="utf-8")

    if policy.get("schema_version") != 1:
        fail("unsupported agent-policy schema version")

    daily = policy["daily_run"]
    expected_false = (
        "allow_merge",
        "allow_release",
        "allow_deploy",
        "allow_secret_mutation",
        "allow_privileged_enforcement",
        "allow_self_modification",
    )
    for key in expected_false:
        if daily.get(key) is not False:
            fail(f"{key} must remain false")

    if daily.get("max_objectives") != 1 or daily.get("max_branches") != 1:
        fail("daily autonomous scope must remain one objective / one branch")
    if daily.get("max_issues") != 1 or daily.get("max_draft_pull_requests") != 1:
        fail("daily output budget must remain one issue or one draft PR")
    if daily.get("max_changed_files", 999) > 12:
        fail("daily changed-file budget may not exceed 12")
    if daily.get("max_changed_lines", 9999) > 500:
        fail("daily changed-line budget may not exceed 500")

    harness_requirements = (
        "## Self-modification prohibition",
        "## Protected-boundary stop rule",
        "## Daily autonomous-run budget",
        "privileged_execution=false",
        "one issue **or** one draft pull request",
        "must not search for an alternate route that bypasses the boundary",
    )
    for needle in harness_requirements:
        require_text(harness, needle, str(HARNESS_PATH))

    require_text(team, ".github/AGENT_HARNESS.md", str(TEAM_PATH))
    require_text(team, "cannot merge its own pull request", str(TEAM_PATH))
    require_text(team, "ordinary repository review rather than self-modification", str(TEAM_PATH))

    for agent_file in sorted(AGENTS_DIR.glob("*.agent.md")):
        text = agent_file.read_text(encoding="utf-8")
        require_text(text, ".github/AGENT_HARNESS.md", str(agent_file))
        require_text(text, "harness", str(agent_file))

    required_permissions = policy["required_autonomous_permissions"]
    for name, value in required_permissions.items():
        require_text(source, f"  {name}: {value}", str(AUTONOMOUS_SOURCE))
    for forbidden in policy["forbidden_autonomous_permissions"]:
        if forbidden in source:
            fail(f"forbidden autonomous permission present: {forbidden}")

    source_requirements = (
        "draft: true",
        "max: 1",
        "protected-files: fallback-to-issue",
        "Never mark a draft PR as ready, approve it, or merge it.",
        "If the best task would cross one of these boundaries, create an issue",
    )
    for needle in source_requirements:
        require_text(source, needle, str(AUTONOMOUS_SOURCE))

    if len(lock) < 10_000:
        fail("compiled autonomous workflow lock file is unexpectedly small")
    require_text(lock, "daily-autonomous-maintainer", str(AUTONOMOUS_LOCK))

    protected = policy["protected_governance_paths"]
    required_codeowner_patterns = (
        "/.github/AGENT_HARNESS.md",
        "/.github/AGENT_TEAM.md",
        "/.github/agent-policy.json",
        "/.github/agents/",
        "/.github/workflows/",
        "/.github/scripts/validate_agent_governance.py",
        "/.github/copilot-instructions.md",
        "/SECURITY.md",
        "/LICENSE",
        "/GOVERNANCE.md",
    )
    for pattern in required_codeowner_patterns:
        require_text(codeowners, pattern, str(CODEOWNERS_PATH))

    boundary = policy["boundary_stop"]
    if boundary.get("fallback") != "one-issue-and-stop":
        fail("protected-boundary fallback must remain one-issue-and-stop")
    for key in ("retry_via_alternate_tool", "retry_via_alternate_credential", "retry_via_branch_trick"):
        if boundary.get(key) is not False:
            fail(f"{key} must remain false")

    print(
        "Agent governance validated: "
        f"{len(list(AGENTS_DIR.glob('*.agent.md')))} agents, "
        f"{len(protected)} protected path classes, bounded autonomous permissions intact."
    )


if __name__ == "__main__":
    main()
