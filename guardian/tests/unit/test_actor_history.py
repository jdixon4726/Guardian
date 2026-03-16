"""
Unit tests for the Actor History Store (Phase 2).

Tests cover:
  - Recording actions and retrieving profiles
  - Trust level computation (new actors, clean history, block-heavy history)
  - Velocity tracking (actions per hour, per day)
  - Privilege escalation counting
"""

from datetime import datetime, timedelta, timezone

import pytest

from guardian.history.store import ActorHistoryStore, ActorProfile


@pytest.fixture
def store():
    s = ActorHistoryStore(":memory:")
    yield s
    s.close()


# ── Basic recording and profile ──────────────────────────────────────────────

class TestRecordAndProfile:
    def test_empty_profile(self, store: ActorHistoryStore):
        profile = store.get_profile("unknown-actor")
        assert profile.total_actions == 0
        assert profile.trust_level == 0.5
        assert profile.actions_last_hour == 0

    def test_single_action_recorded(self, store: ActorHistoryStore):
        now = datetime.now(timezone.utc)
        store.record("bot-a", "modify_firewall_rule", "sg-123", "allow", 0.3,
                      timestamp=now)
        profile = store.get_profile("bot-a", at=now)
        assert profile.total_actions == 1
        assert profile.total_allows == 1
        assert profile.total_blocks == 0

    def test_multiple_decisions_counted(self, store: ActorHistoryStore):
        now = datetime.now(timezone.utc)
        store.record("bot-b", "action1", "asset1", "allow", 0.2, timestamp=now)
        store.record("bot-b", "action2", "asset1", "block", 0.9, timestamp=now)
        store.record("bot-b", "action3", "asset1", "require_review", 0.6, timestamp=now)
        store.record("bot-b", "action4", "asset1", "allow_with_logging", 0.4, timestamp=now)

        profile = store.get_profile("bot-b", at=now)
        assert profile.total_actions == 4
        assert profile.total_allows == 2  # allow + allow_with_logging
        assert profile.total_blocks == 1
        assert profile.total_reviews == 1


# ── Trust level ──────────────────────────────────────────────────────────────

class TestTrustLevel:
    def test_new_actor_starts_at_neutral(self, store: ActorHistoryStore):
        profile = store.get_profile("new-actor")
        assert profile.trust_level == 0.5

    def test_few_actions_capped_at_half(self, store: ActorHistoryStore):
        """Actors with fewer than 10 actions cannot exceed 0.5 trust."""
        now = datetime.now(timezone.utc)
        for i in range(5):
            store.record("young-bot", f"action{i}", "asset", "allow", 0.2,
                          timestamp=now)
        profile = store.get_profile("young-bot", at=now)
        assert profile.trust_level <= 0.5

    def test_clean_history_builds_trust(self, store: ActorHistoryStore):
        """Many clean allows should push trust above 0.5."""
        now = datetime.now(timezone.utc)
        for i in range(30):
            store.record("good-bot", f"action{i % 3}", "asset", "allow", 0.2,
                          timestamp=now - timedelta(hours=i))
        profile = store.get_profile("good-bot", at=now)
        assert profile.trust_level > 0.5

    def test_blocks_degrade_trust(self, store: ActorHistoryStore):
        """Blocks should push trust below 0.5."""
        now = datetime.now(timezone.utc)
        for i in range(15):
            store.record("bad-bot", f"action{i}", "asset", "block", 0.9,
                          timestamp=now - timedelta(hours=i))
        profile = store.get_profile("bad-bot", at=now)
        assert profile.trust_level < 0.5

    def test_trust_floor_is_zero(self, store: ActorHistoryStore):
        """Trust level should never go below 0.0."""
        now = datetime.now(timezone.utc)
        for i in range(50):
            store.record("worst-bot", f"action{i}", "asset", "block", 1.0,
                          timestamp=now - timedelta(hours=i))
        profile = store.get_profile("worst-bot", at=now)
        assert profile.trust_level >= 0.0

    def test_trust_ceiling_is_one(self, store: ActorHistoryStore):
        """Trust level should never exceed 1.0."""
        now = datetime.now(timezone.utc)
        for i in range(500):
            store.record("best-bot", f"action{i % 3}", "asset", "allow", 0.1,
                          timestamp=now - timedelta(minutes=i))
        profile = store.get_profile("best-bot", at=now)
        assert profile.trust_level <= 1.0


# ── Velocity tracking ────────────────────────────────────────────────────────

class TestVelocity:
    def test_velocity_counts_recent_actions(self, store: ActorHistoryStore):
        now = datetime.now(timezone.utc)
        # 5 actions in the last 30 minutes
        for i in range(5):
            store.record("fast-bot", "action", "asset", "allow", 0.2,
                          timestamp=now - timedelta(minutes=i * 5))
        # 3 actions 12 hours ago
        for i in range(3):
            store.record("fast-bot", "action", "asset", "allow", 0.2,
                          timestamp=now - timedelta(hours=12, minutes=i))

        profile = store.get_profile("fast-bot", at=now)
        assert profile.actions_last_hour == 5
        assert profile.actions_last_day == 8

    def test_velocity_excludes_old_actions(self, store: ActorHistoryStore):
        now = datetime.now(timezone.utc)
        # All actions 3 days ago
        for i in range(10):
            store.record("old-bot", "action", "asset", "allow", 0.2,
                          timestamp=now - timedelta(days=3))

        profile = store.get_profile("old-bot", at=now)
        assert profile.actions_last_hour == 0
        assert profile.actions_last_day == 0

    def test_get_velocity_method(self, store: ActorHistoryStore):
        now = datetime.now(timezone.utc)
        store.record("v-bot", "action", "asset", "allow", 0.2,
                      timestamp=now - timedelta(minutes=10))
        store.record("v-bot", "action", "asset", "allow", 0.2,
                      timestamp=now - timedelta(hours=5))

        hourly, daily = store.get_velocity("v-bot", at=now)
        assert hourly == 1
        assert daily == 2


# ── Privilege escalations ────────────────────────────────────────────────────

class TestPrivilegeEscalations:
    def test_counts_privilege_actions(self, store: ActorHistoryStore):
        now = datetime.now(timezone.utc)
        store.record("esc-bot", "escalate_privileges", "role-1", "require_review",
                      0.7, timestamp=now)
        store.record("esc-bot", "modify_firewall_rule", "sg-1", "allow", 0.3,
                      timestamp=now)
        store.record("esc-bot", "escalate_privileges", "role-2", "block", 0.9,
                      timestamp=now)

        profile = store.get_profile("esc-bot", at=now)
        assert profile.prior_privilege_escalations == 2

    def test_no_privilege_actions(self, store: ActorHistoryStore):
        now = datetime.now(timezone.utc)
        store.record("safe-bot", "modify_firewall_rule", "sg-1", "allow", 0.3,
                      timestamp=now)
        profile = store.get_profile("safe-bot", at=now)
        assert profile.prior_privilege_escalations == 0


# ── Top actions ──────────────────────────────────────────────────────────────

class TestTopActions:
    def test_top_actions_ranked(self, store: ActorHistoryStore):
        now = datetime.now(timezone.utc)
        for _ in range(5):
            store.record("bot", "modify_firewall_rule", "sg", "allow", 0.3,
                          timestamp=now)
        for _ in range(3):
            store.record("bot", "restart_service", "svc", "allow", 0.2,
                          timestamp=now)
        store.record("bot", "delete_resource", "res", "block", 0.9,
                      timestamp=now)

        profile = store.get_profile("bot", at=now)
        actions = list(profile.top_actions.keys())
        assert actions[0] == "modify_firewall_rule"
        assert profile.top_actions["modify_firewall_rule"] == 5
