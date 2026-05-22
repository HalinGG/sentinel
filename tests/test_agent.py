"""Test the autonomous SENTINEL agent."""
import pytest
from agent import SentinelAgent


class TestSentinelAgent:
    """Tests for the autonomous security agent."""

    def test_agent_initializes(self):
        """Should initialize with MCP tools."""
        agent = SentinelAgent()
        assert agent is not None
        assert agent.mcp_tools is not None

    def test_agent_triages_malicious_finding(self):
        """Should quarantine a user with suspicious activity."""
        agent = SentinelAgent()
        finding = {
            "finding_type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
            "severity": 8.0,
            "principal_id": "compromised-user",
            "source_ip": "203.0.113.42",
            "event_name": "PutBucketEncryption",
            "timestamp": "2026-05-22T04:59:00Z"
        }
        decision = agent.triage_finding(finding)
        
        assert isinstance(decision, dict)
        assert "principal_id" in decision
        assert "action" in decision
        assert "reasoning" in decision
        assert "threat_intel" in decision
        assert "cloudtrail_events" in decision
        assert decision["action"] == "QUARANTINE"

    def test_agent_allows_benign_finding(self):
        """Should NOT quarantine benign activity."""
        agent = SentinelAgent()
        finding = {
            "finding_type": "PrivilegeEscalation:IAMUser/MaliciousIPCaller",
            "severity": 1.0,
            "principal_id": "app-role",
            "source_ip": "10.0.0.1",
            "event_name": "GetObject",
            "timestamp": "2026-05-22T03:59:00Z"
        }
        decision = agent.triage_finding(finding)
        
        assert decision["action"] == "MONITOR"
        assert decision["principal_id"] == "app-role"

    def test_agent_decision_includes_evidence(self):
        """Decision should include all evidence used."""
        agent = SentinelAgent()
        finding = {
            "finding_type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
            "severity": 8.0,
            "principal_id": "compromised-user",
            "source_ip": "203.0.113.42",
            "event_name": "ListBuckets",
            "timestamp": "2026-05-22T03:59:00Z"
        }
        decision = agent.triage_finding(finding)
        
        # Decision must include evidence
        assert "threat_intel" in decision
        assert "cloudtrail_events" in decision
        assert "iam_policies" in decision
        assert "severity" in decision
        assert decision["severity"] == 8.0
