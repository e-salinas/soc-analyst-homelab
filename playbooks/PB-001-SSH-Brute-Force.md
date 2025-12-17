# 📘 Playbook: PB-001

## SSH Brute Force Detection & Triage

| Field | Value |
|-------|-------|
| **Playbook ID** | PB-001 |
| **Version** | 1.0 |
| **Last Updated** | December 6, 2025 |
| **Author** | Esteban |
| **Threat Type** | SSH Brute Force / Credential Stuffing |
| **Severity** | 🔴 HIGH |
| **MITRE ATT&CK** | [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) |

---

## Trigger

Execute this playbook when you see these alerts in Wazuh SIEM:

| Rule ID | Description | Level |
|---------|-------------|-------|
| 5758 | Maximum authentication attempts exceeded | 8 |
| 5710 | Attempt to login using a non-existent user | 5 |
| 5720 | Multiple authentication failures | 10 |
| 2502 | User missed the password more than one time | 10 |

---

## Step 1: Alert Triage

**Quick Assessment:**

| Alert Volume | Likely Cause |
|--------------|--------------|
| 1-5 alerts | User typo / forgot password |
| 10-50 alerts | Possible attack or lockout |
| 50+ alerts | Likely automated attack |

---

## Step 2: Gather Key Information

Click on an alert and document these fields:

| Field | Where to Find | Your Notes |
|-------|---------------|------------|
| **Source IP** | `data.srcip` | _______________ |
| **Target System** | `agent.name` | _______________ |
| **Target Username** | `data.dstuser` | _______________ |
| **Timestamp** | `timestamp` | _______________ |
| **Rule ID** | `rule.id` | _______________ |
| **Alert Count** | Total hits | _______________ |

**Take screenshots of:**
- Alert overview (showing total count)
- Alert details (expanded view with source IP)

---

## Step 3: Check for Successful Login

Search for successful authentication from the same source IP:

```
data.srcip: [ATTACKER_IP] AND rule.id: 5715
```

| Result | Action |
|--------|--------|
| **No successful login** | Continue to Step 4 |
| **Successful login found** | **ESCALATE IMMEDIATELY** |

---

## Step 4: Classification Decision

Based on your investigation, classify the alert:

### True Positive Indicators
- High volume of alerts (50+)
- Rapid attempts (multiple per second)
- Common usernames targeted (admin, root, test, user)
- Single source IP with many attempts
- Pattern indicates automated tool

### False Positive Indicators
- Low volume (1-5 alerts)
- Known user reported login issues
- Help desk ticket matches timeframe
- Legitimate service account activity

IF True Positive → Block attack IP at firewall

IF False Positive → Document and close

---

## Step 5: Documentation

Before escalating or closing, ensure you have:

- [ ] Screenshots of alerts saved
- [ ] Source IP documented
- [ ] Target system identified
- [ ] Alert count recorded
- [ ] Successful login check completed
- [ ] Classification decision documented

---

## Quick Reference

### Wazuh Filters

```
# SSH brute force alerts
rule.id: (5758 OR 5710 OR 5720 OR 2502)

# Filter by source IP
data.srcip: 10.0.0.34

# Filter by target system
agent.name: ubuntu-desktop

# Check for successful login (IMPORTANT)
rule.id: 5715
```

### Key Fields

| Field | Description |
|-------|-------------|
| `data.srcip` | Attacker IP address |
| `agent.name` | Target system name |
| `data.dstuser` | Username being targeted |
| `rule.id` | Detection rule that fired |
| `rule.description` | What the rule detected |
| `timestamp` | When the event occurred |

---

## References

- [MITRE ATT&CK T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Wazuh Documentation](https://documentation.wazuh.com/)

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Dec 6, 2025 | Initial playbook |

---

*This playbook reflects Tier 1 SOC Analyst responsibilities for SSH brute force detection and triage.*
