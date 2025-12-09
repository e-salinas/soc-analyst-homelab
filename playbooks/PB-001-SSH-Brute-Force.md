# 📘 Response Playbook: PB-001

## SSH Brute Force Attack Response

| Field | Value |
|-------|-------|
| **Playbook ID** | PB-001 |
| **Version** | 1.0 |
| **Last Updated** | December 6, 2025 |
| **Author** | Steve (SOC Analyst) |
| **Threat Type** | SSH Brute Force / Credential Stuffing |
| **Severity** | 🔴 HIGH |
| **MITRE ATT&CK** | [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/) |

---

## Objective

This playbook provides step-by-step procedures for detecting, investigating, and responding to SSH brute force attacks. The goal is to contain the threat quickly while minimizing impact to legitimate users and preserving evidence for further analysis.

---

## Trigger Conditions

Execute this playbook when you observe any of the following alerts in Wazuh SIEM:

| Rule ID | Description | Level |
|---------|-------------|-------|
| 5758 | Maximum authentication attempts exceeded | 8 |
| 5710 | Attempt to login using a non-existent user | 5 |
| 5720 | Multiple authentication failures | 10 |
| 2502 | User missed the password more than one time | 10 |

### Alert Indicators
- High volume of authentication failures (50+ in short timeframe)
- Multiple failed logins from single source IP
- Attempts against common usernames (admin, root, user, test)
- Rapid succession of attempts (multiple per second)

---

## Phase 1: Detection & Triage

**⏱️ Estimated Time: 2-5 minutes**

### Steps

- [ ] **1.1** Open Wazuh Dashboard and navigate to **Security Events** or **Discover**

- [ ] **1.2** Set time range to **Last 15-30 minutes**

- [ ] **1.3** Apply filters to isolate SSH authentication events:
  ```
  rule.id: (5758 OR 5710 OR 5720 OR 2502)
  ```

- [ ] **1.4** Identify and document:
  | Field | Where to Find | Document Here |
  |-------|---------------|---------------|
  | Source IP | `data.srcip` | _______________ |
  | Target System | `agent.name` | _______________ |
  | Target Username | `data.dstuser` | _______________ |
  | Alert Count | Total hits | _______________ |
  | Time Range | Earliest/Latest alert | _______________ |

- [ ] **1.5** Take screenshot of alert overview

- [ ] **1.6** Initial assessment:
  - [ ] Is this a single source IP or multiple?
  - [ ] Is the source IP internal or external?
  - [ ] How many alerts in what timeframe?
  - [ ] Are common usernames being targeted?

---

## Phase 2: Investigation

**⏱️ Estimated Time: 5-10 minutes**

### Steps

- [ ] **2.1** Expand alert details and review the `full_log` field for raw event data

- [ ] **2.2** Take screenshot of detailed alert view

- [ ] **2.3** Determine source IP type:
  | IP Range | Type | Implication |
  |----------|------|-------------|
  | 10.x.x.x | Internal (Private) | Possible compromised host |
  | 192.168.x.x | Internal (Private) | Possible compromised host |
  | 172.16-31.x.x | Internal (Private) | Possible compromised host |
  | Other | External (Public) | External threat actor |

- [ ] **2.4** Check for successful logins from the same source:
  ```
  data.srcip: [ATTACKER_IP] AND rule.id: 5715
  ```
  - [ ] Successful login found? → **ESCALATE IMMEDIATELY**
  - [ ] No successful login? → Continue investigation

- [ ] **2.5** Analyze attack pattern:
  | Indicator | Automated Attack | Manual Attempt |
  |-----------|------------------|----------------|
  | Speed | Multiple per second | Slow, irregular |
  | Usernames | Common names (admin, root) | Specific usernames |
  | Volume | 50+ attempts | Few attempts |
  | Pattern | Sequential passwords | Random attempts |

- [ ] **2.6** Make classification decision:
  - [ ] **TRUE POSITIVE** - Confirmed malicious attack → Proceed to Phase 3
  - [ ] **FALSE POSITIVE** - Legitimate user lockout → Document and close

---

## Phase 3: Containment

**⏱️ Estimated Time: 2-5 minutes**

> ⚠️ **IMPORTANT:** Only proceed if classified as TRUE POSITIVE

### Steps

- [ ] **3.1** Access the target system via SSH or console

- [ ] **3.2** Enable firewall (if not already enabled):
  ```bash
  sudo ufw enable
  ```

- [ ] **3.3** Block the attacker IP:
  ```bash
  sudo ufw deny from [ATTACKER_IP]
  ```
  Replace `[ATTACKER_IP]` with the actual source IP (e.g., `10.0.0.34`)

- [ ] **3.4** Verify the firewall rule:
  ```bash
  sudo ufw status numbered
  ```

- [ ] **3.5** Take screenshot of firewall status showing block rule

- [ ] **3.6** Document containment time: _______________

- [ ] **3.7** If successful authentication was detected, immediately disable the compromised account:
  ```bash
  sudo passwd -l [USERNAME]
  ```

---

## Phase 4: Eradication & Recovery

**⏱️ Estimated Time: 10-30 minutes (if compromise occurred)**

> Only required if successful authentication was detected

### Steps

- [ ] **4.1** Check for unauthorized access:
  ```bash
  # Recent login history
  last -a | head -20
  
  # Failed login attempts
  lastb | head -20
  
  # Currently logged in users
  who
  ```

- [ ] **4.2** Check for unauthorized changes:
  ```bash
  # New user accounts
  cat /etc/passwd | tail -10
  
  # Sudoers modifications
  sudo cat /etc/sudoers
  
  # Scheduled tasks
  crontab -l
  sudo crontab -l
  
  # SSH authorized keys
  ls -la ~/.ssh/
  cat ~/.ssh/authorized_keys
  ```

- [ ] **4.3** Check for suspicious processes:
  ```bash
  # Running processes
  ps aux | grep -v root | head -20
  
  # Network connections
  netstat -tulpn
  ss -tulpn
  ```

- [ ] **4.4** If compromise confirmed:
  - [ ] Reset all passwords for affected accounts
  - [ ] Remove unauthorized SSH keys
  - [ ] Remove unauthorized user accounts
  - [ ] Remove suspicious cron jobs
  - [ ] Consider system rebuild if extensive compromise

- [ ] **4.5** Restore normal operations:
  - [ ] Re-enable legitimate accounts (if disabled)
  - [ ] Verify services are running normally
  - [ ] Continue monitoring for suspicious activity

---

## Phase 5: Documentation

**⏱️ Estimated Time: 15-30 minutes**

### Required Documentation Checklist

- [ ] **5.1** Complete incident report (INC-XXX) including:
  - [ ] Incident summary
  - [ ] Timeline of events with timestamps
  - [ ] Attack details (source IP, target, method)
  - [ ] Detection details (rules triggered, alert count)
  - [ ] Response actions taken
  - [ ] Metrics (MTTD, MTTR)
  - [ ] Recommendations

- [ ] **5.2** Attach all screenshots:
  - [ ] SIEM alert overview
  - [ ] Alert details
  - [ ] Attack timeline
  - [ ] Containment evidence (firewall rules)

- [ ] **5.3** Calculate and record metrics:
  | Metric | Formula | Value |
  |--------|---------|-------|
  | MTTD | First Alert Time - Attack Start Time | _______ |
  | MTTR | Containment Time - First Alert Time | _______ |

- [ ] **5.4** File incident report in tracking system

---

## Escalation Criteria

**Escalate to Tier 2 / Incident Manager immediately if:**

| Condition | Action |
|-----------|--------|
| ✅ Successful authentication detected | Escalate + Continue containment |
| ✅ Multiple systems targeted simultaneously | Escalate + Coordinate response |
| ✅ Source is internal network | Escalate + Investigate compromised host |
| ✅ Evidence of lateral movement | Escalate + Network isolation |
| ✅ Data exfiltration indicators | Escalate + Preserve evidence |
| ✅ Attack persists after containment | Escalate + Review containment |

### Escalation Contact Template

```
SECURITY INCIDENT ESCALATION

Incident ID: INC-XXX
Severity: HIGH
Time Detected: [TIMESTAMP]

Summary: SSH brute force attack detected on [TARGET].
[Successful/Unsuccessful] authentication from [SOURCE_IP].

Immediate Actions Taken:
- [List containment actions]

Escalation Reason:
- [Reason for escalation]

Analyst: [Your Name]
Contact: [Your Contact Info]
```

---

## Post-Incident Actions

### Immediate (Within 24 hours)
- [ ] Verify containment is still effective
- [ ] Check for any related alerts
- [ ] Complete incident documentation
- [ ] Brief team on incident

### Short-term (Within 1 week)
- [ ] Implement fail2ban or similar IPS
- [ ] Review SSH configuration and hardening
- [ ] Consider disabling password authentication
- [ ] Update firewall rules if needed

### Long-term (Within 1 month)
- [ ] Conduct lessons learned review
- [ ] Update this playbook based on findings
- [ ] Implement additional detection rules
- [ ] Consider network segmentation improvements

---

## Quick Reference Commands

### Wazuh Query Filters
```
# SSH brute force alerts
rule.id: (5758 OR 5710 OR 5720 OR 2502)

# Filter by source IP
data.srcip: 10.0.0.34

# Filter by agent
agent.name: ubuntu-desktop

# Successful SSH login
rule.id: 5715
```

### Linux Containment Commands
```bash
# Block IP with UFW
sudo ufw deny from [IP]

# Block IP with iptables
sudo iptables -A INPUT -s [IP] -j DROP

# Disable user account
sudo passwd -l [USERNAME]

# Kill user sessions
sudo pkill -u [USERNAME]
```

### Investigation Commands
```bash
# Check auth logs
sudo tail -100 /var/log/auth.log | grep sshd

# Check failed logins
sudo grep "Failed password" /var/log/auth.log

# Check successful logins
sudo grep "Accepted" /var/log/auth.log
```

---

## References

- [MITRE ATT&CK T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Wazuh Documentation - SSH Authentication](https://documentation.wazuh.com/)
- [NIST SP 800-61 Rev. 2 - Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [CIS Benchmark - SSH Hardening](https://www.cisecurity.org/)

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Dec 6, 2025 | Steve | Initial playbook creation |

---

*This playbook was created as part of a SOC Analyst homelab project to demonstrate incident response procedures.*
