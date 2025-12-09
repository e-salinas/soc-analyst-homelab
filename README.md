# 🛡️ SOC Analyst Homelab - Wazuh SIEM

Enterprise-grade Security Operations Center (SOC) homelab demonstrating real-time threat detection, incident response, and security monitoring using Wazuh SIEM.

![Lab Status](https://img.shields.io/badge/Lab%20Status-Active-brightgreen)
![Scenarios](https://img.shields.io/badge/Attack%20Scenarios-7-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.x-orange)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Lab Architecture](#lab-architecture)
- [Skills Demonstrated](#skills-demonstrated)
- [Attack Scenarios](#attack-scenarios)
- [Incident Reports](#incident-reports)
- [Response Playbooks](#response-playbooks)
- [Key Metrics](#key-metrics)
- [Tools & Technologies](#tools--technologies)
- [Screenshots](#screenshots)
- [Lessons Learned](#lessons-learned)

---

## Overview

This project simulates a real-world Security Operations Center environment where I detect, investigate, and respond to various cyber attacks. The goal is to demonstrate practical SOC analyst skills including:

- Real-time security event monitoring
- Alert triage and classification
- Incident investigation and documentation
- Threat containment and remediation
- Playbook development and execution

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      SOC ANALYST HOMELAB                        │
│                    Network: 10.0.0.0/24                         │
└─────────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────────────┐
    │              MacBook (SIEM Server)                      │
    │  ┌───────────────────────────────────────────────────┐  │
    │  │            Ubuntu Server 24.04 VM (UTM)           │  │
    │  │                   10.0.0.65                       │  │
    │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │  │
    │  │  │   Wazuh     │ │   Wazuh     │ │   Wazuh     │  │  │
    │  │  │   Manager   │ │   Indexer   │ │  Dashboard  │  │  │
    │  │  └─────────────┘ └─────────────┘ └─────────────┘  │  │
    │  └───────────────────────────────────────────────────┘  │
    └─────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │   Network: 10.0.0.0/24│
                    └───────────┬───────────┘
                                │
    ┌───────────────────────────────────────────────────────────┐
    │                    iMac (Attack Lab)                      │
    │                                                           │
    │  ┌─────────────────────────────────────────────────────┐  │
    │  │                 UTM Virtual Machines                │  │
    │  │                                                     │  │
    │  │  ┌─────────┐    ┌─────────────┐    ┌─────────────┐  │  │
    │  │  │  KALI   │    │   UBUNTU    │    │   UBUNTU    │  │  │
    │  │  │  LINUX  │    │   DESKTOP   │    │   SERVER    │  │  │
    │  │  │         │    │             │    │             │  │  │
    │  │  │ Attacker│───▶│   Target    │    │   Target    │  │  │
    │  │  │   VM    │    │ + Wazuh     │    │ + Wazuh     │  │  │
    │  │  │         │    │   Agent     │    │   Agent     │  │  │
    │  │  │10.0.0.34│    │ 10.0.0.18   │    │ 10.0.0.186  │  │  │
    │  │  └─────────┘    └─────────────┘    └─────────────┘  │  │
    │  │                                                     │  │
    │  └─────────────────────────────────────────────────────┘  │
    │                                                           │
    └───────────────────────────────────────────────────────────┘
```

### Components

| Component | Role | IP Address |
|-----------|------|------------|
| Wazuh Server | SIEM - Manager, Indexer, Dashboard | 10.0.0.65 |
| Ubuntu Desktop | Primary Target + Wazuh Agent | 10.0.0.18 |
| Ubuntu Server | Secondary Target + Wazuh Agent | 10.0.0.186 |
| Kali Linux | Attack Platform (Red Team) | 10.0.0.34 |

---

## Skills Demonstrated

| Skill Category | Specific Skills |
|----------------|-----------------|
| **SIEM Operations** | Alert monitoring, log analysis, correlation rules, dashboard navigation |
| **Incident Response** | Detection, triage, investigation, containment, documentation |
| **Threat Analysis** | Attack pattern recognition, IOC identification, MITRE ATT&CK mapping |
| **Documentation** | Incident reports, response playbooks, timeline creation |
| **Linux Administration** | Firewall configuration (UFW), service management, log analysis |
| **Network Security** | Traffic analysis, port scanning detection, network segmentation |

---

## Attack Scenarios

| # | Scenario | MITRE ATT&CK | Status | Incident Report |
|---|----------|--------------|--------|-----------------|
| 1 | SSH Brute Force | T1110 - Brute Force | ✅ Complete | [INC-001](incidents/INC-001-SSH-Brute-Force.md) |
| 2 | Malware Detection (EICAR) | T1204 - User Execution | 🔄 In Progress | INC-002 |
| 3 | Privilege Escalation | T1548 - Abuse Elevation Control | ⏳ Planned | INC-003 |
| 4 | Port Scanning | T1046 - Network Service Discovery | ⏳ Planned | INC-004 |
| 5 | SQL Injection | T1190 - Exploit Public-Facing App | ⏳ Planned | INC-005 |
| 6 | Suspicious Process | T1059 - Command and Scripting | ⏳ Planned | INC-006 |
| 7 | Lateral Movement | T1021 - Remote Services | ⏳ Planned | INC-007 |

---

## Incident Reports

Detailed documentation of each security incident including timeline, investigation steps, and remediation actions.

| Incident ID | Title | Severity | Classification | Link |
|-------------|-------|----------|----------------|------|
| INC-001 | SSH Brute Force Attack | 🔴 HIGH | True Positive | [View Report](incidents/INC-001-SSH-Brute-Force.md) |

---

## Response Playbooks

Step-by-step procedures for responding to common security incidents.

| Playbook ID | Title | Threat Type | Link |
|-------------|-------|-------------|------|
| PB-001 | SSH Brute Force Response | Credential Attack | [View Playbook](playbooks/PB-001-SSH-Brute-Force.md) |

---

## Key Metrics

Performance metrics from incident response activities:

| Metric | Target | Achieved |
|--------|--------|----------|
| Mean Time to Detect (MTTD) | < 5 min | ✅ < 1 min |
| Mean Time to Respond (MTTR) | < 15 min | ✅ ~10 min |
| True Positive Rate | > 90% | ✅ 100% |
| Incidents Documented | 7+ | 🔄 1 (in progress) |
| Playbooks Created | 7+ | 🔄 1 (in progress) |

---

## Tools & Technologies

### Security Tools
- **Wazuh 4.x** - SIEM, IDS, FIM, Vulnerability Detection
- **Hydra** - Password cracking / brute force testing
- **Nmap** - Network scanning and reconnaissance
- **SQLmap** - SQL injection testing

### Infrastructure
- **UTM** - Virtualization platform (macOS)
- **Ubuntu Server 24.04** - SIEM host
- **Ubuntu Desktop 24.04** - Target endpoint
- **Kali Linux** - Attack platform

### Frameworks
- **MITRE ATT&CK** - Threat classification
- **NIST SP 800-61** - Incident response framework

---

## Screenshots

### Lab Overview
<!-- Add your Wazuh dashboard home screenshot -->
![Wazuh Dashboard Home](screenshots/wazuh-dashboard-home.png)
*Wazuh Dashboard showing monitored agents and security events*

### Scenario 1: SSH Brute Force Attack

#### Attack Detection
<!-- Add your screenshot showing the 94 alerts -->
![SSH Brute Force Alerts](screenshots/ssh-brute-force/01-alerts-overview.png)
*Wazuh detecting 94 authentication failure events from brute force attack*

#### Alert Details
<!-- Add your screenshot of expanded alert details -->
![Alert Details](screenshots/ssh-brute-force/02-alert-details.png)
*Detailed view showing attacker IP, target system, and MITRE ATT&CK mapping (T1110)*

#### Attack Timeline
<!-- Add your screenshot showing the event timeline/histogram -->
![Attack Timeline](screenshots/ssh-brute-force/03-attack-timeline.png)
*Timeline showing burst of authentication attempts during attack window*

#### Containment
<!-- Add your screenshot of UFW firewall block -->
![Firewall Block](screenshots/ssh-brute-force/04-containment-ufw.png)

*UFW firewall rule blocking attacker IP address*

---

## Lessons Learned

### Technical Insights
1. **Real-time detection is critical** - Wazuh detected the brute force attack within seconds, enabling rapid response
2. **Log correlation reveals patterns** - Multiple rule IDs (5758, 5710, 2502) together confirmed automated attack vs. user error
3. **Defense in depth works** - SSH rate limiting + SIEM detection + firewall blocking created multiple defensive layers

### Process Improvements
1. **Document as you go** - Capturing timestamps during the incident made report writing much easier
2. **Playbooks save time** - Having a documented procedure reduced response time significantly
3. **Screenshots are evidence** - Visual documentation proves hands-on experience to potential employers

---

## Future Enhancements

- [ ] Configure Wazuh Active Response for automated IP blocking
- [ ] Add Windows endpoint to lab environment
- [ ] Implement threat intelligence feeds
- [ ] Create custom Wazuh detection rules
- [ ] Set up automated reporting

---

## Connect With Me

- 📧 [LinkedIn](https://www.linkedin.com/in/esteban-salinas-11bb25291)
- 🔐 [CompTIA Security+ Certification](https://www.credly.com/badges/5316b1a9-f965-4b82-927f-82881234d4ab/public_url)

---

## Acknowledgments

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
