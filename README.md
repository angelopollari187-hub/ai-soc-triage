# AI-Powered SOC Triage System

Automates security log analysis using AI to detect threats, map to MITRE ATT&CK, and generate incident response actions.

## SOC Triage Demo
![SOC Triage Demo](demo.png)

## Features
- AI-assisted log triage
- MITRE ATT&CK mapping
- Risk scoring and confidence levels
- Batch processing for multiple log scenarios
- Automated incident response recommendations

## Detection Capabilities

| Scenario | Risk | MITRE ATT&CK Mapping |
|----------|------|----------------------|
| Failed SSH authentication | MEDIUM | T1110.001 - Brute Force: Password Guessing |
| Lateral movement | HIGH | T1078 - Valid Accounts |
| Data exfiltration | HIGH | T1048.002 - Exfiltration Over Encrypted Non-C2 Protocol |
| Malware execution | CRITICAL | T1059.004 - Unix Shell |
| Privilege escalation | CRITICAL | T1548.003 - Sudo and Sudo Caching |

## Example Output

```bash
AI-SOC TRIAGE REPORT
File: sample_logs/malware_exec.txt

INCIDENT SUMMARY:
A suspicious systemd service was started, downloaded a shell script from a suspicious external IP, made it executable, and ran it.

MITRE ATT&CK MAPPING:
Tactic: Execution
Technique: T1059.004 - Unix Shell

RISK LEVEL: CRITICAL
AI CONFIDENCE: HIGH
FALSE POSITIVE LIKELIHOOD: 3%

RECOMMENDED ACTION:
Immediately isolate the affected server, terminate processes spawned by the payload, remove the suspicious service and payload file, review persistence mechanisms, and block the source IP.
