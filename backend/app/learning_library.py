"""Curated defensive learning templates.

These are educational draft detections, not production-ready rules. They never execute,
deploy, block, isolate, or change a system.
"""
from app.db import connection

Topic = tuple[str, str, str]

ON_PREM: list[Topic] = [
    ("Encoded PowerShell", "T1059.001", "PowerShell script block and process creation logs"),
    ("MSHTA proxy execution", "T1218.005", "Process creation logs"),
    ("Rundll32 proxy execution", "T1218.011", "Process creation logs"),
    ("Regsvr32 proxy execution", "T1218.010", "Process creation logs"),
    ("Certutil download or decode", "T1140", "Process creation and proxy logs"),
    ("BITS job abuse", "T1197", "BITS operational logs"),
    ("WMI event subscription persistence", "T1546.003", "WMI activity logs"),
    ("Scheduled task persistence", "T1053.005", "Task Scheduler and process logs"),
    ("Suspicious service creation", "T1543.003", "Windows System event logs"),
    ("Run key or Startup folder persistence", "T1547.001", "Registry and file creation logs"),
    ("LSASS credential access", "T1003", "Sysmon process access logs"),
    ("DCSync replication request", "T1003.006", "Directory service logs"),
    ("Kerberoasting indicators", "T1558.003", "Domain controller security logs"),
    ("RDP anomalous logon", "T1021.001", "Windows logon logs"),
    ("WinRM remote execution", "T1021.006", "WinRM and PowerShell logs"),
    ("SMB admin-share access", "T1021.002", "Windows file share logs"),
    ("Event-log clearing", "T1070.001", "Windows event log service logs"),
    ("Shadow-copy deletion", "T1490", "Process creation logs"),
    ("Security-tool impairment", "T1562.001", "Endpoint security and process logs"),
    ("IIS worker spawning shell", "T1505.003", "IIS and process creation logs"),
    ("Linux cron persistence", "T1053.003", "Linux audit and cron logs"),
    ("SSH authorized-keys modification", "T1098", "Linux file integrity logs"),
    ("Systemd service persistence", "T1543.002", "Linux systemd and audit logs"),
    ("Docker socket access", "T1611", "Container runtime audit logs"),
    ("SQL xp_cmdshell execution", "T1059", "SQL Server audit logs"),
]

CLOUD: list[Topic] = [
    ("Impossible-travel sign-in", "T1078", "Identity provider sign-in logs"),
    ("MFA fatigue pattern", "T1621", "Identity MFA and sign-in logs"),
    ("Legacy authentication use", "T1078", "Identity sign-in logs"),
    ("OAuth consent grant", "T1098.002", "Identity audit logs"),
    ("Service principal credential creation", "T1098", "Cloud directory audit logs"),
    ("Privileged cloud role assignment", "T1098", "Cloud directory audit logs"),
    ("Mailbox forwarding rule", "T1114.003", "Email audit logs"),
    ("Suspicious inbox rule", "T1114.003", "Email audit logs"),
    ("MFA method change", "T1098", "Identity audit logs"),
    ("AWS root-account use", "T1078", "CloudTrail"),
    ("AWS access-key creation", "T1098", "CloudTrail"),
    ("AWS IAM policy change", "T1098", "CloudTrail"),
    ("CloudTrail logging change", "T1562.008", "CloudTrail"),
    ("S3 bucket policy exposure", "T1530", "CloudTrail and S3 data events"),
    ("S3 bulk data access", "T1530", "S3 data events"),
    ("EC2 user-data modification", "T1059", "CloudTrail"),
    ("EKS cluster-role binding", "T1098", "Kubernetes audit logs"),
    ("GCP service-account key creation", "T1098", "Google Cloud audit logs"),
    ("GCP owner-role grant", "T1098", "Google Cloud audit logs"),
    ("Cloud audit-log disablement", "T1562.008", "Google Cloud audit logs"),
    ("Public cloud-storage permission", "T1530", "Cloud storage audit logs"),
    ("Azure Key Vault secret access", "T1552.004", "Azure Key Vault logs"),
    ("Azure VM extension deployment", "T1059", "Azure activity logs"),
    ("GitHub personal-token creation", "T1098", "GitHub organization audit logs"),
    ("Cloud token replay indicators", "T1528", "Identity and cloud audit logs"),
]

INCIDENT_RESPONSE: list[Topic] = [
    ("New local-account creation", "T1136", "Endpoint account-management logs"),
    ("Privileged-group membership change", "T1098", "Directory and endpoint security logs"),
    ("Office child-process execution", "T1204", "Process creation logs"),
    ("Suspicious archive creation", "T1560", "Process and file creation logs"),
    ("DNS tunneling indicators", "T1071.004", "DNS query logs"),
    ("Periodic beaconing pattern", "T1071", "Proxy and network-flow logs"),
    ("Remote-access tool execution", "T1219", "Process and network logs"),
    ("Remote-service lateral movement", "T1021", "Authentication and service logs"),
    ("Unexpected scheduled task", "T1053", "Task Scheduler logs"),
    ("Service-install triage", "T1543", "Windows System event logs"),
    ("Password-spray pattern", "T1110.003", "Identity sign-in logs"),
    ("Web-shell execution evidence", "T1505.003", "Web-server and process logs"),
    ("Staged-data collection", "T1074", "File and process logs"),
    ("Potential data exfiltration", "T1041", "Proxy and network-flow logs"),
    ("Known C2-domain query", "T1071.004", "DNS query logs"),
    ("Suspicious email-rule activity", "T1114.003", "Email audit logs"),
    ("Endpoint containment review trigger", "T1489", "Endpoint telemetry"),
    ("Log-deletion triage", "T1070.001", "Endpoint and cloud audit logs"),
    ("Suspicious driver installation", "T1547", "Driver and kernel event logs"),
    ("Registry-persistence triage", "T1547.001", "Registry audit logs"),
    ("Cryptocurrency-wallet artifact", "T1486", "Endpoint file and process logs"),
    ("Ransom-note file creation", "T1486", "Endpoint file creation logs"),
    ("Backup-deletion evidence", "T1490", "Process and backup-service logs"),
    ("Cloud-token abuse triage", "T1528", "Identity and cloud audit logs"),
    ("Evidence-retention gap", "T1070", "Collection and logging health records"),
]


def rule_content(segment: str, title: str, technique: str, telemetry: str, variant: str) -> tuple[str, str]:
    if variant == "detection":
        return "Sigma", f"title: {segment} learning — {title}\nstatus: experimental\ndescription: Educational draft. Human review and telemetry validation required.\ntags:\n  - attack.{technique.lower()}\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: '<review for {title}>'\n  condition: selection\nfalsepositives:\n  - Authorized administrative activity\nlevel: medium"
    return "Microsoft Sentinel KQL", f"// Educational hunt query draft — human review required\n// Topic: {title}\n// ATT&CK: {technique}\n// Required telemetry: {telemetry}\nSecurityEvent\n| where TimeGenerated > ago(7d)\n| where isnotempty(Account)\n| project TimeGenerated, Computer, Account, Activity, EventID"


def ensure_learning_library() -> None:
    libraries = {"On-Prem": ON_PREM, "Cloud": CLOUD, "Incident Response": INCIDENT_RESPONSE}
    with connection() as conn, conn.cursor() as cur:
        for segment, topics in libraries.items():
            for order, (title, technique, telemetry) in enumerate(topics, start=1):
                for variant, suffix, rank in (("detection", "Detection Pattern", order), ("hunt", "Hunt & Tuning Pattern", order + 25)):
                    template_title = f"{segment} — {title} ({suffix})"
                    rule_format, content = rule_content(segment, title, technique, telemetry, variant)
                    cur.execute(
                        """INSERT INTO detections (title, description, rule_format, rule_content, attack_techniques, required_telemetry, confidence, status, segment, learning_purpose, library_rank, learning_level)
                           VALUES (%s, %s, %s, %s, %s, %s, 'medium', 'draft', %s, true, %s, 'intermediate')
                           ON CONFLICT (segment, title) DO NOTHING""",
                        (template_title, f"Educational {variant} template for {title}. DRAFT — HUMAN REVIEW REQUIRED.", rule_format, content, [technique], [telemetry], segment, rank),
                    )
        cur.execute(
            """UPDATE detections
               SET learning_level = CASE
                   WHEN ((library_rank - 1) % 25) + 1 <= 7 THEN 'beginner'
                   WHEN ((library_rank - 1) % 25) + 1 <= 18 THEN 'intermediate'
                   ELSE 'advanced'
               END
               WHERE learning_purpose"""
        )
