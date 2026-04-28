MITRE_RULES = {
    "brute_force": {
        "tactic": "TA0006 Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "description": "Repeated authentication attempts can indicate credential guessing against exposed or internal services.",
    },
    "port_scan": {
        "tactic": "TA0007 Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
        "description": "Broad connection attempts across ports can indicate reconnaissance and service discovery activity.",
    },
    "phishing_email": {
        "tactic": "TA0001 Initial Access",
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "description": "Suspicious email indicators may represent initial access attempts through social engineering.",
    },
    "malware_download": {
        "tactic": "TA0002 Execution",
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "description": "A risky download followed by user interaction can indicate attempted payload execution.",
    },
    "suspicious_login": {
        "tactic": "TA0006 Credential Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "description": "Successful login from unusual geography or infrastructure can indicate account misuse.",
    },
    "powershell_execution": {
        "tactic": "TA0002 Execution",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "description": "Suspicious PowerShell execution can indicate scripted automation, staging, or hands-on-keyboard activity.",
    },
    "command_and_control": {
        "tactic": "TA0011 Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "description": "Periodic outbound traffic over common protocols can indicate command-and-control beaconing.",
    },
    "web_attack": {
        "tactic": "TA0001 Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "description": "Suspicious web requests against exposed services can indicate exploitation attempts.",
    },
    "lateral_movement": {
        "tactic": "TA0008 Lateral Movement",
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "description": "Unexpected remote service usage can indicate movement between internal systems.",
    },
    "dns_tunneling": {
        "tactic": "TA0011 Command and Control",
        "technique_id": "T1071.004",
        "technique_name": "DNS",
        "description": "High-entropy or repetitive DNS queries can indicate tunneling or covert command channels.",
    },
    "privilege_escalation": {
        "tactic": "TA0004 Privilege Escalation",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "description": "Local privilege change indicators can suggest attempted escalation from a lower-privileged context.",
    },
    "data_exfiltration": {
        "tactic": "TA0010 Exfiltration",
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "description": "Unusual outbound data volume can indicate attempted collection staging or exfiltration.",
    },
}
