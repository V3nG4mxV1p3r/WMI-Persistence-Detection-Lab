# 🛡️ WMI Event Subscription Persistence Detection (MITRE T1546.003)

## 📌 Overview

This repository documents a **Purple Team detection lab** focused on engineering custom, high-fidelity Wazuh SIEM alerts for one of the stealthiest persistence mechanisms on Windows — **WMI Event Subscription**.

This technique is tracked under **MITRE ATT&CK Technique [T1546.003](https://attack.mitre.org/techniques/T1546/003/)** and is classified under both **Persistence** and **Privilege Escalation** tactics.

Unlike registry Run keys or scheduled tasks, WMI subscriptions:
- ✅ Write **no new files** to disk
- ✅ Create **no registry Run keys**
- ✅ **Survive reboots** automatically
- ✅ Are **missed by most AV/EDR** solutions monitoring only file-based indicators


---

## 🎯 Objective & The Blind Spot

Most SIEM implementations and SOC teams focus on **registry persistence** (Run keys) and **scheduled tasks** as their primary persistence detection surface. This creates a significant blind spot:

> **WMI Event Subscriptions are entirely in-memory, fileless, and persist across reboots — making them invisible to defenders who don't monitor WMI telemetry.**

This lab demonstrates how to close that gap using **Sysmon Event ID 19/20/21** combined with **custom Wazuh detection rules** and a **Sigma rule** for portability.

---

## 🏗️ Lab Environment

| Component | Role |
|-----------|------|
| Windows 10 (VirtualBox) | Target machine — Wazuh Agent + Sysmon v15.15 |
| Wazuh Server (Ubuntu) | SIEM — log ingestion, rule engine, alerting |

---

## ⚔️ Phase 1: Enabling WMI Telemetry (Sysmon Config)

By default, Sysmon does not log WMI activity. The first step is enabling **Event ID 19, 20, 21** in the Sysmon configuration.

I updated the active Sysmon config (`shell_config.xml`) to include:

```xml
<WmiEvent onmatch="include">
  <Operation condition="is">Created</Operation>
</WmiEvent>
```

After applying the config with `sysmon64 -c shell_config.xml`, the rule configuration was verified:

<img width="883" height="469" alt="01_sysmon_wmi_config_verified" src="https://github.com/user-attachments/assets/be354487-5239-4bf7-b5b3-e77e94a0771d" />

> ✅ `WmiEvent onmatch: include — Operation: is 'Created'` confirmed active.

---

## 🏴‍☠️ Phase 2: Attack Simulation — Building the WMI Persistence Chain

The attack was executed entirely via **PowerShell** on the Windows 10 target, simulating a post-exploitation persistence scenario.

A WMI persistence chain consists of three components:

| Component | Class | Purpose |
|-----------|-------|---------|
| EventFilter | `__EventFilter` | Defines the WQL trigger query |
| EventConsumer | `CommandLineEventConsumer` | Defines the payload to execute |
| FilterToConsumerBinding | `__FilterToConsumerBinding` | Binds the filter to the consumer |

**Attack script (simplified):**

```powershell
# EventFilter — trigger
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name           = "AltaSecPersist"
    Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    QueryLanguage  = "WQL"
    EventNameSpace = "root\cimv2"
}

# EventConsumer — payload
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name                = "AltaSecConsumer"
    CommandLineTemplate = "cmd.exe /c echo WMIPersistTest >> C:\wmi_test.txt"
}

# Binding — complete the chain
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter   = $filter
    Consumer = $consumer
}
```

The WMI persistence chain was confirmed registered:

<img width="884" height="427" alt="02_wmi_persistence_registered" src="https://github.com/user-attachments/assets/220592dd-18ca-468a-8ee5-3f1ba0183cf1" />

> ✅ `AltaSecPersist` (EventFilter) and `AltaSecConsumer` (EventConsumer) successfully registered in `root\subscription`.

---

## 🔍 Phase 3: Sysmon Detection — Event ID 19, 20, 21

Immediately after the attack, **Sysmon captured all three stages** of the persistence chain in the Windows Event Log:

### Event ID 19 — WmiEventFilter Activity Detected

<img width="1090" height="770" alt="04_sysmon_event19_filter" src="https://github.com/user-attachments/assets/7baf1ed8-bec1-4ca3-bd74-19f0465db8a6" />

> `EventType: WmiFilterEvent | Name: AltaSecPersist | Query: SELECT * FROM __InstanceModificationEvent...`

### Event ID 20 — WmiEventConsumer Activity Detected

<img width="1086" height="769" alt="05_sysmon_event20_consumer" src="https://github.com/user-attachments/assets/2c53929f-dd61-45ac-ab50-7c968e2c490f" />

> `EventType: WmiConsumerEvent | Name: AltaSecConsumer | Destination: cmd.exe /c echo WMIPersistTest >> C:\wmi_test.txt`

### Event ID 21 — WmiEventConsumerToFilter Binding Detected

<img width="1088" height="755" alt="03_sysmon_event21_binding_detected" src="https://github.com/user-attachments/assets/94386bd2-49fd-487a-8de5-7f696812c75b" />

> `EventType: WmiBindingEvent | Consumer: AltaSecConsumer | Filter: AltaSecPersist`  
> ⚠️ **Full persistence chain established.**

---

## 🧠 Phase 4: Custom Detection Rule Architecture (Wazuh)

Since I wanted **AltaySec-signed detections** on top of Wazuh's built-in rules, I engineered three custom rules mapping each stage of the WMI persistence chain:

```xml
<group name="sysmon,wmi,persistence,altaysec">

  <rule id="100200" level="12">
    <if_group>sysmon_eid19_detections</if_group>
    <description>AltaySec: WMI EventFilter registered - T1546.003 Persistence</description>
    <mitre><id>T1546.003</id></mitre>
  </rule>

  <rule id="100201" level="12">
    <if_group>sysmon_eid20_detections</if_group>
    <description>AltaySec: WMI EventConsumer registered - T1546.003 Persistence</description>
    <mitre><id>T1546.003</id></mitre>
  </rule>

  <rule id="100202" level="15">
    <if_group>sysmon_eid21_detections</if_group>
    <description>AltaySec: WMI FilterToConsumerBinding - Full persistence chain complete T1546.003</description>
    <mitre><id>T1546.003</id></mitre>
  </rule>

</group>
```

Custom rules deployed and verified in Wazuh Dashboard:

<img width="942" height="440" alt="08_wazuh_custom_rules" src="https://github.com/user-attachments/assets/4c9fb905-66fa-4447-9d00-1117a49bbb88" />


> ✅ Rule IDs 100200, 100201, 100202 active — Level 12/15 with MITRE T1546.003 tagging.

---

## 🚨 Phase 5: SIEM Triage & Alert Results

The custom detection logic performed successfully in real-time. Upon attack execution, **Rule 100201 triggered instantly**:

<img width="680" height="155" alt="09_wazuh_custom_rule_100201_triggered" src="https://github.com/user-attachments/assets/aa7e2d1e-2b2c-4f56-a08a-78b59ca4b408" />

<img width="681" height="278" alt="10_wazuh_custom_rule_100201_triggered" src="https://github.com/user-attachments/assets/00c65723-c3fe-4ae1-b309-cdd1d75779f6" />

**Confirmed alert fields:**

| Field | Value |
|-------|-------|
| `rule.id` | 100201 |
| `rule.level` | 12 |
| `rule.description` | AltaySec: WMI EventConsumer registered - T1546.003 Persistence |
| `rule.mitre.id` | T1546.003 |
| `rule.mitre.tactic` | Privilege Escalation, Persistence |
| `agent.name` | Windows10 |
| `data.win.eventdata.name` | AltaSecConsumer |
| `data.win.eventdata.destination` | cmd.exe /c echo WMIPersistTest >> C:\wmi_test.txt |

### Deep Log Analysis

The triggered alert captured the full payload and IOC context:

<img width="855" height="279" alt="06a_wazuh_discover_overview" src="https://github.com/user-attachments/assets/07cb95cb-d5d5-42c1-b218-6d954818961a" />

<img width="709" height="373" alt="06b_wazuh_discover_payload" src="https://github.com/user-attachments/assets/264a11be-02f4-4794-97c6-c33f4dca07fa" />

---

## 🟣 Phase 6: Sigma Rule — Portable Detection

To make this detection portable across any SIEM, I authored a **Sigma rule** covering all three WMI event IDs:

```yaml
title: WMI Event Subscription Persistence Detection
id: a1b2c3d4-0001-0001-0001-000000000001
status: experimental
description: Detects WMI Event Subscription persistence via Sysmon Event ID 19/20/21
author: Emir Rasit Gokce (@V3nG4mxV1p3r) - AltaySec Labs
date: 2026/05/05
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1546.003
logsource:
    product: windows
    category: wmi_event
detection:
    selection:
        EventID:
            - 19
            - 20
            - 21
    condition: selection
falsepositives:
    - Legitimate software using WMI subscriptions (e.g. SCCM, monitoring agents)
level: high
```

---

## 💡 Key Takeaways

- **WMI persistence is fileless** — no artifacts on disk, no registry keys
- **Sysmon Event ID 19/20/21 is the only reliable telemetry source** for this technique
- **Behavioral detection beats signature detection** — the payload content doesn't matter, the WMI subscription creation itself is the IOC
- Defenders relying only on file/registry monitoring are **completely blind** to this attack vector

---

## 📁 Repository Structure

```
WMI-Persistence-Detection-Lab/
├── attack/
│   ├── wmi_persistence.ps1       # Full attack simulation script
│   └── wmi_cleanup.ps1           # Lab cleanup — removes all artifacts
├── detection/
│   ├── wazuh_rules.xml           # Custom Wazuh rules (100200-100202)
│   └── sigma_wmi_persistence.yml # Sigma rule — SIEM-agnostic
├── sysmon/
│   └── shell_config.xml          # Sysmon config with WMI logging enabled
└── screenshots/                  # Lab evidence
```

---

## 🔗 References

- [MITRE ATT&CK T1546.003](https://attack.mitre.org/techniques/T1546/003/)
- [Sysmon WMI Events Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Wazuh Documentation](https://documentation.wazuh.com)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)

---
