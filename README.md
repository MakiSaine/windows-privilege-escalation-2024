# Windows Privilege Escalation Lab (2024)

This repository documents a controlled lab exercise performed as part of coursework and later extended with additional self directed analysis. The lab demonstrates discovery, exploitation of a legacy SMB vulnerability, post-exploitation enumeration and evidence collection on a Windows VM. All images have been redacted to remove sensitive values and are included for educational and defensive research in authorized environments only.

## Table of Contents

- [Summary](#summary)  
- [Scope and safety](#scope-and-safety)  
- [Project content](#project-content)  
- [Key findings](#key-findings)  
- [Tools and technologies](#tools-and-technologies)  
- [High level workflow](#high-level-workflow)  
- [Project screenshots](#project-screenshots)  
  - [Environment and access](#environment-and-access)  
  - [Network discovery and exposure](#network-discovery-and-exposure)  
  - [Compromise and session](#compromise-and-session)  
  - [Host capture and evidence handling](#host-capture-and-evidence-handling)  
  - [Trace conversion and network analysis](#trace-conversion-and-network-analysis)  
- [Defensive recommendations](#defensive-recommendations)  
- [References](#references)  
- [Contact](#contact)

## Summary

This lab demonstrates how an attacker can enumerate services, exploit an exposed legacy vulnerability to gain a remote session, and collect host and network artefacts. It also shows how trace data can be extracted from the host, converted for offline analysis, and used to recover sensitive information. The material here is high level and intended to help defenders spot indicators of compromise and improve controls.

## Scope and safety

- Lab environment only. Do not reuse techniques against systems you do not own or have explicit authorization to test.  
- Screenshots have been redacted (IPs, usernames, hashes and session tokens removed).  
- This document intentionally omits step-by-step exploit commands. It focuses on observations, artefacts and defensive guidance.

## Project content

- A chronological set of screenshots documenting the exercise from initial enumeration to evidence extraction.  
- High level narrative of actions and observations.  
- Recommendations for detection, containment and remediation.

## Key findings

- Unpatched legacy services may allow remote code execution leading to full system compromise.  
- An attacker with SYSTEM privileges can create, move and delete forensic artefacts; monitoring for suspicious file activity and transfers is crucial.  
- ETL traces on Windows can be converted for network analysis and may reveal sensitive cleartext credentials if the target application lacks TLS.  
- Endpoint telemetry (process creation, command lines, file writes) combined with network captures are the most reliable path to detect and investigate such incidents.

## Tools and technologies

- Windows Server (victim lab host)  
- Kali Linux (attacker / analysis host)  
- Network and host enumeration tools, exploitation framework for lab testing (high level only)  
- Windows built-in ETW tracing (`netsh trace`) for host captures  
- etl2pcapng utility for converting ETL traces to PCAPNG  
- Wireshark for offline network analysis

## High level workflow

1. Confirm lab connectivity and collect host IP addresses for attacker and victim.  
2. Perform network and service enumeration to identify exposed services.  
3. Validate presence of a known legacy vulnerability in a safe, controlled manner.  
4. Use an appropriate test framework in the lab to gain an interactive session for analysis purposes.  
5. From the compromised host collect system information and open an interactive shell for investigation.  
6. Start a host side network trace and allow the target application to exercise the functionality of interest.  
7. Stop the trace, transfer the ETL file to the analysis host and convert it to PCAPNG.  
8. Inspect the capture for sensitive artifacts such as HTTP POST bodies, credentials or suspicious callouts.  
9. Clean up temporary artefacts and document findings.

---

## Project screenshots

> Note: image paths below use `screenshot/<filename>.png` to match the repository folder name exactly.

### Environment and access

Shows the administrative user context menu in the lab environment.  
![Administrator user menu](screenshot/admin_user_menu.png)

Login prompt for the utility Linux VM used during the exercise.  
![Linux login screen (osboxes)](screenshot/osboxes_login.png)

Victim host interactive login screen. Useful to correlate interactive sessions with timeline events.  
![Windows login prompt](screenshot/windows_login_screen.png)

Snapshot of system settings and product activation details used for baseline documentation.  
![Windows system information](screenshot/windows_system_info.png)

### Network discovery and exposure

Target host IP address and interface details used for connectivity verification.  
![Windows IP configuration output](screenshot/windows_ipconfig_output.png)

Attacker host IP configuration used for routing and file transfer validation.  
![Kali IP configuration output](screenshot/kali_ifconfig_output.png)

Utility host interface details used during file handling and conversion steps.  
![Linux IP configuration output](screenshot/linux_ip_address.png)

Shows a vulnerability script result indicating exposure of a legacy SMB weakness; demonstrates why patching and inventory are critical.  
![Nmap MS17 010 vulnerability scan](screenshot/nmap_ms17_010_scan.png)

Service fingerprinting output used to build the attack surface map.  
![Nmap service scan result](screenshot/nmap_scan_result.png)

### Compromise and session

Attacker framework start; in production such tool usage may trigger EDR detections.  
![Starting Metasploit console](screenshot/msfconsole_start.png)

High level exploit output showing session creation in the lab. (No exploit commands included).  
![MS17 010 exploit execution](screenshot/ms17_010_exploit_execution.png)

Interactive session opened; defenders should monitor for unusual shell spawn and lateral movement attempts.  
![Meterpreter shell started](screenshot/meterpreter_shell_start.png)

Confirmation of privilege context observed by the attacker (SYSTEM in the lab scenario).  
![Meterpreter shell with whoami](screenshot/meterpreter_shell_whoami.png)

Collected host metadata: OS version, architecture and domain details used to prioritise response.  
![Meterpreter system information](screenshot/meterpreter_sysinfo.png)

### Host capture and evidence handling

Host side trace started to capture network activity for forensic analysis.  
![Starting ETL trace capture](screenshot/netsh_trace_start.png)

Verification that host tracing is active and recording to the expected file.  
![Checking ETL trace status](screenshot/netsh_trace_status.png)

Provider and level information indicating what subsystems were traced.  
![Netsh trace show status output](screenshot/netsh_trace_show_status.png)

Trace session stopped and ETL file persisted to disk.  
![Stopping ETL trace capture](screenshot/netsh_trace_stop.png)

Temporary files observed on the victim prior to cleanup; monitor temp locations for staging.  
![Windows temp directory listing](screenshot/windows_temp_directory.png)

Example of attacker cleanup activity. Alerts for bulk deletions and unusual cleanup scripts can indicate tampering.  
![Meterpreter cleanup commands](screenshot/meterpreter_cleanup_commands.png)

### Trace conversion and network analysis

ETL file transferred to the analysis host and visible in the file manager.  
![Kali file manager with ETL file](screenshot/kali_file_manager.png)

Interaction showing retrieval of the ETL from the victim to the analyst host.  
![Downloading ETL file via Meterpreter](screenshot/meterpreter_file_download.png)

Workspace organization for conversion tasks and captured artefacts.  
![ETL file folder view](screenshot/etl_file_folder_view.png)

Utility used to convert ETL traces to PCAPNG format for Wireshark analysis.  
![Downloading etl2pcapng tool](screenshot/etl2pcapng_download.png)

Conversion output confirming frames were written to the PCAPNG file.  
![Converting ETL to PCAPNG file](screenshot/etl_to_pcap_conversion.png)

Movement of capture files between hosts; monitor and restrict cross-segment transfers.  
![ETL file transfer between systems](screenshot/etl_file_transfer.png)

Filtered list of HTTP requests used to quickly identify POSTs and form submissions.  
![Wireshark captured HTTP requests](screenshot/wireshark_http_requests.png)

Captured HTTP POST body containing application credentials in the lab capture. This shows why TLS and secure session handling are essential.  
![HTTP POST form with credentials](screenshot/wireshark_http_post_credentials.png)

---

## Defensive recommendations

- **Patch and inventory**: Remove or isolate legacy services and ensure timely patching of high risk vulnerabilities.  
- **Network segmentation**: Limit lateral movement and reduce exposure of management services.  
- **Endpoint telemetry**: Collect process, command line and file activity; alert on suspicious shells and rapid file transfers.  
- **Network monitoring**: Capture and retain relevant packet captures or ETW traces for forensic validation; alert on plaintext credential transmissions.  
- **Least privilege and credential hygiene**: Reduce administrative exposure and enforce multi factor authentication for privileged accounts.  
- **Secure development**: Ensure applications validate and encode user input, enforce HTTPS and use secure cookie attributes.

## References

- OWASP — Cross Site Scripting Prevention Cheat Sheet  
- Microsoft — Event Tracing for Windows (ETW) documentation  
- Wireshark — User guide and HTTP analysis

## Contact

For questions or collaboration, please reach out.

Created by Mahamed Maki Saine – Cybersecurity | Ethical Hacker | AI Learner

