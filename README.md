# Network Traffic Analysis: DNS Tunneling Data Exfiltration

## Executive Summary
**Objective:** To analyze a PCAP file, map the network environment, and identify the mechanism used for suspected data exfiltration.

**Conclusion:** Identified an active data exfiltration campaign utilizing DNS tunneling. The attacker bypassed the internal DNS server to exfiltrate Personally Identifiable Information (PII) and credit card details by encoding a compressed '.gz' archive in Base32 and appending it as subdomains in anomalous DNS queries.

---

## Environment & Network Topology

Through Endpoint and Conversation statistics mapping, I established the following baseline network architecture:
*  **Identified Subnets:** '10.75.34.0' and '10.87.182.0'
*  **Default Gateway:** '10.75.34.1' (Handles forwarded external DNS/HTTP traffic)
*  **Internal DNS Server:** '10.75.34.2' (Internal clients query this; forwards external requests to the gateway)
*  **Compromised Internal Host:** '10.75.34.13'
*  **Attacker/Malicious DNS Server:** '251.91.13.37'
*  **Tools Used:** Wireshark, tshark, CyberChef

---

## Investigation Walkthrough

### 1. Protocol Hierarchy & Initial Triage
To begin the investigation, I reviewed the Protocol Hierarchy and noted that HTTP and DNS accounted for the vast majority of packet exchanges. 
* **Action:** Initially focused on HTTP traffic.
* **Observation:** After thorough inspection, HTTP traffic appeared benign. I then pivoted my focus to the DNS traffic.

<img width="953" height="508" alt="image" src="https://github.com/user-attachments/assets/873facc3-e8ab-4021-83ac-ace4de50e59a" />

### 2. Network Mapping & Anomaly Detection
To understand normal behavior, I mapped the network using Conversations and Endpoint statistics. I observed the standard flow: endpoints queried the internal DNS ('10.75.34.2'), which forwarded requests to the gateway.
* **Observation:** I discovered an anomaly. A specific host ('10.75.34.13') was bypassing the standard internal DNS resolution path and sending direct DNS requests to an external, unknown IP address ('251.91.13.37').
* **The Payload:** The requested subdomains to this external IP were unusually long and appeared to be encoded strings rather than legitimate domain names.

  <img width="956" height="509" alt="image" src="https://github.com/user-attachments/assets/89c8172e-9c69-4964-9b24-edefcceb4f76" />

### 3. Data Extraction via Tshark
The Wireshark GUI is inefficient for extracting hundreds of sequential subdomains. To rebuild the payload, I switched to the command line using 'tshark' to filter the PCAP and carve out just the queried subdomains.
   Command utilized (powershell): 
    """
    (.\tshark.exe -r pirates.pcap -Y "ip.dst == 251.91.13.37" -T fields -e dns.qry.name | ForEach-Object { $_ -replace '\..*' }) -join '' > subdomains.txtt
    """
 
<img width="854" height="32" alt="image" src="https://github.com/user-attachments/assets/b87ae459-e60f-47ba-9ee8-e5441e5cebd3" />

### 4. Decoding and Payload Identification
Recognizing the character set of the extracted string (a-z,2-7), I suspected Base32 encoding.
*   **Action:** Imported the extracted string into CyberChef.
*   **Recipe Applied:** 
    1. 'From Base32' (Converting the base32 to Hex, the decoded output contained the magic bytes for a GZIP archive)
    2.  'Gunzip'
 
<img width="737" height="358" alt="image" src="https://github.com/user-attachments/assets/1fa1eb10-3230-48a7-9797-b4a6728a3c72" />

### 5. Final Exfiltration Discovery
The decoded output successfully decompressed the '.gz' archive. 
*   **Finding:** The archive contained a plaintext file holding sensitive user information, including cleartext credit card details. The attacker successfully utilized DNS tunneling to covertly exfiltrate this data past the firewall.

  ---

## Indicators of Compromise (IoCs)

| Type | Value | Description |
| :--- | :--- | :--- |
| **IPv4** | '251.91.13.37' | Malicious External DNS / Exfiltration Server |
| **IPv4** | '10.75.34.13' | Compromised Internal Host |
| **Technique** | Base32 Encoded Subdomains | DNS Tunneling Data Exfiltration |

---

## Remediation Recommendations
1.  **Network Segmentation:** Block outbound DNS requests (Port 53) from all internal client subnets directly to the internet. Force all DNS traffic to route exclusively through the internal DNS server ('10.75.34.2').
2.  **Isolation:** Immediately isolate '10.75.34.13' from the network to prevent further data loss and begin forensic imaging to determine the initial infection vector.
3.  **Threat Intelligence:** Add '251.91.13.37' to the firewall and SIEM blocklists.
