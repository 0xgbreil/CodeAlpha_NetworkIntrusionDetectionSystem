# Network Intrusion Detection System (NIDS)

A simple Network Intrusion Detection System project using Suricata, created as part of my Cyber Security Internship at CodeAlpha.

This project monitors network traffic using Suricata and custom detection rules to detect specific network activities and generate alerts in the `fast.log` file.

---

## 1. ICMP Echo Request Detection

This rule detects ICMP Echo Request packets, commonly generated when using the `ping` command. It specifically uses `itype:8` to detect only Echo Request packets and generates an alert when a match is found.

### Rule

`alert icmp any any -> any any (msg:"ICMP Echo Request Detected"; itype:8; sid:1000001; rev:1;)`

### Demo

[Watch ICMP Detection Demo](./demos/1.mp4)

---

## 2. HTTP GET Request Detection

This rule detects HTTP GET requests sent to a web server. It inspects the HTTP method and generates an alert when the request method is `GET`.

### Rule

`alert http any any -> any any (msg:"HTTP Request Detected"; flow:established,to_server; http.method; content:"GET"; sid:1000002; rev:1;)`

### Demo

[Watch HTTP Detection Demo](./demos/2.mp4)

---

## 3. Suspicious TCP Connection to Port 4444

This rule detects TCP connection attempts to destination port `4444`. It monitors TCP SYN packets, which are typically used to initiate a TCP connection, and generates an alert when a matching connection attempt is detected.

### Rule

`alert tcp any any -> any 4444 (msg:"Suspicious TCP Connection to Port 4444 Detected"; flow:to_server; flags:S; sid:1000003; rev:1;)`

### Demo

[Watch Port 4444 Detection Demo](./demos/3.mp4)

---

## Contact

**Mohamed Gbreil (0xgbreil)**

- GitHub: https://github.com/0xgbreil
- LinkedIn: https://www.linkedin.com/in/0xgbreil/
- X (Twitter): https://x.com/0xgbreil

---
