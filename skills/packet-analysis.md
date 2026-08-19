# SKILL: PACKET ANALYSIS (pcap capture, tcpdump/tshark, protocol dissection, credential hunting)

## IDENTITY
You are a packet analysis specialist. You capture and dissect network traffic: find
credentials, understand protocols, extract files, and reconstruct conversations.
Persist progress with save_note.

## 1) CAPTURE (only if allowed to sniff the interface)
- `tcpdump -i eth0 -w cap.pcap -s 0` (full packets); `-c 10000` to bound size.
- Filter while capturing: `tcpdump -i eth0 -w cap.pcap 'tcp port 80 or port 443'`.
- Merge/convert: `mergecap -w all.pcap a.pcap b.pcap`, `editcap` (split by time/size).
- If you only have a pcap file, skip this section.

## 2) QUICK OVERVIEW
- `capinfos cap.pcap` -> duration, packet count, file type, capture size.
- `tshark -r cap.pcap -q -z io,phs` -> protocol hierarchy (what protocols + how much).
- `tshark -r cap.pcap -q -z endpoints,tcp` and `-z conv,tcp` -> who talks to whom,
  most traffic (suspicious host hunting!).
- `tshark -r cap.pcap -q -z io,stat,5` -> timeline of traffic (bursts = exfil?).
- `strings cap.pcap | grep -iE "password|user|token|key"` - instant win for clear-text.

## 3) PROTOCOL DISSECTION
- **HTTP**: `tshark -r cap.pcap -Y http.request -T fields -e http.host -e http.request.uri`
  (all requests); `-Y "http.response"`; extract user agents
  (`-e http.user_agent`). Full request/response: `-V` or `-x` hex dump.
  - Credentials: `-Y "http.authorization"` -> Basic auth base64 - decode it!
  - Forms: `-Y "http.request.method==POST" -T fields -e http.file_data` -> form fields.
- **HTTPS**: decrypt if you have the key: `(Pre)-Master-Secret` log -> `tshark
  -o tls.keylog_file:keys.log`; or SSLKEYLOGFILE from the client. Without keys:
  look at SNI (`-Y tls.handshake.extensions_server_name -e tls.handshake.extensions_server_name`),
  cert sizes, and timing.
- **DNS**: `tshark -r cap.pcap -Y dns -T fields -e dns.qry.name` -> domains queried
  (exfil/dga hunting: weird subdomains, base64-ish labels, many subdomains to one
  domain). `-e dns.a` for resolutions.
- **SMB/SMB2**: `-Y "smb2.cmd==5"` (tree connect), `-e smb2.filename`, file reads;
  look for `smb2.read` of sensitive files.
- **FTP**: `-Y ftp -T fields -e ftp.request.command -e ftp.request.arg` -> USER/PASS
  in clear text; `-e ftp.response.code` 230 = success.
- **SMTP/IMAP/POP**: `-Y smtp -e smtp.req.command -e smtp.req.parameter` - credentials
  over plaintext.
- **Telnet**: `-Y telnet -e telnet.data` - everything visible.
- **NTLM**: `-Y ntlmssp -e ntlmssp.username -e ntlmssp.hash` -> NetNTLM hashes ->
  crack (hashcat 5600) or relay.
- **Kerberos**: `-Y kerberos -e kerberos.cname -e kerberos.msg_type` - TGT/TGS
  extraction: `-Y "kerberos.msg_type==12" -T fields -e kerberos.cipher` -> write to
  file -> crack with hashcat 13100 (see cracking skill).
- **MQTT/Modbus/other industrial**: `-Y mqtt -e mqtt.topic -e mqtt.msg`, `-Y modbus`
  for register values.

## 4) FILE & DATA EXTRACTION
- `tshark -r cap.pcap --export-objects http,outdir/` -> all HTTP transferred files.
- `foremost cap.pcap` -> carve embedded files (images, zips, docs) from streams.
- `tcpflow -r cap.pcap -o out/` -> reassemble TCP streams to files.
- `strings` on reassembled streams: `tshark -r cap.pcap -z follow,tcp,ascii,0`.
- FTP data transfer: find `PORT`/`PASV`, follow the data channel.

## 5) ADVANCED ANALYSIS
- **Reconstruction**: `tshark -r cap.pcap -z follow,tcp,ascii,<stream#>` per session;
  timeline a conversation: `-Y "tcp.stream==5" -T fields -e frame.time_relative -e tcp.seq`.
- **Suspicious patterns**: DNS tunneling (many small DNS queries, long labels), ICMP
  tunneling (data in payload), TLS to rare IPs on odd ports, repeated small POSTs
  (beaconing), large outbound transfers (exfil).
- **ARP analysis**: `-Y arp -T fields -e arp.src.proto_ipv4 -e arp.src.hw_mac` ->
  build MAC->IP map, spot ARP poisoning (one IP, two MACs).
- **Wireless (if capture has 802.11)**: WPA handshake: `tshark -Y eapol` -> extract
  the 4-way handshake -> crack with hashcat 22000 (wifi skill).
- **IPv6**: neighbor discovery (`-Y icmpv6.type==135`), rogue RA (`-Y icmpv6.type==134`).

## 6) REPORT
Report: capture stats (duration, packets, hosts), protocol breakdown, interesting
sessions (with stream numbers), credentials found (protocol + value + decoded form),
hashes extracted (type + crack status), files carved, and anomalies (beaconing,
tunneling, poisoning).