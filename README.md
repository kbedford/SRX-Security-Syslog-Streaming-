# SRX-Security-Syslog-Streaming-
Juniper SRX RT_FLOW logs are famously chatty but most analytics only need a handful of fields: the source/destination, any NAT translation, the protocol, a couple of byte counters, and when the session actually happened

This post shows how to turn that firehose into neat, line-delimited JSON using Logstash, while keeping only the session-close events that carry bytes and elapsed time (so we can also infer the session start).

Built a tiny lab—SRX1 → SRX2 (DUT) → SRX3 with a CentOS collector—generate ICMP traffic, and stream SRX2’s RT_FLOW logs (RFC5424 + structured data) to UDP/5514. 

Logstash parses the message, drops session-create, computes session.start = close_time − elapsed_time, and writes just the essentials to a file.

By the end you’ll have:

    A working SRX config that streams RT_FLOW to a remote collector
    
    A Logstash pipeline that extracts exactly the fields you care about
    
    Compact JSON lines ready for search, dashboards, or downstream shipping (Elasticsearch, S3, Kafka, etc.)
    
    If you’re fighting log volume or correlation complexity, close-only logging plus this pipeline is a clean, low-overhead way to get precise session timing and NAT visibility without drowning in noise.



---

# Parsing Juniper SRX RT\_FLOW with Logstash (End-to-End Lab)

> Turn noisy firewall logs into compact, analytics-ready JSON using Logstash.
> We’ll build a tiny three-node lab (SRX1 → SRX2 → SRX3 + CentOS syslog collector), generate traffic, send **RT\_FLOW** logs from SRX2, and extract exactly the fields we care about—**source/destination+NAT, protocol, session timestamps, bytes, elapsed time**—with **close-only** logging.


* SRX2 is the DUT (Device Under Test): it does source NAT for `10.10.10.0/24 → 20.20.20.0/24` and streams security logs to a CentOS collector (`111.1.1.2:5514/UDP`).
* We log **session-close** events and derive the session **start** timestamp from Junos’ `elapsed-time`.
* Logstash parses Junos RFC5424 + structured data, drops session-create, and emits slim JSON lines.

---

## Lab Topology

```
SRX1 (10.10.10.1)  --[10.10.10.0/24]-->  SRX2 (DUT)
                                        - ge-0/0/1: 10.10.10.2/24  (inside)
                                        - ge-0/0/2: 20.20.20.1/24  (outside)
                                        - ge-0/0/0: 111.1.1.1/24   (log plane)

SRX3 (20.20.20.2/24)  <--[20.20.20.0/24]-- SRX2

CentOS (syslog+Logstash) at 111.1.1.2/24 listens on UDP/5514
```

Traffic flow we generate:

* ICMP from SRX1 (`10.10.10.1`) to SRX2 outside (`20.20.20.1`), SNATed by SRX2.
* SRX2 streams `RT_FLOW` logs (structured-data format) to the CentOS collector.

---

## Generate Traffic

From SRX1:

```text
root@srx1> ping 20.20.20.1 source 10.10.10.1 size 900
PING 20.20.20.1 (20.20.20.1): 900 data bytes
908 bytes from 20.20.20.1: icmp_seq=0 ttl=64 time=1.399 ms
908 bytes from 20.20.20.1: icmp_seq=1 ttl=64 time=1.767 ms
908 bytes from 20.20.20.1: icmp_seq=2 ttl=64 time=1.714 ms
```

SRX2 confirms NATed sessions:

```text
root@srx2> show security flow session
Session ID: 11557, Policy name: ALLOW-OUT/4, Timeout: 4, Session State: Valid
  In: 10.10.10.1/43397 --> 20.20.20.1/10;icmp, If: ge-0/0/1.0, Pkts: 1, Bytes: 928
  Out: 20.20.20.1/10 --> 20.20.20.1/17783;icmp, If: .local..0, Pkts: 1, Bytes: 928
...
```

---

## SRX2 (DUT) Configuration

```text
set version 23.4R2-S3.10
set groups member0 system host-name srx2
set groups member0 system backup-router 10.49.31.254
set groups member0 interfaces fxp0 unit 0 family inet address 10.49.27.204/19
set apply-groups member0
set system ports console log-out-on-disconnect

# (Optional) local file match for ad-hoc troubleshooting
set system syslog file traffic-log any any
set system syslog file traffic-log match "RT_FLOW.*(SESSION_CLOSE|policy-name=\"ALLOW-OUT\")"

# Security log streaming → CentOS (UDP/5514)
set security log mode stream
set security log stream ngtest severity info
set security log stream ngtest format sd-syslog
set security log stream ngtest category flow
set security log stream ngtest host 111.1.1.2
set security log stream ngtest host port 5514
set security log stream ngtest source-address 111.1.1.1

# Address book
set security address-book global address INSIDE-SUBNET 10.10.10.0/24
set security address-book global address OUTSIDE-SUBNET 20.20.20.0/24

# Source NAT
set security nat source rule-set OUTBOUND from zone M-INTDMZ-DMZFW
set security nat source rule-set OUTBOUND to zone M-EXTINET-DMZFW
set security nat source rule-set OUTBOUND rule INSIDE-TO-OUTSIDE match source-address 10.10.10.0/24
set security nat source rule-set OUTBOUND rule INSIDE-TO-OUTSIDE match destination-address 20.20.20.0/24
set security nat source rule-set OUTBOUND rule INSIDE-TO-OUTSIDE then source-nat interface

# Policy (note: we enable both init & close here; Logstash drops init)
set security policies from-zone M-INTDMZ-DMZFW to-zone M-EXTINET-DMZFW policy ALLOW-OUT match source-address INSIDE-SUBNET
set security policies from-zone M-INTDMZ-DMZFW to-zone M-EXTINET-DMZFW policy ALLOW-OUT match destination-address OUTSIDE-SUBNET
set security policies from-zone M-INTDMZ-DMZFW to-zone M-EXTINET-DMZFW policy ALLOW-OUT match application any
set security policies from-zone M-INTDMZ-DMZFW to-zone M-EXTINET-DMZFW policy ALLOW-OUT then permit
set security policies from-zone M-INTDMZ-DMZFW to-zone M-EXTINET-DMZFW policy ALLOW-OUT then log session-init
set security policies from-zone M-INTDMZ-DMZFW to-zone M-EXTINET-DMZFW policy ALLOW-OUT then log session-close

# Zones and interfaces
set security zones security-zone M-INTDMZ-DMZFW host-inbound-traffic system-services ping
set security zones security-zone M-INTDMZ-DMZFW interfaces ge-0/0/1.0
set security zones security-zone M-EXTINET-DMZFW host-inbound-traffic system-services ping
set security zones security-zone M-EXTINET-DMZFW interfaces ge-0/0/2.0
set security zones security-zone M-EXTINET-SYSLOG host-inbound-traffic system-services all
set security zones security-zone M-EXTINET-SYSLOG host-inbound-traffic protocols all
set security zones security-zone M-EXTINET-SYSLOG interfaces ge-0/0/0.0

set interfaces ge-0/0/0 unit 0 family inet address 111.1.1.1/24  # log plane → CentOS
set interfaces ge-0/0/1 unit 0 family inet address 10.10.10.2/24  # inside
set interfaces ge-0/0/2 unit 0 family inet address 20.20.20.1/24   # outside
```

> **Recommendation:** for production volume control, log **only** `session-close` on the policy:
>
> ```
> set security policies ... then log session-close
> ```

---

## Collector (CentOS) – Logstash Pipeline

We ingest UDP/5514, parse Junos RFC5424 + the structured data, **drop session-create**, compute session start from `elapsed-time`, translate numerics to protocol names, and emit JSON lines.

**`/etc/logstash/conf.d/10-input-srx.conf`**

```conf
input {
  udp {
    id   => "srx-rtflow-udp"
    host => "0.0.0.0"
    port => 5514
    codec => plain { charset => "UTF-8" }
  }
}
```

**`/etc/logstash/conf.d/20-filter-srx.conf`**

```conf
filter {
  # Strip forwarder prefix like: "2025-...Z {ip=111.1.1.1} "
  mutate { gsub => [ "message", "^\S+\s+\{ip=[^}]+\}\s+", "" ] }

  # Parse RFC5424-ish header + Junos structured-data block
  grok {
    match => { "message" => [
      "^<%{NONNEGINT:syslog.pri}>%{NONNEGINT:syslog.version} %{TIMESTAMP_ISO8601:log_ts} %{HOSTNAME:host} %{WORD:app} %{DATA:procid} %{DATA:msgid} \[(?:junos@%{NOTSPACE:junos_sd_id}) (?<sd_block>.*)\]$",
      "^%{NONNEGINT:syslog.version} %{TIMESTAMP_ISO8601:log_ts} %{HOSTNAME:host} %{WORD:app} %{DATA:procid} %{DATA:msgid} \[(?:junos@%{NOTSPACE:junos_sd_id}) (?<sd_block>.*)\]$"
    ] }
    tag_on_failure => ["_rtflow_grok_fail"]
  }

  date { match => ["log_ts", "ISO8601"] }

  kv { source => "sd_block" target => "jf" trim_key => "\"" trim_value => "\"" remove_field => ["sd_block"] }

  mutate {
    rename => {
      "[jf][source-address]"        => "[source][ip]"
      "[jf][source-port]"           => "[source][port]"
      "[jf][destination-address]"   => "[destination][ip]"
      "[jf][destination-port]"      => "[destination][port]"
      "[jf][nat-source-address]"    => "[source][nat][ip]"
      "[jf][nat-source-port]"       => "[source][nat][port]"
      "[jf][protocol-id]"           => "[juniper][protocol_id]"
      "[jf][bytes-from-server]"     => "[network][bytes_from_server]"
      "[jf][elapsed-time]"          => "[juniper][elapsed_seconds]"
      "[jf][session-id]"            => "[juniper][session_id]"
    }
    convert => {
      "[source][port]"               => "integer"
      "[destination][port]"          => "integer"
      "[source][nat][port]"          => "integer"
      "[juniper][protocol_id]"       => "integer"
      "[network][bytes_from_server]" => "integer"
      "[juniper][elapsed_seconds]"   => "integer"
    }
    remove_field => ["event","log_ts","host","app","procid","msgid","junos_sd_id","syslog.pri","syslog.version","@version","tags","jf","message"]
  }

  # Keep CLOSE only (elapsed-time only exists on close)
  if ![juniper][elapsed_seconds] { drop {} }

  # Derive session start/end from elapsed-time
  ruby {
    code => '
      secs = event.get("[juniper][elapsed_seconds]")
      if secs
        end_ts = event.get("@timestamp").time
        event.set("[session][end]",   LogStash::Timestamp.new(end_ts))
        event.set("[session][start]", LogStash::Timestamp.new(end_ts - secs))
      end
    '
  }

  translate {
    source      => "[juniper][protocol_id]"
    target      => "[network][transport]"
    dictionary  => { "1" => "icmp" "6" => "tcp" "17" => "udp" }
    fallback    => "other"
  }

  # Keep only the fields you need
  prune {
    whitelist_names => [
      "^@timestamp$",
      "^session$",
      "^source$",
      "^destination$",
      "^juniper$",
      "^network$"
    ]
  }
}
```

**`/etc/logstash/conf.d/30-output-json.conf`**

```conf
output {
  file {
    path  => "/var/log/logstash/srx_rtflow.json"
    codec => json_lines { ecs_compatibility => disabled }
  }
}
```

### Validate and run

```bash
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
sudo systemctl restart logstash

# Confirm UDP listener
sudo ss -uanp | grep 5514

# Watch output
sudo tail -f /var/log/logstash/srx_rtflow.json
```

### Sample Output (Close-only JSON)

```json
{"source":{"port":43397,"ip":"10.10.10.1","nat":{"ip":"20.20.20.1","port":17783}},"destination":{"port":10,"ip":"20.20.20.1"},"@timestamp":"2025-09-03T11:24:12.193Z","juniper":{"session_id":"11557","elapsed_seconds":4,"protocol_id":1},"network":{"bytes_from_server":928,"transport":"icmp"},"session":{"start":"2025-09-03T11:24:08.193Z","end":"2025-09-03T11:24:12.193Z"}}
```

Fields we keep:

* `source.ip`, `source.port`, `source.nat.ip`, `source.nat.port`
* `destination.ip`, `destination.port`
* `juniper.session_id`, `juniper.protocol_id`, `juniper.elapsed_seconds`
* `network.transport`, `network.bytes_from_server`
* `session.start`, `session.end`, plus `@timestamp` (close time)

---

## Why log **close** only?

* **Volume**: halves (or better) the log rate vs logging both create+close.
* **Completeness**: close events contain **bytes** and **elapsed-time**; create events don’t.
* **Session start**: compute it precisely as `close_time - elapsed_time` without having to correlate two messages.

> If you want to reduce device CPU/traffic further, consider changing the policy to log **only** `session-close` on SRX. In this lab we left both enabled and dropped creates in Logstash to demonstrate filtering.

---

## Full Lifecycle (What We Verified)

1. **Connectivity/flow works** (SRX1 ↔ SRX2 outside) and shows as valid sessions on SRX2.
2. **Streaming logs** leave SRX2 (`111.1.1.1 → 111.1.1.2:5514/udp`).
3. **Collector is listening** on UDP/5514 and receives traffic.
4. **Logstash parsing**:

   * Strips the forwarder prefix.
   * GROKs the header, `kv` parses the Junos structured-data.
   * Renames/normalizes keys and converts types.
   * **Drops** session-create.
   * Computes session start from `elapsed-time`.
   * Emits compact JSON lines.

---

## Troubleshooting Notes

* **UDP listener**:

  ```bash
  sudo ss -uanp | grep 5514
  sudo tcpdump -ni <iface> udp port 5514
  ```
* **Validate config** before restarting Logstash:

  ```bash
  sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
  ```
* **Grok misses**: keep a side output for failures during tuning:

  ```conf
  output {
    if "_rtflow_grok_fail" in [tags] {
      file { path => "/var/log/logstash/srx_grok_fail.log" codec => line }
    }
  }
  ```
* **DNS on the collector** (if repos/tools install fails): set `/etc/resolv.conf` and ensure NetworkManager doesn’t overwrite it (e.g., `nmcli con mod "System eth0" ipv4.ignore-auto-dns yes` and set `ipv4.dns`).

---

## Appendix A — Sample Raw Messages (for reference)

**Session Created** (dropped in pipeline)

```
<14>1 2025-08-28T06:05:38.467-07:00 srx2 RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.129 source-address="10.10.10.1" ... protocol-id="1" policy-name="ALLOW-OUT" ...]
```

**Session Close** (parsed & kept)

```
<14>1 2025-08-28T06:05:41.665-07:00 srx2 RT_FLOW - RT_FLOW_SESSION_CLOSE [junos@2636.1.1.1.2.129 reason="response received" source-address="10.10.10.1" ... bytes-from-server="928" elapsed-time="3" ...]
```

---

## Appendix B — What You’ll See on the Collector

A rolling stream of **close** events only, for each ICMP echo/echo-reply exchange:

```json
{"source":{"port":43397,"ip":"10.10.10.1","nat":{"ip":"20.20.20.1","port":22938}},"destination":{"port":15,"ip":"20.20.20.1"},"@timestamp":"2025-09-03T11:24:16.188Z","juniper":{"session_id":"11567","elapsed_seconds":3,"protocol_id":1},"network":{"bytes_from_server":928,"transport":"icmp"},"session":{"start":"2025-09-03T11:24:13.188Z","end":"2025-09-03T11:24:16.188Z"}}
```

---

## Appendix C — Minimal Install (CentOS)

> Already installed in this lab (Logstash 8.x with bundled JDK). For completeness:

```bash
# Add Elastic repo (8.x), then:
sudo dnf install -y logstash
sudo systemctl enable --now logstash

# Place the three pipeline files under /etc/logstash/conf.d/
# Validate & restart:
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
sudo systemctl restart logstash
```

---

## Closing Thoughts

* **Close-only** gives you both **accurate session timing** and **volume control**.
* The pipeline is fast, readable, and easy to extend (e.g., add `bytes-from-client`, enrich with GeoIP, forward to ES, S3, or Kafka).
* Swap ICMP for TCP/UDP in your tests and the same pipeline will extract the right fields with no changes.

Happy parsing! 🧪📈

---
