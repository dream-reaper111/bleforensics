# Architecture

Read-only bounded file import verifies format headers and record lengths before HCI metadata extraction. Events are sorted into a UTC timeline and grouped by HCI connection handle. The report preserves original evidence SHA-256 and source format. PCAP export is HCI H4 link type 187; it cannot preserve BTSnoop direction flags. The parser recognizes a small set of LE Meta and disconnect events plus ACL/L2CAP/ATT headers. It does not decode payload contents or infer security from missing events. File analysis has no runtime hardware dependency.
