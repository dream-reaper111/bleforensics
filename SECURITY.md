# Security

Analyze only evidence collected with authorization. HCI logs can contain sensitive identifiers and application data; reports include packet hex to preserve forensic context, so store them with the same care as originals and set an external retention policy. The CLI does not capture, transmit, decrypt, pair, or alter evidence. It does not claim an HCI log is a complete over-the-air record. Input size and packet lengths are bounded; output can still be large, so use controlled storage.
