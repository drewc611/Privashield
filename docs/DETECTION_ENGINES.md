# Detection Engines

PrivaShield Phase 2 introduces local, explainable detection engines that do not depend on cloud services and do not execute containment actions.

## DLP and Sensitive Data Classification

`POST /api/v1/dlp/classify` detects selected PII, PHI-context identifiers, financial identifiers, payment cards, and common credential forms. Credit-card candidates are Luhn validated. The API can return a redacted representation according to the requested permission tier.

Raw text is not written into the audit ledger. Only classification labels, counts, sensitivity, and permission tier are audited.

## Identity Anomaly Detection

`POST /api/v1/anomaly/evaluate` maintains a local in-memory baseline for recent identity observations. The first implementation detects:

- impossible travel using supplied latitude/longitude and elapsed time
- single large downloads
- ten-minute aggregate download bursts

PrivaShield does not call a third-party geolocation service. Location must come from an authorized upstream identity source.

## Ransomware Behavior Assessment

`POST /api/v1/ransomware/evaluate` scores file-system windows using operation rate, rename bursts, extension changes, high-entropy writes, and directory spread. The assessment is advisory and `enforced=false`.

This is behavioral detection, not a guarantee that unknown malware or ransomware will be detected.

## File Risk Analysis

`POST /api/v1/malware/evaluate` scores file metadata using locally supplied signature state, extension characteristics, double-extension disguises, and entropy. It does not upload files and does not claim to replace antivirus engines or sandboxing.

Future adapters may enrich this result with local YARA or ClamAV findings while preserving the same API contract.
