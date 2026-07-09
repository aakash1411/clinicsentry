# HIPAA Safe Harbor Coverage Matrix

The 18 identifier categories of 45 CFR §164.514(b)(2), and what the firewall
detects for each. "Deterministic" = regex/checksum on the default install;
"NER" = requires `[phi]` (Presidio) or a cloud backend
(`detector_backend: aws_comprehend_medical`).

| # | HIPAA identifier | Coverage | Detector label(s) |
|---|------------------|----------|-------------------|
| 1 | Names | NER only | Presidio `PERSON` / Comprehend `NAME` |
| 2 | Geographic subdivisions smaller than a state | Partial: precise ZIP+4 deterministic; street addresses NER | `ZIP`, NER |
| 3 | Dates (except year) | Deterministic (common formats) | `DATE` |
| 4 | Telephone numbers | Deterministic (US); `de_DE` pack for +49 | `PHONE`, `DE_PHONE` |
| 5 | Fax numbers | Deterministic (label-anchored) | `FAX` |
| 6 | Email addresses | Deterministic | `EMAIL` |
| 7 | Medical record numbers | Deterministic (label-anchored) | `MRN` |
| 8 | Health plan beneficiary numbers | Deterministic (label-anchored) | `MEMBER_ID` |
| 9 | Account numbers | Deterministic (label-anchored) | `ACCOUNT` |
| 10 | Certificate/license numbers | Partial: DEA + NPI deterministic | `DEA`, `NPI` |
| 11 | Vehicle identifiers incl. VIN / plates | VIN opt-in deterministic; plates not covered | `VIN` (opt-in) |
| 12 | Device identifiers and serial numbers | Deterministic (label-anchored) | `DEVICE_ID`, `UDI` |
| 13 | Web URLs | Deterministic | `URL` |
| 14 | IP addresses | Deterministic (IPv4) | `IP_ADDRESS` |
| 15 | Biometric identifiers | Not covered (binary payloads pass through opaque) | — |
| 16 | Full-face photographs | Not covered (out of scope for text middleware) | — |
| 17 | Social Security numbers | Deterministic | `SSN` |
| 18 | Any other unique identifying number | Extension point | `custom_detectors` / `register_detector` |

Non-US identifier packs (`phi_firewall.locales`): `en_GB` (`NHS_NUMBER` with
mod-11 checksum, `UK_NINO`, `IBAN` with mod-97), `en_CA` (`CA_SIN` with Luhn,
`IBAN`), `de_DE` (`DE_PHONE`, `IBAN`).

## Reading this honestly

- Deterministic detectors are precise but anchor-dependent: an MRN without an
  "MRN" label nearby is not caught. That is the deliberate trade against
  false positives — pair with NER for recall on free text.
- Categories 15–16 are binary-media problems; this library scans text and
  structured payloads. DICOM datasets are redacted at the metadata level.
- Category 18 is unbounded by definition; every deployment should register
  detectors for its proprietary formats (see docs/api.md for the extension
  API).
