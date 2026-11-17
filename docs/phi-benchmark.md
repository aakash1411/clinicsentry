# PHI Detection Benchmark

`clinicsentry phi-bench` measures how much PHI the firewall actually catches on
labelled text, so detector changes and policy choices can be judged on data.

```bash
clinicsentry phi-bench                                  # bundled synthetic notes
clinicsentry phi-bench --dataset corpus.jsonl --json    # your own JSONL
clinicsentry phi-bench --dataset brat_dir/ --label-map labels.yaml
clinicsentry phi-bench --policy policy.yaml --min-recall 0.95   # CI gate (exit 1)
clinicsentry phi-bench --detector local-llm             # regex + local LLM layer
```

## Metrics

All labels are normalised to the 18 HIPAA Safe Harbor categories
(45 CFR §164.514(b)(2)) before typed scoring.

| Metric | Meaning |
|---|---|
| Span recall | Gold identifiers whose every character is covered by some detection (of any type). This is what decides whether PHI leaves after redaction. |
| Leakage rate | `1 - span recall`: identifiers left fully or partly visible. |
| Character recall | Gold PHI characters covered by any detection. |
| Precision | Detections overlapping some gold identifier. |
| Strict typed F1 | Exact boundaries and matching category. |

Reports contain counts and rates only, never document text or span values, so
they can be shared from a PHI-bearing environment.

## Dataset formats

- **JSONL**: one document per line,
  `{"id": "...", "text": "...", "spans": [{"start": 0, "end": 8, "label": "PATIENT"}]}`.
- **BRAT standoff**: a directory of `<id>.txt` + `<id>.ann` pairs (the format
  i2b2/n2c2 2014 and many de-identification corpora are distributed in or
  converted to). Discontinuous spans are scored per fragment.

Common corpus labels (`PATIENT`, `DOCTOR`, `MEDICALRECORD`, `HEALTHPLAN`,
`IDNUM`, `LOCATION-OTHER`, ...) are mapped automatically; `PROFESSION`,
`ORGANIZATION`, `STATE` and `COUNTRY` are not Safe Harbor identifiers and are
ignored. Override or extend with `--label-map` (YAML `label: CATEGORY`, or
`label: null` to ignore).

The bundled dataset is 50 synthetic notes with no real PHI; it is a regression
floor, not evidence of real-world recall. Licensed corpora (n2c2, PhysioNet)
must be obtained under their data-use agreements and are never redistributed.

## Python API

```python
from clinicsentry import PHIFirewall
from clinicsentry.benchmarks import evaluate_phi, load_dataset

report = evaluate_phi(PHIFirewall(use_presidio=True), load_dataset("brat_dir/"))
print(report.to_markdown())
```

`evaluate_phi` accepts a `PHIFirewall`, any detector with `detect(text)`, or a
callable returning `(label, start, end)` tuples.

## Local LLM detector

`phi_firewall.detector_backend: local_llm` adds `LocalLLMDetector`, which asks
an OpenAI-compatible endpoint on the same host (Ollama, vLLM, llama.cpp) for
identifiers and maps them back to exact offsets. Configure with
`CLINICSENTRY_LLM_BASE_URL` (default `http://127.0.0.1:11434/v1`) and
`CLINICSENTRY_LLM_MODEL`. Non-loopback endpoints are refused unless
`allow_remote=True` is passed in code. Model output can only add redactions of
text that appears verbatim; on any backend error the regex layer still runs.
It adds a network round trip per scan, so use it for batch de-identification
or latency-tolerant paths.
