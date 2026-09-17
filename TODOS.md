# TODOS

## T-001: Bundled YARA rule starter library
**What:** Embed a curated set of YARA rules (EICAR, common RAT patterns, credential-dumping tool signatures) as `go:embed` assets under `internal/scanner/rules/`. User can override with `--yara` flag.
**Why:** The `-tags yara` scanner integration ships zero rules. Researchers without an existing rule library get no value from the YARA integration on day one. Open-source security tools require zero-setup value to gain adoption.
**Pros:** Immediate out-of-the-box value for researchers; demonstrates the YARA integration with real rules.
**Cons:** Embedded rules increase binary size; rules become stale and need maintenance.
**Context:** The v0.2.0 YARA scanner integration is complete but bring-your-own-rules. A starter library makes it immediately useful. Suggested sources: Abuse.ch, YARA-Forge community rules (permissive licenses only). Effort: human ~1 day / CC ~20 min.
**Depends on:** v0.2.0 shipped first (YARA scanner integration complete).
