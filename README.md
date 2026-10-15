# PolicyBridge

Implementation of **Certified partial migration of authorization decisions and obligations**.

Finite-domain implementation of full typed outcomes, mandatory obligation multiplicity, precedence closure, certified request regions, version binding and exact source fallback.

## Install

Use Python 3.11 or newer.

```bash
git clone https://github.com/Hqa77880011/PolicyBridge.git
cd PolicyBridge
python -m venv .venv
```

Activate with `source .venv/bin/activate` on Linux/macOS or `.venv\Scripts\Activate.ps1` in PowerShell.

```bash
python -m pip install -e .
```

## Prepare the workload

```bash
python -m policybridge prepare --count 200 --seed 17 --output data/workload.jsonl
```

The seeded generator constructs finite scenarios from the formal problem. Independently generated or recorded cases may be imported with the same JSONL schema.

`source` and `target` contain rules with typed predicate expressions and Permit/Deny effects. Predicates support present, eq, in, ge, and/or/not. Rules may carry obligation objects and precedence edges. `domains` declares the complete finite request domain; `__MISSING__` omits a field. `query` is the runtime request, with bound and current revision maps.

## Execute and compare

```bash
python -m policybridge run --data data/workload.jsonl --output runs/main
python -m policybridge suite --data data/workload.jsonl --output runs/comparison
```

`--methods` selects one or more method names. There are no learned parameters or model training in these finite algorithms.

`policybridge` compiles safe requests; `source_only` executes the source; `dual_execution` runs both with source authority; `per_request` compares full observations on demand. `boolean_observation`, `merged_errors` and `no_version_binding` are the representation and binding ablations.

## Metrics and plots

Full outcome mismatch, source-obligation-conditioned obligation loss, target coverage, source-call ratio, authorized completion, guard size, certificate serialization size and runtime.

Each method writes `records.jsonl` and `metrics.json` under its output subdirectory. Conditional rates omit cases outside their denominator. Summary fields include means, sample standard deviations, P50/P95/P99 and usable sample counts. Independent scoring runs after the method timer. RSS includes the process runtime; serialized sizes measure JSON bytes.

```bash
python -m policybridge plot --inputs runs/comparison/policybridge --output figures
```

Supply multiple method directories after `--inputs` for comparison. Plotting writes `summary.csv` and metric PNGs.

## Implementation conventions

Finite-domain exhaustive certification replaces SMT. Guards are exact request cells and preserve missing/null distinctions. The rule interpreter implements deny-overrides with explicit errors and nonapplicability; adapters for arbitrary XACML/Cedar syntax are outside this JSON language. Compilation is included in per-case kernel timing; online routing can also be called separately via `synthesize` and `route`.


## Uncertainty and paired comparisons

```bash
python -m policybridge.statistics --records runs/main/policybridge/records.jsonl --output results/intervals.json
```

Supply --reference with a matched record file for paired differences. Resampling uses independent case IDs, or explicit cluster IDs when provided. Repeated observations from one source unit must share cluster. Zero-event bounds refer to an event in an independent cluster.
