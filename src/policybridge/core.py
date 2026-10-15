import copy
import itertools
import json
from collections import Counter


METHODS = [
    "policybridge",
    "source_only",
    "dual_execution",
    "per_request",
    "boolean_observation",
    "merged_errors",
    "no_version_binding",
]


def requests(domains):
    keys = sorted(domains)
    for values in itertools.product(*(domains[k] for k in keys)):
        yield {k: v for k, v in zip(keys, values) if v != "__MISSING__"}


def expression(node, request):
    op = node[0]
    if op == "present":
        return node[1] in request
    if op in ("and", "or"):
        values = [expression(child, request) for child in node[1:]]
        if op == "and" and False in values:
            return False
        if op == "or" and True in values:
            return True
        return None if None in values else (all(values) if op == "and" else any(values))
    if op == "not":
        value = expression(node[1], request)
        return None if value is None else not value
    if node[1] not in request:
        return None
    left, right = request[node[1]], node[2]
    if op == "eq":
        return type(left) is type(right) and left == right
    if op == "in":
        return any(type(left) is type(v) and left == v for v in right)
    if op == "ge":
        return (
            left >= right if type(left) is type(right) and isinstance(left, (int, float)) else None
        )
    raise ValueError("Unknown predicate operator")


def observe(policy, request):
    applies = []
    error = False
    for rule in policy["rules"]:
        matched = expression(rule["if"], request)
        error |= matched is None
        if matched:
            applies.append(rule)
    deny = [r for r in applies if r["effect"] == "Deny"]
    permit = [r for r in applies if r["effect"] == "Permit"]
    selected = deny or permit
    decision = (
        "Deny" if deny else "Indeterminate" if error else "Permit" if permit else "NotApplicable"
    )
    if error and not deny:
        selected = []
    obligations = []
    edges = set()
    for rule in selected:
        for obligation in rule.get("obligations", []):
            item = copy.deepcopy(obligation)
            item["args"] = {
                k: request[v[1:]] if isinstance(v, str) and v.startswith("$") else v
                for k, v in item.get("args", {}).items()
            }
            obligations.append(json.dumps(item, sort_keys=True))
        edges.update(tuple(edge) for edge in rule.get("precedence", []))
    changed = True
    while changed:
        added = {(a, d) for a, b in edges for c, d in edges if b == c}
        changed = not added <= edges
        edges |= added
    if any(a == b for a, b in edges):
        return {
            "decision": "Indeterminate",
            "error": "cyclic_obligation",
            "obligations": [],
            "precedence": [],
        }
    return {
        "decision": decision,
        "error": "missing_or_type" if error and not deny else None,
        "obligations": sorted(obligations),
        "precedence": sorted(map(list, edges)),
    }


def projection(outcome, method):
    if method == "boolean_observation":
        return outcome["decision"] == "Permit"
    if method == "merged_errors" and outcome["decision"] != "Permit":
        return "nonpermit"
    return outcome


def synthesize(case, method):
    universe = list(requests(case["domains"]))
    safe = []
    for request in universe:
        source = observe(case["source"], request)
        target = observe(case["target"], request)
        if projection(source, method) == projection(target, method):
            safe.append(request)
    return {
        "safe": safe,
        "bound_source": copy.deepcopy(case["source"]),
        "bound_target": copy.deepcopy(case["target"]),
        "revisions": copy.deepcopy(case["revisions"]),
    }


def route(case, artifact, request, method):
    bound = (
        artifact["revisions"] == case["current_revisions"]
        and artifact["bound_source"] == case["source"]
        and artifact["bound_target"] == case["target"]
    )
    if method == "no_version_binding":
        bound = True
    if method == "source_only":
        return observe(case["source"], request), "source"
    if method == "dual_execution":
        observe(case["target"], request)
        return observe(case["source"], request), "source"
    if method == "per_request":
        left, right = observe(case["source"], request), observe(case["target"], request)
        return (right, "target") if left == right else (left, "source")
    if bound and any(
        json.dumps(request, sort_keys=True) == json.dumps(r, sort_keys=True)
        for r in artifact["safe"]
    ):
        return observe(case.get("runtime_target", case["target"]), request), "target"
    return observe(case["source"], request), "source"


def generate(rng, count):
    audit = {"id": "audit", "args": {"object": "$object"}, "phase": "before", "recurrence": "once"}
    watermark = {
        "id": "watermark",
        "args": {"label": "restricted"},
        "phase": "before",
        "recurrence": "once",
    }
    for index in range(count):
        source = {
            "rules": [
                {
                    "if": ["and", ["eq", "qualified", True], ["eq", "class", "public"]],
                    "effect": "Permit",
                    "obligations": [audit],
                },
                {
                    "if": ["and", ["eq", "qualified", True], ["eq", "class", "restricted"]],
                    "effect": "Permit",
                    "obligations": [audit, watermark],
                    "precedence": [["audit", "watermark"]],
                },
            ]
        }
        target = copy.deepcopy(source)
        target["rules"][1]["obligations"] = [audit]
        target["rules"][1]["precedence"] = []
        domains = {
            "qualified": [True, False, None, "__MISSING__"],
            "class": ["public", "restricted"],
            "object": ["a", "b"],
        }
        universe = list(requests(domains))
        query = copy.deepcopy(rng.choice(universe))
        runtime = copy.deepcopy(target)
        changed = rng.random() < 0.2
        if changed:
            runtime["rules"][0]["obligations"] = []
        yield {
            "id": str(index),
            "family": "ordered-obligations",
            "source": source,
            "target": target,
            "runtime_target": runtime,
            "domains": domains,
            "query": query,
            "revisions": {"source": 1, "target": 1},
            "current_revisions": {"source": 1, "target": 2 if changed else 1},
        }


def run_case(case, method):
    artifact = synthesize(case, method)
    outcome, engine = route(case, artifact, case["query"], method)
    return {
        "outcome": outcome,
        "route": engine,
        "guard_cells": len(artifact["safe"]),
        "certificate_bytes": len(json.dumps(artifact).encode()),
    }


def score(case, result):
    expected = observe(case["source"], case["query"])
    actual = result["outcome"]
    missing = Counter(expected["obligations"]) - Counter(actual["obligations"])
    edges = {tuple(x) for x in expected["precedence"]} - {tuple(x) for x in actual["precedence"]}
    return {
        "full_outcome_mismatch": int(expected != actual),
        "obligation_loss": int(bool(missing or edges)) if expected["obligations"] else None,
        "certified_coverage": int(result["route"] == "target"),
        "source_call_ratio": int(result["route"] == "source"),
        "completion": int(actual == expected) if expected["decision"] == "Permit" else None,
        "certificate_bytes": result["certificate_bytes"],
        "guard_cells": result["guard_cells"],
        "legal_effects": int(actual == expected and actual["decision"] == "Permit"),
    }
