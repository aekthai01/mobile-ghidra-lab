#!/usr/bin/env python3
import csv, json, re, sys
from collections import defaultdict, deque
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit("usage: v51_rank_targets.py <analysis-output-dir>")
root = Path(sys.argv[1])

def rows(name):
    p = root / name
    if not p.exists() or p.stat().st_size == 0:
        return []
    with p.open(encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f))

def canon(x):
    try:
        return f"{int((x or '').strip(), 16):08X}"
    except Exception:
        return (x or "").strip().upper()

metrics = rows("v4_function_metrics.csv")
calls = rows("callgraph.csv")
refs = rows("v51_function_refs.csv")
if not metrics:
    raise SystemExit("v4_function_metrics.csv missing")

by_entry = {canon(r.get("entry")): dict(r) for r in metrics if canon(r.get("entry"))}
callees, callers = defaultdict(set), defaultdict(set)
for r in calls:
    a, b = canon(r.get("caller_entry")), canon(r.get("callee_entry"))
    if a in by_entry and b in by_entry:
        callees[a].add(b); callers[b].add(a)

callback_edges = defaultdict(set)
for r in refs:
    src, dst = canon(r.get("from_function_entry")), canon(r.get("target_function_entry"))
    if src in by_entry and dst in by_entry and src != dst:
        typ = (r.get("reference_type") or "").upper()
        is_call = (r.get("is_call") or "").lower() == "true"
        if not is_call and any(k in typ for k in ("DATA","READ","WRITE","COMPUTED","PARAM","INDIRECTION")):
            callback_edges[src].add(dst)

def is_third(r):
    return (r.get("third_party") or "").lower() == "true" or bool((r.get("third_party_family") or "").strip())

def fname(r):
    return (r.get("name") or "").strip()

def seed_ok(e, r):
    n = fname(r)
    if is_third(r):
        return False
    if n in ("JNI_OnLoad","JNI_OnUnload"):
        return True
    if n.startswith("Java_"):
        return True
    if re.search(r"(?i)(^RegisterNatives$|Weave|gvraudio)", n):
        return True
    return False

seeds = {e for e,r in by_entry.items() if seed_ok(e,r)}
if not seeds:
    for e,r in by_entry.items():
        n = fname(r)
        if n and not n.upper().startswith(("FUN_","SUB_","LAB_")) and not is_third(r):
            seeds.add(e)
            if len(seeds) >= 8: break

def bfs(starts, graph, maxd):
    dist = {}
    q = deque((s,0) for s in starts)
    while q:
        e,d = q.popleft()
        if e in dist and dist[e] <= d: continue
        dist[e] = d
        if d >= maxd: continue
        for n in graph.get(e, ()):
            q.append((n,d+1))
    return dist

forward = bfs(seeds, callees, 6)
reverse = bfs(seeds, callers, 3)
cb_start = set(seeds) | {e for e,d in forward.items() if d <= 2}
callback_raw = bfs(cb_start, callback_edges, 4) if callback_edges else {}
callback = {e:d for e,d in callback_raw.items() if d > 0}
callback_forward = bfs({e for e,d in callback.items() if d <= 2}, callees, 4) if callback else {}

forward_weight = {0:30000,1:18000,2:9000,3:4500,4:2200,5:1000,6:400}
callback_weight = {1:15000,2:8000,3:3500,4:1200}
cbf_weight = {0:4000,1:6000,2:3000,3:1200,4:500}
reverse_weight = {0:0,1:900,2:350,3:100}

ranked = []
for e,r in by_entry.items():
    base = int(float(r.get("score") or 0))
    score = max(0, min(base, 9000))
    reasons = [x for x in (r.get("reasons") or "").split(";") if x and not x.startswith("distance:") and x != "seed"]
    if e in seeds:
        score += 50000; reasons.append("v51_seed")
    fd = forward.get(e)
    if fd is not None:
        score += forward_weight.get(fd,0); reasons.append(f"forward:{fd}")
    cd = callback.get(e)
    if cd is not None and e not in seeds:
        score += callback_weight.get(cd,0); reasons.append(f"callback:{cd}")
    cfd = callback_forward.get(e)
    if cfd is not None and e not in seeds and (fd is None or cfd < fd):
        score += cbf_weight.get(cfd,0); reasons.append(f"callback_forward:{cfd}")
    rd = reverse.get(e)
    if rd is not None and e not in seeds:
        score += reverse_weight.get(rd,0); reasons.append(f"reverse_context:{rd}")

    third = is_third(r)
    family = (r.get("third_party_family") or "").strip()
    if third:
        penalty = 18000
        if fd is not None and fd <= 1: penalty = 6500
        elif fd is not None and fd <= 2: penalty = 10000
        score -= penalty
        reasons.append(f"v51_third_party_penalty:{family or 'known'}")

    mode = r.get("recommended_mode") or "full"
    size = int(float(r.get("size_bytes") or 0))
    if size <= 32 and e not in seeds and fname(r):
        score -= 18000
        reasons.append("tiny_api_thunk")

    tier = "D"
    if e in seeds: tier = "A-seed"
    elif fd is not None and fd <= 1 and not third: tier = "A-forward"
    elif cd is not None and cd <= 1 and not third: tier = "A-callback"
    elif fd is not None and fd <= 3 and not third: tier = "B-forward"
    elif cfd is not None and cfd <= 2 and not third: tier = "B-callback-flow"
    elif not third and score >= 7000: tier = "C-interesting"
    elif third: tier = "Z-third-party"

    rr = dict(r)
    rr.update({
        "v51_score": score,
        "forward_distance": "" if fd is None else fd,
        "callback_distance": "" if cd is None else cd,
        "callback_forward_distance": "" if cfd is None else cfd,
        "reverse_context_distance": "" if rd is None else rd,
        "v51_priority_tier": tier,
        "v51_reasons": ";".join(reasons),
    })
    ranked.append(rr)

tier_order = {"A-seed":0,"A-forward":1,"A-callback":2,"B-forward":3,"B-callback-flow":4,"C-interesting":5,"D":6,"Z-third-party":7}
ranked.sort(key=lambda r:(tier_order.get(r["v51_priority_tier"],9), -int(r["v51_score"]), canon(r.get("entry"))))

selected = []
region_count = 0
third_count = 0
for r in ranked:
    if len(selected) >= 360: break
    third = is_third(r)
    tier = r["v51_priority_tier"]
    score = int(r["v51_score"])
    keep = tier.startswith(("A-","B-")) or (not third and score >= 4500) or (third and score >= 12000)
    if not keep: continue
    if score < 0 and not tier.startswith("A-"):
        continue
    if r.get("recommended_mode") == "region":
        if region_count >= 120 and not tier.startswith("A-"): continue
        region_count += 1
    if third:
        if third_count >= 12: continue
        third_count += 1
    selected.append(r)

selected.sort(key=lambda r:(
    tier_order.get(r["v51_priority_tier"],9),
    1 if r.get("recommended_mode") == "region" else 0,
    -int(r["v51_score"]), canon(r.get("entry"))
))

fields = list(ranked[0].keys())
with (root/"v51_function_metrics.csv").open("w",encoding="utf-8",newline="") as f:
    w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(ranked)
with (root/"v51_selected_functions.csv").open("w",encoding="utf-8",newline="") as f:
    w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(selected)

summary = {
    "seeds": len(seeds), "forward_reachable": len(forward), "callback_edges": sum(len(v) for v in callback_edges.values()),
    "callback_reachable": len(callback), "selected": len(selected),
    "selected_region": sum(1 for r in selected if r.get("recommended_mode")=="region"),
    "selected_third_party": sum(1 for r in selected if is_third(r)),
}
(root/"v51_ranking.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
with (root/"v51_ranking.md").open("w",encoding="utf-8") as w:
    w.write("# V5.1 directed execution-path ranking\n\n")
    w.write("Forward calls, reverse callers and function-pointer/data-reference callback evidence are scored separately. Third-party JNI names are not automatically treated as app seeds.\n\n")
    for k,v in summary.items(): w.write(f"- {k.replace('_',' ').title()}: **{v}**\n")
    w.write("\n| # | Tier | Score | Entry | Mode | Function | Forward | Callback | Third-party |\n|---:|---|---:|---|---|---|---:|---:|---|\n")
    for i,r in enumerate(selected[:100],1):
        w.write(f"| {i} | {r['v51_priority_tier']} | {r['v51_score']} | `{r.get('entry','')}` | {r.get('recommended_mode','')} | `{r.get('name','')}` | {r['forward_distance']} | {r['callback_distance']} | {r.get('third_party_family','')} |\n")
print(json.dumps(summary))
