#!/usr/bin/env python3
import json
import os
import subprocess
import statistics
import time

DIRECT_URL = "http://127.0.0.1:8080/search?q=bench"
PROXY_URL = "https://127.0.0.1:8443/search?q=bench"

def run_k6_script(script_file, env_vars):
    cmd = [
        "docker", "run", "--rm", "-i", "--net=host"
    ]
    for k, v in env_vars.items():
        cmd.extend(["-e", f"{k}={v}"])
    cmd.extend(["grafana/k6", "run", "-q", "-"])

    with open(script_file, "r") as f:
        script_code = f.read()

    proc = subprocess.run(cmd, input=script_code, text=True, capture_output=True)
    out = proc.stdout.strip()

    if not out:
        print("ERROR: Empty stdout from k6. Stderr:", proc.stderr[:300])
        return None

    try:
        data = json.loads(out)
        dur = data["metrics"]["http_req_duration"]["values"]
        rps = data["metrics"]["http_reqs"]["values"]["rate"]
        fails = data["metrics"]["http_req_failed"]["values"]["rate"] if "rate" in data["metrics"]["http_req_failed"]["values"] else 0
        
        p99 = dur.get("p(99)", dur.get("p(95)", dur.get("max", 0)))
        return {
            "p50": dur["med"],
            "p95": dur["p(95)"],
            "p99": p99,
            "rps": rps,
            "fail": fails
        }
    except Exception as e:
        print("Parse error:", e, "out head:", out[:100])
        return None

def summarize_reps(results):
    p50s = [r["p50"] for r in results]
    p95s = [r["p95"] for r in results]
    p99s = [r["p99"] for r in results]
    rpss = [r["rps"] for r in results]
    fails = [r["fail"] for r in results]
    return {
        "p50_med": statistics.median(p50s),
        "p50_min": min(p50s),
        "p50_max": max(p50s),
        "p95_med": statistics.median(p95s),
        "p95_min": min(p95s),
        "p95_max": max(p95s),
        "p99_med": statistics.median(p99s),
        "p99_min": min(p99s),
        "p99_max": max(p99s),
        "rps_med": statistics.median(rpss),
        "fail": max(fails)
    }

def main():
    print("=== 1. CONSTANT ARRIVAL RATE AT 2,500 REQ/S (3 Repetitions) ===")
    direct_reps = []
    proxy_reps = []

    print("Running Direct Target (3 reps)...")
    for i in range(3):
        print(f"  Direct Rep {i+1}...")
        r = run_k6_script("bench/k6_constant_rate.js", {"TARGET_URL": DIRECT_URL, "TARGET_RPS": "2500"})
        if r is None:
            print("Failed run!")
            return
        direct_reps.append(r)
        print(f"    p50={r['p50']:.2f}ms, p95={r['p95']:.2f}ms, p99={r['p99']:.2f}ms, rps={r['rps']:.1f}")
        time.sleep(1)

    print("Running Proxy Passthrough (3 reps)...")
    for i in range(3):
        print(f"  Proxy Rep {i+1}...")
        r = run_k6_script("bench/k6_constant_rate.js", {"TARGET_URL": PROXY_URL, "TARGET_RPS": "2500"})
        if r is None:
            print("Failed run!")
            return
        proxy_reps.append(r)
        print(f"    p50={r['p50']:.2f}ms, p95={r['p95']:.2f}ms, p99={r['p99']:.2f}ms, rps={r['rps']:.1f}")
        time.sleep(1)

    d_sum = summarize_reps(direct_reps)
    p_sum = summarize_reps(proxy_reps)

    print("\n--- Summary 2500 req/s ---")
    print("Direct Target:", d_sum)
    print("Proxy Passthrough:", p_sum)

    print("\n=== 2. CONCURRENCY STRESS TESTS (100, 500, 1000 VUs, 3 Repetitions each) ===")
    concurrency_results = {}
    for vus in [100, 500, 1000]:
        print(f"\n--- Testing Concurrency: {vus} VUs ---")
        d_v_reps = []
        p_v_reps = []
        for i in range(3):
            print(f"  Direct Rep {i+1} ({vus} VUs)...")
            r = run_k6_script("bench/k6_concurrency.js", {"TARGET_URL": DIRECT_URL, "VUS": str(vus)})
            if r is None:
                print("Failed run!")
                return
            d_v_reps.append(r)
            print(f"    p50={r['p50']:.2f}ms, p95={r['p95']:.2f}ms, p99={r['p99']:.2f}ms, rps={r['rps']:.1f}")
            time.sleep(1)

        for i in range(3):
            print(f"  Proxy Rep {i+1} ({vus} VUs)...")
            r = run_k6_script("bench/k6_concurrency.js", {"TARGET_URL": PROXY_URL, "VUS": str(vus)})
            if r is None:
                print("Failed run!")
                return
            p_v_reps.append(r)
            print(f"    p50={r['p50']:.2f}ms, p95={r['p95']:.2f}ms, p99={r['p99']:.2f}ms, rps={r['rps']:.1f}")
            time.sleep(1)

        concurrency_results[vus] = {
            "direct": summarize_reps(d_v_reps),
            "proxy": summarize_reps(p_v_reps)
        }

    out_file = "bench/matrix_results.json"
    res_payload = {
        "constant_2500": {"direct": d_sum, "proxy": p_sum},
        "concurrency": concurrency_results
    }
    with open(out_file, "w") as f:
        json.dump(res_payload, f, indent=2)

    print(f"\n\nFINAL RESULTS SAVED TO {out_file}:")
    print(json.dumps(res_payload, indent=2))

if __name__ == "__main__":
    main()
