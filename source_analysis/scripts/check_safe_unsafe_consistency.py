#!/usr/bin/env python3
"""
Validate total_safe_unsafe and vul_safe_unsafe against the row-level
* tables (function, unsafe_block) and *_fix tables (function_fix, unsafe_block_fix).

  Check A : total_safe_unsafe must EQUAL the aggregates of function + unsafe_block
            per (cve_id, hash).  (safe_func == #False, unsafe_func == #True, unsafe_block == COUNT)
  Check B : vul_safe_unsafe is fix-diff-derived, so each of its counts must be a SUBSET
            (<=) of the whole-repo / whole-fix-repo detail counts, on both sides.
  Check C : cross-table coverage (total rows missing detail rows / missing vul rows).

Usage: python check_safe_unsafe_consistency.py [path/to/CVEfixes.db]
Exit:  0 if all checks pass, 1 if any inconsistency is found.
"""
import argparse
import os
import sqlite3


def connect(path):
    uri = "file:" + os.path.abspath(path) + "?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    con.text_factory = str
    return con


def icast(v):
    try:
        return int(float(str(v)))
    except (TypeError, ValueError):
        return None


def counts_of(cur, table, unsafety=None):
    q = "SELECT cve_id, hash, COUNT(*) FROM %s WHERE 1=1" % table
    if unsafety is not None:
        q += " AND unsafety='%s'" % unsafety
    q += " GROUP BY cve_id, hash"
    return {(r[0], r[1]): r[2] for r in cur.execute(q)}


def check_total(cur):
    func_safe = counts_of(cur, "function", "False")
    func_uns = counts_of(cur, "function", "True")
    blocks = counts_of(cur, "unsafe_block")

    rows = cur.execute(
        "SELECT cve_id, hash, safe_func, unsafe_func, unsafe_block "
        "FROM total_safe_unsafe ORDER BY cve_id, hash"
    ).fetchall()
    print(f"== Check A: total_safe_unsafe vs function+unsafe_block (exact) == "
          f"[{len(rows)} rows]")
    bad_s = bad_u = bad_b = 0
    for c, h, sf, uf, ub in rows:
        ok = (icast(sf) == func_safe.get((c, h), 0),
              icast(uf) == func_uns.get((c, h), 0),
              icast(ub) == blocks.get((c, h), 0))
        bad_s += not ok[0]
        bad_u += not ok[1]
        bad_b += not ok[2]
        if not all(ok):
            print(f"  MISMATCH {c} {h}: table(safe={sf},unsafe={uf},block={ub}) "
                  f"detail(safe={func_safe.get((c,h),0)},unsafe={func_uns.get((c,h),0)},"
                  f"block={blocks.get((c,h),0)})")
    print(f"  summary -> safe_func {bad_s}/{len(rows)}, unsafe_func {bad_u}/{len(rows)}, "
          f"unsafe_block {bad_b}/{len(rows)}")
    return bad_s + bad_u + bad_b

def check_vul(cur):
    func_safe = counts_of(cur, "function", "False")
    func_uns = counts_of(cur, "function", "True")
    blocks = counts_of(cur, "unsafe_block")
    ff_safe = counts_of(cur, "function_fix", "False")
    ff_uns = counts_of(cur, "function_fix", "True")
    bf = counts_of(cur, "unsafe_block_fix")

    rows = cur.execute(
        "SELECT cve_id, hash, safe_func, unsafe_func, unsafe_block, "
        "safe_func_fix, unsafe_func_fix, unsafe_block_fix "
        "FROM vul_safe_unsafe ORDER BY cve_id, hash"
    ).fetchall()
    print(f"== Check B: vul_safe_unsafe vs * and *_fix (region <= whole repo) "
          f"[{len(rows)} rows]")
    tol = dict.fromkeys(["safe", "unsafe", "block", "fix_safe", "fix_unsafe", "fix_block"], 0)
    for c, h, sf, uf, ub, sff, uuf, ubf in rows:
        bads = []
        if icast(sf) > func_safe.get((c, h), 0):
            bads.append("vul.safe_func>whole.safe")
            tol["safe"] += 1
        if icast(uf) > func_uns.get((c, h), 0):
            bads.append("vul.unsafe_func>whole.unsafe")
            tol["unsafe"] += 1
        if icast(ub) > blocks.get((c, h), 0):
            bads.append("vul.unsafe_block>whole.block")
            tol["block"] += 1
        if icast(sff) > ff_safe.get((c, h), 0):
            bads.append("vul.safe_func_fix>fix.safe")
            tol["fix_safe"] += 1
        if icast(uuf) > ff_uns.get((c, h), 0):
            bads.append("vul.unsafe_func_fix>fix.unsafe")
            tol["fix_unsafe"] += 1
        if icast(ubf) > bf.get((c, h), 0):
            bads.append("vul.unsafe_block_fix>fix.block")
            tol["fix_block"] += 1
        if bads:
            print(f"  VIOLATION {c} {h}: {bads}\n"
                  f"     vul: {sf=} {uf=} {ub=} | fix: {sff=} {uuf=} {ubf=}\n"
                  f"     detail: safe={func_safe.get((c,h),0)} unsafe={func_uns.get((c,h),0)} "
                  f"block={blocks.get((c,h),0)} | fix safe={ff_safe.get((c,h),0)} "
                  f"fix unsafe={ff_uns.get((c,h),0)} fix block={bf.get((c,h),0)}")
    print("  summary violations -> " + ", ".join(f"{k}={v}" for k, v in tol.items()))
    return sum(tol.values())


def check_coverage(cur):
    print("== Check C: coverage ==")
    func_safe = counts_of(cur, "function", "False")
    func_uns = counts_of(cur, "function", "True")
    t_set = {(r[0], r[1]) for r in cur.execute("SELECT cve_id, hash FROM total_safe_unsafe")}
    v_set = {(r[0], r[1]) for r in cur.execute("SELECT cve_id, hash FROM vul_safe_unsafe")}

    no_detail = sum(1 for (c, h) in t_set if (c, h) not in func_safe and (c, h) not in func_uns)
    miss_vul = len(t_set - v_set)
    orphan_vul = len(v_set - t_set)
    print(f"  total rows with NO function detail rows : {no_detail}")
    print(f"  total (cve,hash) lacking a vul row        : {miss_vul}   (expected when diff/compile absent)")
    print(f"  vul (cve,hash) lacking a total row        : {orphan_vul}")
    # Missing vul rows are informational (only exist where a fix diff is extractable).
    return no_detail + orphan_vul


def main():
    ap = argparse.ArgumentParser(description="Validate aggregate unsafe tables vs detail tables.")
    ap.add_argument("db", nargs="?", default="CVEfixes.db", help="path to CVEfixes.db")
    args = ap.parse_args()

    con = connect(args.db)
    cur = con.cursor()

    errs = 0
    errs += check_total(cur)
    errs += check_vul(cur)
    errs += check_coverage(cur)

    print("\n" + ("PASS" if errs == 0 else f"FAIL - {errs} inconsistency(ies) found. See above."))
    con.close()
    raise SystemExit(0 if errs == 0 else 1)


if __name__ == "__main__":
    main()

