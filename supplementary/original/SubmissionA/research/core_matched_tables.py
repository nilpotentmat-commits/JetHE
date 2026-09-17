"""Render/check paper tables from the completed matched readback; no HE or writes."""
import argparse
from hashlib import sha256
import json
import math
import re
from pathlib import Path
from statistics import median

ROOT = Path(__file__).resolve().parents[2]
PAPER = ROOT / "SubmissionA"
DATA = PAPER / "evidence/core-matched-complete-readback-v1.json"
CELLS = {
    "w1-l16-j1": ("W1",16,1,r"$P_{16,1}$"),
    "w1-l16-j16": ("W1",16,16,r"$P_{16,16}$"),
    "w1-l256-j1": ("W1",256,1,r"$P_{256,1}$"),
    "w1-l256-j16": ("W1",256,16,r"$P_{256,16}$"),
    "w2-shallow-l256-j16": ("W2 shallow",256,16,r"$S$"),
    "w2-deep-l256-j16": ("W2 deep",256,16,r"$D$"),
}


def load():
    result = json.loads(DATA.read_text(encoding="utf-8"))
    assert result["status"] == "PASS" and result["campaign_status"] == "COMPLETE"
    assert result["worker_statuses"] == {"PASS":114} and result["complete_verified_batches"] == 228
    assert result["native_prime_bits"] == 60 and result["native_gadget_width"] == 48
    assert result["editorial_protocol_erratum_bound"] and not result["security_128_qualified"]
    assert len(result["profiles"]) == 38 and len(result["endpoints"]) == 6
    assert all(row["complete_all_three"] for row in result["profiles"])
    return result


def compiler(row):
    c = row["config"]
    if c["compiler"] == "native":
        return "Native"
    if c["compiler"] == "b16":
        return "BSGS 13107"
    return str(c["m"])+(r"/"+c["policy"] if c["policy"] != "raw" else "")


def seconds(value):
    return format(value, ".6f" if value < 0.001 else ".4f" if value < 1 else ".3f")


def deep_receipts(data):
    endpoint = next(e for e in data["endpoints"] if e["cell"] == "w2-deep-l256-j16")
    return [PAPER / f'evidence/core-matched-v1-r{i}-{endpoint[key]}.json'
            for key in ("native_id", "primary_warm_endpoint") for i in range(3)]


def caption_first(tex):
    """Use the LNCS table-caption position without changing any table data."""
    def move(match):
        block = match.group(0)
        start = block.index(r"\caption{")
        pos = start + len(r"\caption{")
        depth = 1
        while depth:
            if block[pos] == "{" and block[pos-1] != "\\":
                depth += 1
            elif block[pos] == "}" and block[pos-1] != "\\":
                depth -= 1
            pos += 1
        caption = block[start:pos]
        without = block[:start] + block[pos:]
        split = without.index("\n") + 1
        return without[:split] + caption + "\n" + without[split:]
    return re.sub(r"\\begin\{table\}(?:\[[^\]]*\])?[\s\S]*?\\end\{table\}",
                  move, tex)


def render():
    data = load()
    rows = {r["config"]["id"]:r for r in data["profiles"]}
    main = [r"\begin{table}[t]",r"\centering\small",r"\setlength{\tabcolsep}{3pt}",r"\begin{tabular}{llrrrrr}",r"\toprule",
        r"Workload & $(L,J)$ & \multicolumn{2}{c}{Warm local (s)} & CRT/native & \multicolumn{2}{c}{First-use local (s)}\\",
        r" & & Native & CRT & ratio & Native & CRT\\",r"\midrule"]
    resources = [r"\begin{table}[t]",r"\centering\small",r"\setlength{\tabcolsep}{3pt}",r"\begin{tabular}{llrrr}",r"\toprule",
        r"Workload & CRT endpoint & Public keys (MiB) & Batch I/O (MiB) & Peak RSS (MiB)\\",r"\midrule"]
    endpoint_rows = []
    for end in data["endpoints"]:
        cell = end["cell"]
        assert end["status"] == "DESCRIPTIVE_FINITE_FAMILY_ONLY"
        family,length,jobs,label = CELLS[cell]
        native,crt = rows[end["native_id"]],rows[end["primary_warm_endpoint"]]
        endpoint_rows.append((end, label, native, crt))
        nt,ct = native["warm"]["local_seconds"]["median"],crt["warm"]["local_seconds"]["median"]
        main.append(f'{family} & $({length},{jobs})$ & {seconds(nt)} & {seconds(ct)} & {ct/nt:.2f} & '
                    f'{seconds(native["first_use_local_seconds"]["median"])} & {seconds(crt["first_use_local_seconds"]["median"])}'+r"\\")
        def pair(function, places=3):
            return " / ".join(format(function(r),f".{places}f") for r in (native,crt))
        key = pair(lambda r:r["public_keys_and_hints_bytes"]["median"]/2**20)
        traffic = pair(lambda r:(r["warm"]["input_bytes"]["median"]+r["warm"]["output_bytes"]["median"])/2**20)
        rss = pair(lambda r:r["process_peak_rss_mib"]["median"],1)
        resources.append(f'{label} & {compiler(crt)} & {key} & {traffic} & {rss}'+r"\\")
    main.extend([r"\bottomrule",r"\end{tabular}",
        r"\caption{Dense core: medians of three independent key setups, each with a first and a warm fresh-encryption batch. The CRT endpoint minimizes the observed warm median within the finite admitted family; its same profile supplies the first-use column. Ratios above one favor native. Local time charges all owners, full evaluation, serialization and recovery, excluding validation and network; first use additionally charges setup and keys. Ranges and every candidate appear in Appendix~\ref{app:core-matched-measurements}. No profile is qualified at 128 bits.}",
        r"\label{tab:main-core-results}",r"\end{table}"])
    resources.extend([r"\bottomrule",r"\end{tabular}",
        r"\caption{Resources for the same endpoints: each numeric pair is native / CRT. Public keys include every evaluation key. Batch I/O is serialized inputs plus outputs, not peak memory or measured traffic time. RSS covers all roles in one process. $P_{L,J}$ denotes W1, and $S,D$ denote shallow/deep W2 at $(256,16)$. Serialized input/output volumes and all candidates are reported separately in the supplement.}",
        r"\label{tab:main-core-resources}",r"\end{table}"])
    supplement = [r"\section{Complete matched dense-core measurements}",r"\label{app:core-matched-measurements}",
        r"The first two tables retain all 38 configurations, not only the main-text endpoints. Each row has three independently sampled key setups and two fresh-encryption batches per setup. Warm entries are median [minimum, maximum]; first use adds setup and keys to the first batch. Other resource entries are medians. Sizes are MiB and times seconds; $b_Q$ is the actual initial ciphertext-modulus bit length, not the library bit request. Public keys include hints; input and output volumes are separated. Native has 60-bit primes and gadget width 48. HElib uses its own exact published-modulus and key policy. Neither side has a 128-bit qualification.",
        r"Here $P_{L,J}$ denotes W1; $S$ and $D$ are shallow/deep W2 at $(256,16)$. A conductor without a suffix uses raw three-part delivery; suffixes $nn,ny,yn,yy$ are the deep policies of Appendix~\ref{app:terminal-core-admission}. The BSGS row is the independent dense anchor, not the primary terminal-CRT endpoint. The aggregate retains each combined-phase and byte sample; individual kernel and owner-subphase timers remain in its hash-bound \texttt{core-matched-v1-r*.json} receipts."]
    groups = [[r for r in data["profiles"] if r["config"]["cell"].startswith("w1-")],
              [r for r in data["profiles"] if r["config"]["cell"].startswith("w2-")]]
    for index,group in enumerate(groups):
        supplement.extend([r"\begin{table}[p]",r"\centering\scriptsize",r"\setlength{\tabcolsep}{3pt}",
            r"\begin{tabular}{llrrrrrrr}",r"\toprule",
            r"Cell & Compiler & $b_Q$ & Warm [min,max] & First use & Keys & Inputs & Outputs & RSS\\",r"\midrule"])
        for row in group:
            p = row["profile"]
            bits = 60*p["chain"][0] if row["config"]["compiler"] == "native" else math.prod(map(int,p["ciphertext_primes"])).bit_length()
            w = row["warm"]["local_seconds"]
            warm = f'{seconds(w["median"])} [{seconds(w["minimum"])},{seconds(w["maximum"])}]'
            cells = [CELLS[row["config"]["cell"]][3],compiler(row),str(bits),warm,
                seconds(row["first_use_local_seconds"]["median"]),
                f'{row["public_keys_and_hints_bytes"]["median"]/2**20:.3f}',
                f'{row["warm"]["input_bytes"]["median"]/2**20:.3f}',
                f'{row["warm"]["output_bytes"]["median"]/2**20:.3f}',
                f'{row["process_peak_rss_mib"]["median"]:.1f}']
            supplement.append(" & ".join(cells)+r"\\")
        supplement.extend([r"\bottomrule",r"\end{tabular}",
            r"\caption{All dense-product profiles and the BSGS anchor.}" if index == 0 else
            r"\caption{All shallow/deep profiles. Nine-component delivery without evaluation keys remains visible alongside switching alternatives.}",
            r"\label{tab:all-core-products}" if index == 0 else r"\label{tab:all-core-circuits}",r"\end{table}"])
    supplement.extend([
        r"\paragraph{Complete phase and throughput accounting.}",
        r"The following panels use the same six native/CRT endpoints as the main text. Each entry is native / CRT. Phase entries are medians across three warm batches; their sum need not equal the median complete local time. Residual plumbing time remains charged in the complete total. Evaluation includes all evaluator allocations, copies, alignment and switching, not only arithmetic kernels. Owner and recovery entries include the respective counting-sink serialization. Throughputs divide useful jobs or field coefficients by the warm local median; they are not steady-state or network measurements. Public setup and key generation/serialization are charged once per setup. Cache sizes count prepared-plaintext buffer payloads: native binary-coefficient bytearrays versus CRT uint16 evaluation arrays. They exclude container overhead, temporary buffers and fixed public tables; they are not peak RSS.",
        r"\begin{table}[p]",r"\centering\scriptsize",r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{lrrrr}",r"\toprule",
        r"Cell & Owner (s) & Evaluation (s) & Recovery (s) & Jobs/s\\",r"\midrule"])
    for end,label,native,crt in endpoint_rows:
        values = [label]
        for key in ("owners_seconds", "evaluation_seconds", "recipient_seconds"):
            values.append(" / ".join(seconds(r["warm"][key]["median"]) for r in (native,crt)))
        values.append(" / ".join(f'{end["jobs"]/r["warm"]["local_seconds"]["median"]:.2f}' for r in (native,crt)))
        supplement.append(" & ".join(values)+r"\\")
    supplement.extend([r"\bottomrule",r"\end{tabular}",
        r"\caption{Warm local phase medians and derived throughput for all six main-text endpoints.}",
        r"\label{tab:core-phase-breakdown}",r"\end{table}",
        r"\begin{table}[p]",r"\centering\scriptsize",r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{lrrrr}",r"\toprule",
        r"Cell & Public setup (s) & Key setup (s) & Cache (MiB) & Field coefficients/s\\",r"\midrule"])
    for end,label,native,crt in endpoint_rows:
        values = [label]
        for key in ("public_setup_seconds", "keys_and_serialization_seconds"):
            values.append(" / ".join(seconds(r[key]["median"]) for r in (native,crt)))
        values.append(" / ".join(f'{r["warm"]["prepared_plaintext_cache_bytes"]["median"]/2**20:.6f}' for r in (native,crt)))
        values.append(" / ".join(f'{end["jobs"]*end["length"]/r["warm"]["local_seconds"]["median"]:.2f}' for r in (native,crt)))
        supplement.append(" & ".join(values)+r"\\")
    supplement.extend([r"\bottomrule",r"\end{tabular}",
        r"\caption{Separately charged preparation, prepared-plaintext buffer payloads and useful-output throughput.}",
        r"\label{tab:core-setup-throughput}",r"\end{table}"])
    kernels = []
    for path in deep_receipts(data):
        assert sha256(path.read_bytes()).hexdigest() == data["sources_sha256"][path.relative_to(ROOT).as_posix()]
        kernels.append(json.loads(path.read_text())["result"]["batches"][1]["kernel_seconds"])
    supplement.extend([r"\begin{table}[p]",r"\centering\small",r"\begin{tabular}{lrr}",r"\toprule",
        r"Deep-anchor nested timer & Native (s) & CRT 13107/ny (s)\\",r"\midrule"])
    for label,native_key,crt_key in (
        ("Product/add versus multiplication", "multiply_and_add", "evaluation_multiply"),
        ("Independent rekey versus relinearization", "independent_rekey", "evaluation_relinearize"),
        ("Prime drop versus explicit modulus work", "prime_drop", "evaluation_modulus")):
        values = [median(k[native_key] for k in kernels[:3]),median(k[crt_key] for k in kernels[3:])]
        supplement.append(label+" & "+" & ".join(f"{v:.6f}" for v in values)+r"\\")
    supplement.extend([r"\bottomrule",r"\end{tabular}",
        r"\caption{Backend-specific nested timers, medians of three warm batches. These are non-exhaustive components of the complete evaluation times, not comparable primitive definitions or replacement totals. HElib multiplication also includes automatic modulus management; its separate addition timer has median "
        +f'{median(k["evaluation_add"] for k in kernels[3:]):.6f}'
        +r" seconds. Neither primary endpoint uses rotations.}",
        r"\label{tab:core-nested-timers}",r"\end{table}"])
    supplement.append(r"\clearpage")
    return dict(main=caption_first("\n".join(main)+"\n\n"+"\n".join(resources)+"\n"),
                supplement=caption_first("\n".join(supplement)+"\n"))


def check():
    rendered = render()
    paths = {"main":PAPER / "sections/evaluation.tex", "supplement":PAPER / "appendices/core-matched-measurements.tex"}
    for key,path in paths.items():
        assert " ".join(rendered[key].split()) in " ".join(path.read_text(encoding="utf-8").split()), path
    return dict(status="PASS",checked_profile_rows=38,checked_main_endpoints=6,
                security_128_qualified=False,readback_runs_encryption=False,
                sources_sha256={p.relative_to(ROOT).as_posix():sha256(p.read_bytes()).hexdigest()
                                for p in (Path(__file__),DATA,*paths.values(),*deep_receipts(load()))})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    args = parser.parse_args()
    print(json.dumps(check() if args.check else render(),indent=2))
