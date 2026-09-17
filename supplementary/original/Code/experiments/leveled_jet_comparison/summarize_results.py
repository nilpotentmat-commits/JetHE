"""Generate deterministic, non-overwriting reports from verified measured runs.

No measurements are generated here.  Every input must be a successful complete
manifest accepted by verify_results.py.  --check rerenders all four reports and
compares bytes without changing files.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import itertools
import json
from pathlib import Path
from typing import Any

import verify_results as verifier


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ARMS = (("BGV", "native"), ("BGV", "packed_terminal"),
        ("BFV", "native"), ("BFV", "packed_terminal"))
LAYOUT_NAMES = {"native": "native", "packed_terminal": "terminal packed"}
PHASES = ("encode", "encrypt", "eval", "decrypt", "decode", "end_to_end")
PARAMETERS = (
    "plaintext_modulus", "ring_dimension", "parameter_multiplicative_depth", "ctct_depth",
    "ciphertext_q_bits", "ciphertext_q_log2", "ciphertext_q_towers", "ciphertext_q_primes",
    "key_switching_p_bits", "key_switching_p_primes", "key_switching_qp_bits", "output_q_towers",
    "key_switching_technique", "secret_key_distribution", "scaling_technique",
    "encryption_technique", "multiplication_technique", "evaluation_points",
    "integer_low_coefficient_bound", "jobs_per_ciphertext_capacity", "ciphertext_batches",
    "input_ciphertexts", "output_ciphertexts", "ctct_calls_per_trial", "rotation_calls",
    "bootstrap_calls", "security_requested", "independent_security_certification",
)
RESOURCES = ("public_key_bytes", "relinearization_key_bytes", "input_bytes", "output_bytes",
             "peak_rss_bytes", "setup_ms", "precomputation_ms")


def relative_path(path: Path, root: Path) -> str:
    path = path.resolve()
    verifier.require(path.is_relative_to(root.resolve()), f"path is outside repository: {path}")
    return path.relative_to(root.resolve()).as_posix()


def binding(path: Path, root: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {"path": relative_path(path, root), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def number(value: float, digits: int = 3) -> str:
    return f"{value:.{digits}f}"


def latex(value: Any) -> str:
    substitutions = {"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$",
                     "#": r"\#", "_": r"\_", "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}",
                     "^": r"\textasciicircum{}"}
    return "".join(substitutions.get(character, character) for character in str(value))


def load_runs(paths: list[Path], root: Path) -> dict[str, Any]:
    verifier.require(len({path.resolve() for path in paths}) == len(paths), "duplicate parent manifest")
    parents, cases = [], []
    for run_index, path in enumerate(paths, 1):
        path = path.resolve()
        before = binding(path, root)
        checked = verifier.verify_manifest(path, root)
        manifest = verifier.read_json(path)
        verifier.require(binding(path, root) == before, "parent manifest changed during verification")
        parent = {**before, "run_index": run_index, "run_id": manifest["run_id"],
                  "case_count": checked["case_count"], "environment": manifest["environment"],
                  "started_utc": manifest.get("started_utc"),
                  "completed_utc": manifest.get("completed_utc"),
                  "elapsed_seconds": manifest.get("elapsed_seconds"),
                  "executable": manifest["executable"], "dependencies": manifest.get("dependencies", []),
                  "source_bindings": manifest["source_bindings"]}
        parents.append(parent)
        for case_binding, statistics in zip(manifest["cases"], checked["case_summaries"]):
            case_path = verifier.check_binding(case_binding, path.parent)
            raw = verifier.read_json(case_path)
            case = {
                "run_index": run_index, "run_id": manifest["run_id"],
                "manifest_path": before["path"], "case_binding": binding(case_path, root),
                "configuration": case_binding["configuration"],
                "scheme": raw["scheme"], "layout": raw["layout"], "schedule": raw["schedule"],
                "length": raw["length"], "mults": raw["mults"], "jobs": raw["jobs"],
                "fixture_seed": raw["fixture_seed"], "fixture_fnv1a64": raw["fixture_fnv1a64"],
                "repetitions": raw["repetitions"],
                "warmup_trials_excluded": raw["warmup_trials_excluded"],
                "verified_measured_trials": statistics["verified_measured_trials"],
                "verified_measured_output_coefficients": statistics["verified_measured_output_coefficients"],
                "timings_ms": statistics["timings_ms"],
                "throughput_jobs_per_second": statistics["throughput_jobs_per_second"],
                "parameters": {name: raw[name] for name in PARAMETERS},
                "resources": {name: raw[name] for name in RESOURCES},
                "openfhe_version": raw["openfhe_version"], "compiler": raw["compiler"],
                "hardware_threads": raw["hardware_threads"], "omp_num_threads": raw["omp_num_threads"],
                "process_elapsed_seconds": case_binding.get("process_elapsed_seconds"),
                "serialization": raw["serialization"],
            }
            cases.append(case)
    verifier.require(len({parent["run_id"] for parent in parents}) == len(parents), "duplicate run identifiers")
    # Preserve supplied manifest order; use a stable semantic order within each run.
    cases.sort(key=lambda c: (c["run_index"], c["length"], c["mults"], c["jobs"],
                             c["schedule"], c["scheme"], c["layout"], c["fixture_seed"]))
    return {
        "schema": "nilhe.leveled-library-comparison.report.v1",
        "status": "MEASURED_LEVELED_LIBRARY_COMPARISON_ONLY",
        "claim_boundary": {
            "verified_scope": "record integrity and finite-trial decoded plaintext correctness",
            "independent_security_certification": False, "failure_probability_certification": False,
            "exactjet_execution": False, "refresh_execution": False,
            "arbitrary_cyclotomic_security_transfer": False,
            "historical_execution_or_nonoverwrite_independently_proved": False,
            "warmup_outputs_independently_verified": False,
        },
        "report_source_bindings": [binding(Path(__file__).resolve(), root),
                                   binding(Path(verifier.__file__).resolve(), root)],
        "parent_manifests": parents,
        "case_count": len(cases),
        "verified_measured_trials": sum(c["verified_measured_trials"] for c in cases),
        "verified_measured_output_coefficients": sum(c["verified_measured_output_coefficients"] for c in cases),
        "statistical_convention": {
            "timings": "min, median and max of serialized measured samples; one warmup excluded",
            "end_to_end": "per-trial encode + encrypt + eval + decrypt + decode; excludes setup and precomputation",
            "decode": "coefficient recovery plus output-oracle comparison and associated bookkeeping",
            "throughput": "min, median and max of 1000 * jobs / per-trial milliseconds",
            "setup_and_precomputation": "one scalar per process; precomputation includes fixture/oracle construction and interpolation weights",
            "memory": "whole-process peak RSS, not isolated evaluation memory",
            "bytes": "sum of separate uncompressed library binary serializations",
        },
        "cases": cases,
    }


def main_grid(report: dict[str, Any]) -> tuple[int, dict[tuple[Any, ...], dict[str, Any]]]:
    expected = set(itertools.product((4, 8, 16), (1, 2, 4), (1, 16), ARMS))
    for parent in report["parent_manifests"]:
        index = {}
        for case in report["cases"]:
            if case["run_index"] == parent["run_index"] and case["schedule"] == "sequential":
                key = (case["length"], case["mults"], case["jobs"], (case["scheme"], case["layout"]))
                verifier.require(key not in index, "ambiguous main-grid case")
                index[key] = case
        if expected <= set(index):
            return parent["run_index"], index
    raise verifier.VerificationError("manuscript tables require one complete main grid: e=4/8/16, d=1/2/4, J=1/16, four arms")


def metric(case: dict[str, Any], phase: str = "eval", statistic: str = "median") -> float:
    return case["timings_ms"][phase][statistic]


def arm_name(arm: tuple[str, str]) -> str:
    return f"{arm[0]} {LAYOUT_NAMES[arm[1]]}"


def render_csv(report: dict[str, Any]) -> bytes:
    identity = ["run_index", "run_id", "scheme", "layout", "schedule", "length", "mults", "jobs",
                "fixture_seed", "fixture_fnv1a64", "repetitions", "verified_measured_output_coefficients",
                "openfhe_version", "compiler", "hardware_threads", "omp_num_threads", "process_elapsed_seconds"]
    timing_columns = [f"{phase}_ms_{statistic}" for phase in PHASES for statistic in ("median", "min", "max")]
    throughput_columns = [f"{phase}_jobs_per_second_{statistic}"
                          for phase in ("eval", "end_to_end") for statistic in ("median", "min", "max")]
    fields = identity + list(PARAMETERS) + list(RESOURCES) + timing_columns + throughput_columns + ["case_path", "case_sha256"]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for case in report["cases"]:
        row = {name: case[name] for name in identity}
        row.update(case["parameters"])
        row.update(case["resources"])
        for phase in PHASES:
            for statistic in ("median", "min", "max"):
                row[f"{phase}_ms_{statistic}"] = case["timings_ms"][phase][statistic]
        for phase in ("eval", "end_to_end"):
            for statistic in ("median", "min", "max"):
                row[f"{phase}_jobs_per_second_{statistic}"] = case["throughput_jobs_per_second"][phase][statistic]
        row.update(case_path=case["case_binding"]["path"], case_sha256=case["case_binding"]["sha256"])
        writer.writerow({key: json.dumps(value, separators=(",", ":")) if isinstance(value, list) else value
                         for key, value in row.items()})
    return stream.getvalue().encode("utf-8")


def table_begin(caption: str, label: str, columns: str, headers: list[str]) -> list[str]:
    return [r"\begin{table}[t]", r"\centering", r"\scriptsize", r"\renewcommand{\arraystretch}{1.08}",
            r"\caption{" + caption + "}", r"\label{" + label + "}",
            r"\begin{tabular}{@{}" + columns + r"@{}}", r"\toprule",
            " & ".join(headers) + r" \\", r"\midrule"]


def table_end() -> list[str]:
    return [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]


def render_latex(report: dict[str, Any], primary: int, grid: dict) -> str:
    lines = ["% Deterministically generated by summarize_results.py; do not hand-edit.",
             "% Parent manifests and exact generator hashes are in summary.json."]
    for parent in report["parent_manifests"]:
        lines.append(f"% Parent {parent['run_index']}: {parent['path']} SHA256={parent['sha256']}")
    versions = sorted({case["openfhe_version"] for case in report["cases"]})
    parent = next(p for p in report["parent_manifests"] if p["run_index"] == primary)
    environment = parent["environment"]
    cpu = environment.get("cpu", environment.get("processor", "processor recorded in manifest"))
    lines.extend(["", r"\paragraph{Measured results.}",
        f"The bound manifests contain {report['case_count']} measured cases and "
        f"{report['verified_measured_trials']} retained trials; an independent carryless-polynomial "
        f"checker verifies all {report['verified_measured_output_coefficients']} recorded output coefficients.",
        f"The runs use OpenFHE {latex(', '.join(versions))} on {latex(cpu)}, with "
        r"\texttt{OMP\_NUM\_THREADS=1}, dynamic OpenMP disabled, and one timed process at a time.",
        "Each case excludes one warmup.  Pipeline time is encoding, encryption, evaluation, "
        "decryption, and decoding; the decoding timer includes output-oracle checks.  "
        "Precomputation includes fixtures, plaintext oracles, and interpolation weights and is "
        "reported separately from setup and pipeline time.  Balanced circuits are executed "
        "serially, so these comparisons do not measure a CPU-parallel speedup.  These "
        "are finite-trial correctness and measured library results: the requested "
        r"\texttt{HEStd\_128\_classic} preset is not an independent security certification, "
        "and these runs execute neither ExactJet nor refresh.", ""])
    for jobs in (1, 16):
        caption = (f"Complete sequential grid with $J={jobs}$ independent jobs.  Each cell is "
                   "median evaluation / pipeline milliseconds.  The four arms return the same "
                   "$e$ binary coefficients; $d$ is the number of ciphertext multiplications "
                   "per job or packed batch.")
        lines += table_begin(caption, f"tab:leveled-measured-j{jobs}", "rr" + "r" * 4,
                             ["$e$", "$d$"] + [latex(arm_name(arm)) for arm in ARMS])
        for length, mults in itertools.product((4, 8, 16), (1, 2, 4)):
            values = [str(length), str(mults)]
            for arm in ARMS:
                case = grid[(length, mults, jobs, arm)]
                values.append(f"{number(metric(case))} / {number(metric(case, 'end_to_end'))}")
            lines.append(" & ".join(values) + r" \\")
        lines += table_end()
    lines += table_begin(
        "Representative sequential resource measurements at $e=16,d=4,J=16$.  "
        "$Q/QP$ gives actual modulus bit lengths; PK/RLK and input/output are MiB "
        "of separate uncompressed binary serializations.  RSS is whole-process peak MiB.  "
        "Setup/precomputation are single process measurements in milliseconds.",
        "tab:leveled-measured-resources", "lrrrrrr",
        ["Arm", "$N$", "$Q/QP$", "PK / RLK", "Input / output", "RSS", "Setup / precomp."])
    for arm in ARMS:
        case = grid[(16, 4, 16, arm)]
        params, resources = case["parameters"], case["resources"]
        mib = lambda key: number(resources[key] / 1048576)
        values = [latex(arm_name(arm)), str(params["ring_dimension"]),
                  f"{params['ciphertext_q_bits']} / {params['key_switching_qp_bits']}",
                  f"{mib('public_key_bytes')} / {mib('relinearization_key_bytes')}",
                  f"{mib('input_bytes')} / {mib('output_bytes')}", mib("peak_rss_bytes"),
                  f"{number(resources['setup_ms'])} / {number(resources['precomputation_ms'])}"]
        lines.append(" & ".join(values) + r" \\")
    lines += table_end()
    intervals = []
    for arm in ARMS:
        case = grid[(16, 4, 16, arm)]
        intervals.append(latex(arm_name(arm)) + " $[" + number(metric(case, "end_to_end", "min"))
                         + "," + number(metric(case, "end_to_end", "max")) + "]$")
    lines.extend([r"At $e=16,d=4,J=16$, the retained pipeline sample min--max intervals "
                  "in milliseconds are " + "; ".join(intervals) + ".  These are observed "
                  "ranges, not confidence intervals.", ""])
    balanced = [case for case in report["cases"] if case["run_index"] == primary
                and case["schedule"] == "balanced" and case["length"] == 16 and case["mults"] == 4]
    if balanced:
        lines += table_begin(
            "Sequential and balanced schedules at $e=16,d=4$.  Both request parameter "
            "depth four and use the same emitted parameter profile within each arm.  Actual "
            "multiplicative depths are four and three.  Values are median milliseconds; "
            "seq./bal. denotes sequential / balanced.",
            "tab:leveled-measured-balanced", "lrrr", ["Arm", "$J$", "Eval. seq. / bal.", "Pipeline seq. / bal."])
        for case in balanced:
            arm = (case["scheme"], case["layout"])
            sequential = grid[(16, 4, case["jobs"], arm)]
            values = [latex(arm_name(arm)), str(case["jobs"]),
                      f"{number(metric(sequential))} / {number(metric(case))}",
                      f"{number(metric(sequential, 'end_to_end'))} / {number(metric(case, 'end_to_end'))}"]
            lines.append(" & ".join(values) + r" \\")
        lines += table_end()
    supplements = [case for case in report["cases"] if case["run_index"] != primary]
    for run_index in sorted({case["run_index"] for case in supplements}):
        selected = [case for case in supplements if case["run_index"] == run_index]
        # Split large supplementary runs into page-friendly tables deterministically.
        for offset in range(0, len(selected), 18):
            part = offset // 18 + 1
            lines += table_begin(
                f"Supplementary measured run {run_index}, part {part}.  All entries are "
                "retained cases; seed is the public fixture seed.  D is actual circuit depth.  "
                "Evaluation/pipeline are median milliseconds and throughput is median pipeline jobs/s.",
                f"tab:leveled-measured-supplement-{run_index}-{part}", "lrrrrrrrr",
                ["Arm", "Seed", "$e$", "$d$", "$J$", "$D$", "Eval.", "Pipeline", "Jobs/s"])
            for case in selected[offset:offset + 18]:
                values = [latex(arm_name((case["scheme"], case["layout"]))), str(case["fixture_seed"]),
                          str(case["length"]), str(case["mults"]), str(case["jobs"]),
                          str(case["parameters"]["ctct_depth"]), number(metric(case)),
                          number(metric(case, "end_to_end")),
                          number(case["throughput_jobs_per_second"]["end_to_end"]["median"])]
                lines.append(" & ".join(values) + r" \\")
            lines += table_end()
    lines.extend(["Full per-case phase medians and ranges, setup and precomputation, key and "
                  "ciphertext bytes, actual modulus records, and throughput are retained in the "
                  "bound JSON/CSV reports.  The observations do not certify a failure probability, "
                  "a refresh procedure, or security for a different carrier or error distribution.", ""])
    return "\n".join(lines)


def render_markdown(report: dict[str, Any], primary: int, grid: dict) -> str:
    lines = ["# Measured leveled-library comparison", "",
             f"Verified {report['case_count']} cases, {report['verified_measured_trials']} retained trials, "
             f"and {report['verified_measured_output_coefficients']} recorded output coefficients.", "",
             "These reports check recorded integrity and finite-trial decoded correctness. "
             "The requested HEStd_128_classic library preset is not an independent security "
             "certification. No ExactJet or refresh execution is represented.", "",
             "Pipeline = encode + encrypt + evaluate + decrypt + decode for each trial; setup "
             "and precomputation are excluded and recorded separately. Decode includes output "
             "comparison/bookkeeping; precomputation includes fixture/oracle construction and "
             "interpolation weights. Balanced circuits run serially and do not measure a CPU-parallel "
             "speedup. Ranges are sample min/max, "
             "not confidence intervals. Throughput is computed per trial before summarizing. "
             "Peak RSS covers the whole process. Byte counts use separate uncompressed library "
             "serializations. One warmup is excluded; its outputs are not in the independent checks.", "",
             "## Bound runs", ""]
    for parent in report["parent_manifests"]:
        versions = sorted({c["openfhe_version"] for c in report["cases"] if c["run_index"] == parent["run_index"]})
        lines.extend([f"- Run {parent['run_index']}: `{parent['run_id']}`; {parent['case_count']} cases; "
                      f"OpenFHE {', '.join(versions)}; SHA-256 `{parent['sha256']}`.",
                      f"  Manifest: `{parent['path']}`.",
                      "  Environment: `" + json.dumps(parent["environment"], sort_keys=True, ensure_ascii=False) + "`."])
    for jobs in (1, 16):
        lines.extend(["", f"## Sequential grid, J = {jobs}", "",
                      "Cells are median evaluation / pipeline milliseconds.", "",
                      "| e | d | " + " | ".join(arm_name(arm) for arm in ARMS) + " |",
                      "|---:|---:|---:|---:|---:|---:|"])
        for length, mults in itertools.product((4, 8, 16), (1, 2, 4)):
            values = [str(length), str(mults)]
            for arm in ARMS:
                case = grid[(length, mults, jobs, arm)]
                values.append(f"{number(metric(case))} / {number(metric(case, 'end_to_end'))}")
            lines.append("| " + " | ".join(values) + " |")
    lines.extend(["", "## Every retained case", "",
                  "Timing cells show median [min, max] milliseconds. The CSV contains every phase, "
                  "resource, modulus and throughput field at full serialized precision.", "",
                  "| Run | Scheme/layout | Schedule | e | d | J | Seed | Evaluation | Pipeline | Pipeline jobs/s |",
                  "|---:|---|---|---:|---:|---:|---:|---:|---:|---:|"])
    for case in report["cases"]:
        values = [str(case["run_index"]), arm_name((case["scheme"], case["layout"])), case["schedule"],
                  str(case["length"]), str(case["mults"]), str(case["jobs"]), str(case["fixture_seed"])]
        for phase in ("eval", "end_to_end"):
            stats = case["timings_ms"][phase]
            values.append(f"{number(stats['median'])} [{number(stats['min'])}, {number(stats['max'])}]")
        values.append(number(case["throughput_jobs_per_second"]["end_to_end"]["median"]))
        lines.append("| " + " | ".join(values) + " |")
    lines.extend(["", "## Report source bindings", ""])
    for source in report["report_source_bindings"]:
        lines.append(f"- `{source['path']}`: SHA-256 `{source['sha256']}` ({source['bytes']} bytes).")
    lines.append("")
    return "\n".join(lines)


def render_reports(paths: list[Path], root: Path) -> dict[str, bytes]:
    report = load_runs(paths, root)
    primary, grid = main_grid(report)
    report["primary_grid_run_index"] = primary
    return {"summary.json": json_bytes(report), "all-cases.csv": render_csv(report),
            "report.md": render_markdown(report, primary, grid).encode("utf-8"),
            "leveled-results.tex": render_latex(report, primary, grid).encode("utf-8")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifests", nargs="+", type=Path)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        root = args.repo_root.resolve(strict=True)
        output = args.output.resolve()
        relative_path(output, root)
        reports = render_reports(args.manifests, root)
        if args.check:
            verifier.require(output.is_dir(), "report directory is missing")
            verifier.require({path.name for path in output.iterdir()} == set(reports),
                             "report directory inventory mismatch")
            for filename, expected in reports.items():
                verifier.require((output / filename).read_bytes() == expected,
                                 f"deterministic report mismatch: {filename}")
            print(f"PASS: deterministic report bytes verified in {output}")
        else:
            output.mkdir(parents=True, exist_ok=False)
            for filename, raw in reports.items():
                with (output / filename).open("xb") as stream:
                    stream.write(raw)
            print(f"CREATED: {len(reports)} reports in {output}")
        return 0
    except (OSError, verifier.VerificationError, KeyError, TypeError, ValueError) as error:
        print(f"FAIL: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
