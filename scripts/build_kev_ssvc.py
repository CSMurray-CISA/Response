#!/usr/bin/env python3
"""Build the staged KEV + SSVC dataset used by the static dashboard."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,19})$", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
CVSS_KEYS = (
    ("cvssV4_0", "4.0"),
    ("cvssV3_1", "3.1"),
    ("cvssV3_0", "3.0"),
    ("cvssV2_0", "2.0"),
    ("cvssV2", "2.0"),
)


def vulnrichment_relpath(cve_id: str) -> Path | None:
    match = CVE_RE.match(cve_id.strip())
    if not match:
        return None
    year, serial = match.groups()
    bucket = f"{int(serial) // 1000}xxx"
    return Path(year) / bucket / f"{cve_id.upper()}.json"


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def record_updated_at(record: dict[str, Any]) -> datetime | None:
    candidates = [parse_timestamp((record.get("cveMetadata") or {}).get("dateUpdated"))]
    cna, adps = containers(record)
    for container in [cna, *adps]:
        candidates.append(parse_timestamp((container.get("providerMetadata") or {}).get("dateUpdated")))
        for metric in container.get("metrics") or []:
            other = metric.get("other") if isinstance(metric, dict) else None
            if isinstance(other, dict):
                candidates.append(parse_timestamp((other.get("content") or {}).get("timestamp")))
    valid = [candidate for candidate in candidates if candidate]
    return max(valid) if valid else None


def unique_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        cleaned = value.strip()
        key = cleaned.casefold()
        if cleaned and key not in seen:
            seen.add(key)
            output.append(cleaned)
    return output


def containers(record: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    group = record.get("containers") or {}
    cna = group.get("cna") if isinstance(group.get("cna"), dict) else {}
    adps = [entry for entry in (group.get("adp") or []) if isinstance(entry, dict)]
    return cna, adps


def is_cisa_adp(container: dict[str, Any]) -> bool:
    metadata = container.get("providerMetadata") or {}
    name = str(metadata.get("shortName") or "").casefold()
    title = str(container.get("title") or "").casefold()
    return "cisa" in name or "cisa adp" in title or "vulnrichment" in title


def extract_ssvc(record: dict[str, Any]) -> dict[str, str]:
    cna, adps = containers(record)
    ordered = [item for item in adps if is_cisa_adp(item)] + [
        item for item in adps if not is_cisa_adp(item)
    ] + [cna]

    for container in ordered:
        for metric in container.get("metrics") or []:
            other = metric.get("other") if isinstance(metric, dict) else None
            if not isinstance(other, dict) or str(other.get("type") or "").casefold() != "ssvc":
                continue
            content = other.get("content") or {}
            options: dict[str, str] = {}
            for option in content.get("options") or []:
                if isinstance(option, dict):
                    options.update({str(key): str(value).casefold() for key, value in option.items()})
            return {
                "exploitation": options.get("Exploitation", "unknown"),
                "automatable": options.get("Automatable", "unknown"),
                "technicalImpact": options.get("Technical Impact", "unknown"),
                "version": str(content.get("version") or ""),
                "timestamp": str(content.get("timestamp") or ""),
                "source": "CISA Vulnrichment" if is_cisa_adp(container) else "CVE record",
            }
    return {}


def cwes_from_container(container: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for problem_type in container.get("problemTypes") or []:
        if not isinstance(problem_type, dict):
            continue
        for description in problem_type.get("descriptions") or []:
            if not isinstance(description, dict):
                continue
            direct = description.get("cweId") or description.get("id")
            if direct and CWE_RE.fullmatch(str(direct).strip()):
                values.append(str(direct).upper())
                continue
            text = " ".join(str(description.get(key) or "") for key in ("description", "value"))
            values.extend(match.upper() for match in CWE_RE.findall(text))
    return unique_strings(values)


def extract_cwes(record: dict[str, Any], kev_entry: dict[str, Any]) -> tuple[list[str], str]:
    cna, adps = containers(record)
    cna_values = cwes_from_container(cna)
    if cna_values:
        return cna_values, "CNA"

    for adp in [item for item in adps if is_cisa_adp(item)] + adps:
        values = cwes_from_container(adp)
        if values:
            return values, "CISA Vulnrichment" if is_cisa_adp(adp) else "ADP"

    kev_values = unique_strings(str(value).upper() for value in (kev_entry.get("cwes") or []))
    return kev_values, "KEV" if kev_values else ""


def cvss_from_container(container: dict[str, Any]) -> dict[str, Any]:
    metrics = [metric for metric in (container.get("metrics") or []) if isinstance(metric, dict)]
    for key, version in CVSS_KEYS:
        candidates: list[dict[str, Any]] = []
        for metric in metrics:
            value = metric.get(key)
            if not isinstance(value, dict) or value.get("baseScore") is None:
                continue
            try:
                score = float(value["baseScore"])
            except (TypeError, ValueError):
                continue
            candidates.append({
                "score": score,
                "version": str(value.get("version") or version),
                "severity": str(value.get("baseSeverity") or "").upper(),
                "vector": str(value.get("vectorString") or ""),
            })
        if candidates:
            return max(candidates, key=lambda item: item["score"])
    return {}


def extract_cvss(record: dict[str, Any]) -> tuple[dict[str, Any], str]:
    cna, adps = containers(record)
    score = cvss_from_container(cna)
    if score:
        return score, "CNA"
    for adp in [item for item in adps if is_cisa_adp(item)] + adps:
        score = cvss_from_container(adp)
        if score:
            return score, "CISA Vulnrichment" if is_cisa_adp(adp) else "ADP"
    return {}, ""


def build_entry(kev: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    cve_id = str(kev.get("cveID") or kev.get("cveId") or "").upper()
    ssvc = extract_ssvc(record)
    cwes, cwe_source = extract_cwes(record, kev)
    cvss, cvss_source = extract_cvss(record)

    exploitation = ssvc.get("exploitation") or "active"
    ssvc_source = ssvc.get("source") or "KEV"
    if exploitation == "unknown":
        exploitation = "active"
        ssvc_source = "KEV"

    return {
        "cve": cve_id,
        "vendor": str(kev.get("vendorProject") or "Unknown"),
        "product": str(kev.get("product") or "Unknown"),
        "cwes": cwes,
        "cweSource": cwe_source,
        "cvss": cvss,
        "cvssSource": cvss_source,
        "vulnerabilityName": str(kev.get("vulnerabilityName") or ""),
        "exploitation": exploitation,
        "technicalImpact": ssvc.get("technicalImpact") or "unknown",
        "automatable": ssvc.get("automatable") or "unknown",
        "ssvcSource": ssvc_source,
        "ssvcVersion": ssvc.get("version") or "",
        "ssvcTimestamp": ssvc.get("timestamp") or "",
        "dateAdded": str(kev.get("dateAdded") or ""),
        "dueDate": str(kev.get("dueDate") or ""),
        "knownRansomwareCampaignUse": str(kev.get("knownRansomwareCampaignUse") or "Unknown"),
        "shortDescription": str(kev.get("shortDescription") or ""),
        "requiredAction": str(kev.get("requiredAction") or ""),
        "notes": str(kev.get("notes") or ""),
    }


def write_sparse_paths(kev_path: Path, output_path: Path) -> int:
    payload = load_json(kev_path)
    paths = []
    for entry in payload.get("vulnerabilities") or []:
        cve_id = str(entry.get("cveID") or entry.get("cveId") or "")
        relative = vulnrichment_relpath(cve_id)
        if relative:
            paths.append(relative.as_posix())
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(sorted(set(paths))) + "\n", encoding="utf-8")
    return len(set(paths))


def build(kev_path: Path, vulnrichment_root: Path, output_path: Path) -> dict[str, Any]:
    payload = load_json(kev_path)
    entries: list[dict[str, Any]] = []
    records_found = 0
    source_updates = [parse_timestamp(payload.get("dateReleased"))]

    for kev in payload.get("vulnerabilities") or []:
        cve_id = str(kev.get("cveID") or kev.get("cveId") or "").upper()
        relative = vulnrichment_relpath(cve_id)
        record: dict[str, Any] = {}
        if relative:
            record_path = vulnrichment_root / relative
            if record_path.is_file():
                try:
                    record = load_json(record_path)
                    records_found += 1
                    source_updates.append(record_updated_at(record))
                except (OSError, json.JSONDecodeError):
                    record = {}
        entries.append(build_entry(kev, record))

    entries.sort(key=lambda item: (item["dateAdded"], item["cve"]), reverse=True)
    latest_source_update = max(update for update in source_updates if update)
    result = {
        "generatedAt": latest_source_update.isoformat().replace("+00:00", "Z"),
        "catalogVersion": payload.get("catalogVersion"),
        "catalogDateReleased": payload.get("dateReleased"),
        "count": len(entries),
        "coverage": {
            "vulnrichmentRecords": records_found,
            "officialSsvc": sum(1 for item in entries if item["ssvcSource"] == "CISA Vulnrichment"),
            "cvss": sum(1 for item in entries if item["cvss"]),
            "cwe": sum(1 for item in entries if item["cwes"]),
        },
        "sources": {
            "kev": "https://github.com/cisagov/kev-data",
            "vulnrichment": "https://github.com/cisagov/vulnrichment",
        },
        "vulnerabilities": entries,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, separators=(",", ":"), ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kev", type=Path, required=True, help="Path to known_exploited_vulnerabilities.json")
    parser.add_argument("--vulnrichment", type=Path, help="Root of a checked-out cisagov/vulnrichment repository")
    parser.add_argument("--output", type=Path, help="Destination staged JSON file")
    parser.add_argument("--write-sparse-paths", type=Path, help="Write the Vulnrichment paths required by this KEV catalog")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.write_sparse_paths:
        count = write_sparse_paths(args.kev, args.write_sparse_paths)
        print(f"Wrote {count} Vulnrichment sparse-checkout paths")
    if args.vulnrichment and args.output:
        result = build(args.kev, args.vulnrichment, args.output)
        print(f"Built {result['count']} KEV rows with {result['coverage']['officialSsvc']} official SSVC records")
    elif not args.write_sparse_paths:
        raise SystemExit("Provide --vulnrichment and --output, or --write-sparse-paths")


if __name__ == "__main__":
    main()
