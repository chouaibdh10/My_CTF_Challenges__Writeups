#!/usr/bin/env python3
"""One-shot solver for Court / Hard (DNS exfil + steno translation)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from solve_pcap import (
    BASE_KEY_DEFAULT,
    decrypt_record,
    derive_xor_key,
    load_dns_exfil_hex_blobs,
    load_seed_from_eml,
    normalize_chord,
    reduce_bursts,
)
from translate_strokes import canonicalize_stroke, resolve_meta_tokens


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Solve the challenge end-to-end.")
    parser.add_argument("--pcap", required=True, help="Path to chall.pcapng")
    parser.add_argument("--eml", required=True, help="Path to email(1).eml")
    parser.add_argument("--dict", default="plover_main.json", help="Path to plover_main.json")
    parser.add_argument("--out-dir", default="build/solve", help="Output directory")
    parser.add_argument("--base-key", default=BASE_KEY_DEFAULT, help="Base XOR key")
    parser.add_argument("--flag-prefix", default="nexus", help="Flag prefix")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    pcap_path = Path(args.pcap).resolve()
    eml_path = Path(args.eml).resolve()
    dict_path = Path(args.dict).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    dictionary = json.loads(dict_path.read_text(encoding="utf-8"))

    seed = load_seed_from_eml(eml_path)
    key = derive_xor_key(args.base_key, seed)
    hex_blobs = load_dns_exfil_hex_blobs(pcap_path)

    decoded_records: list[dict[str, str]] = []
    for hex_blob in hex_blobs:
        record = decrypt_record(hex_blob, key)
        if not record:
            continue
        chord = normalize_chord(record["c"])
        if not chord:
            continue
        decoded_records.append({"c": chord, "t": record["t"]})

    reduced = reduce_bursts(decoded_records, window_ms=40)
    strokes = [item["chord"] for item in reduced]

    canonical = [canonicalize_stroke(stroke) for stroke in strokes]
    translated_tokens = [dictionary.get(stroke, f"[{stroke}]") for stroke in canonical]
    resolved = resolve_meta_tokens(translated_tokens)
    final_flag = f"{args.flag_prefix}{{{resolved}}}"

    (out_dir / "decoded_records.json").write_text(
        json.dumps(decoded_records, indent=2, ensure_ascii=True), encoding="utf-8"
    )
    (out_dir / "decoded_chords.json").write_text(
        json.dumps(reduced, indent=2, ensure_ascii=True), encoding="utf-8"
    )
    (out_dir / "strokes.txt").write_text("\n".join(strokes) + "\n", encoding="utf-8")
    (out_dir / "steno_strokes.txt").write_text("\n".join(canonical) + "\n", encoding="utf-8")
    (out_dir / "translated.txt").write_text(" ".join(translated_tokens) + "\n", encoding="utf-8")
    (out_dir / "final_flag.txt").write_text(final_flag + "\n", encoding="utf-8")

    print(f"[+] Seed: {seed}")
    print(f"[+] XOR key (hex): {key.hex()}")
    print(f"[+] DNS exfil candidates: {len(hex_blobs)}")
    print(f"[+] Decoded events: {len(decoded_records)}")
    print(f"[+] Reconstructed strokes: {len(strokes)}")
    print(f"[+] Final flag: {final_flag}")
    print(f"[+] Outputs in: {out_dir}")


if __name__ == "__main__":
    main()
