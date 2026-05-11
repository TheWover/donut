from pathlib import Path

import donut


def main():
    repo_root = Path(__file__).resolve().parents[1]
    sample = repo_root / "DonutTest" / "rundotnet.exe"

    if not sample.is_file():
        raise SystemExit(f"missing smoke test input: {sample}")

    payload = donut.create(file=str(sample), params="", arch=2)
    if not isinstance(payload, (bytes, bytearray)) or len(payload) == 0:
        raise SystemExit("donut.create returned an empty payload")

    print(f"donut module: {donut.__file__}")
    print(f"payload size: {len(payload)}")


if __name__ == "__main__":
    main()
