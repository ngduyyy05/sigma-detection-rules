"""Hunt pinned public EVTX telemetry and print only rule match counts."""

import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from urllib.parse import quote
from urllib.request import urlretrieve

DATASET = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/4ceed2f4706daf601c212a8f91c113dd85349a2c/"
RULES = Path(__file__).resolve().parents[1] / "rules"
CASES = {
    "Persistence/Network_Service_Guest_added_to_admins_4732.evtx": {
        "Member Added To Built-in Administrators": 2,
    },
    "Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx": {
        "Process Requesting Read Access to LSASS": 1,
    },
    "Lateral Movement/LM_tsclient_startup_folder.evtx": {
        "File Created In User Startup Folder": 1,
    },
    "Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx": {},
}


def main() -> int:
    """Run each archive in isolation, checking exact expected rules and counts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chainsaw", required=True, type=Path)
    parser.add_argument("--mapping", required=True, type=Path)
    args = parser.parse_args()
    chainsaw, mapping = args.chainsaw.resolve(), args.mapping.resolve()
    failed = False
    with TemporaryDirectory() as directory:
        workspace = Path(directory)
        for source, expected in CASES.items():
            evtx = workspace / Path(source).name
            urlretrieve(DATASET + quote(source), evtx)
            output = evtx.with_suffix(".json")
            subprocess.run(
                [chainsaw, "hunt", evtx, "-s", RULES, "--mapping", mapping, "--json",
                 "--output", output, "-q"],
                check=True,
            )
            hits = Counter(hit["name"] for hit in json.loads(output.read_text(encoding="utf-8")))
            passed = hits == expected
            failed |= not passed
            result = "PASS" if passed else "FAIL"
            print(f"{result} {evtx.name}: {dict(sorted(hits.items()))}")
            if not passed:
                print(f"Expected: {expected}")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
