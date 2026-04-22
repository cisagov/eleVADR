# Standard Python Libraries
import json
from pathlib import Path
import re
from typing import Dict, List, Optional
import urllib.request

IEEE_URL = "https://standards-oui.ieee.org/"
MAC_TO_COMPANY_RE = re.compile(r"([0-9A-F-]+)\s+\(hex\)\s+(.+?)\n", re.VERBOSE)


def download_ieee_data() -> str | None:
    """Download MAC OUI data from IEEE site"""
    req = urllib.request.Request(IEEE_URL, method="GET")  # nosec B310
    with urllib.request.urlopen(req) as response:  # nosec B310
        return response.read().decode("utf-8")  # nosec B310


def parse(text_str: str) -> dict:
    """Parse text data from IEEE"""
    matches = MAC_TO_COMPANY_RE.findall(text_str)
    result = {}
    for match in matches:
        value = match[1].strip().lower()
        if value[0:3] == "ge ":
            value = "general electric " + value[3:]
        result[match[0]] = value
    return result
    # return {match[0]: match[1].strip().lower() for match in matches}


if __name__ == "__main__":
    ieee_data = download_ieee_data()
    if ieee_data:
        parsed_data = parse(ieee_data)
        sorted_data = dict(sorted(parsed_data.items(), key=lambda item: item[1]))
        Path("data/latest_oui_lookup.json").write_text(
            json.dumps(sorted_data, indent=4, ensure_ascii=False), encoding="utf-8"
        )
