"""
Converts assessor JSON data files to Parquet format for reduced disk footprint.

Run once after any migration scripts have been applied. The resulting .parquet
files are what the application loads at runtime.
"""

# Standard Python Libraries
import json
from pathlib import Path
import sys  # Import sys for stderr warnings

# Third-Party Libraries
import pandas as pd


def _port_sources(raw_data: dict[str, object], port_num: int) -> list[str]:
    """Return source keys that define a given port."""
    exact_matches = [key for key in raw_data if key == str(port_num)]
    range_matches: list[str] = []
    for key in raw_data:
        if "-" not in key:
            continue
        start_str, end_str = key.split("-", maxsplit=1)
        start_port = int(start_str)
        end_port = int(end_str)
        if port_num in range(start_port, end_port + 1):
            range_matches.append(key)
    return range_matches or exact_matches


def convert(json_path: Path, parquet_path: Path) -> None:
    """Convert a port-keyed JSON file into a Parquet dataset.

    Expand any port ranges, validate that each port is defined only once,
    and write the normalized result to Parquet.
    """
    with open(json_path) as f:
        raw_data = json.load(f)

    # Use a dictionary to store processed port data, allowing for duplicate detection
    processed_ports_data = {}  # Key: port_num (int), Value: service_data (dict)

    for key, value in raw_data.items():
        try:
            # Check if the key represents a port range (e.g., "49152-65535")
            if "-" in key:
                start_port_str, end_port_str = key.split("-")
                start_port = int(start_port_str)
                end_port = int(end_port_str)

                # Expand the range into individual port entries
                for port_num in range(start_port, end_port + 1):
                    if port_num in processed_ports_data:
                        raise ValueError(
                            f"Duplicate port mapping found for port "
                            f"{port_num} in {json_path.name}. Previously "
                            f"defined by '{_port_sources(raw_data, port_num)}', "
                            f"now by '{key}'."
                        )
                    processed_ports_data[port_num] = value
            else:
                # This is a single port or a non-range key
                port_num = int(key)  # Attempt to convert key to int
                if port_num in processed_ports_data:
                    raise ValueError(
                        f"Duplicate port mapping found for port {port_num} in "
                        f"{json_path.name}. Previously defined, now by '{key}'."
                    )
                processed_ports_data[port_num] = value
        except ValueError as e:
            # If key is not a valid integer or range,
            # or a duplicate is found, raise an error
            # For invalid keys, print a warning and skip,
            # for duplicates, re-raise the error
            if "Duplicate port mapping" in str(e):
                raise e  # Re-raise the specific duplicate error
            else:
                print(
                    f"Warning: Skipping invalid port key '{key}' in "
                    f"{json_path.name} due to: {e}",
                    file=sys.stderr,
                )
                continue  # Skip this entry if it's just an invalid key format

    # Convert the processed_ports_data dictionary
    # into a list of records for DataFrame creation
    records = []
    for port_num, data in processed_ports_data.items():
        record = {"port": port_num}
        record.update(data)  # Add all other fields from the service data
        records.append(record)

    # Create DataFrame from the list of records
    df = pd.DataFrame(records)

    # Ensure 'port' column is integer type
    # (should already be from above, but good for safety)
    df["port"] = df["port"].astype(int)

    df.to_parquet(parquet_path, engine="pyarrow", compression="snappy")

    json_size = json_path.stat().st_size
    parquet_size = parquet_path.stat().st_size
    reduction = (1 - parquet_size / json_size) * 100

    print(f"{json_path.name} -> {parquet_path.name}")
    print(
        f"  {json_size / 1024:.1f} KB -> {parquet_size / 1024:.1f} KB "
        f"({reduction:.1f}% reduction)"
    )


if __name__ == "__main__":
    base = Path(__file__).parent

    conversions = [
        ("ports.json", "ports.parquet"),
        ("port_risk_v3.json", "port_risk_v2.parquet"),
    ]

    for json_name, parquet_name in conversions:
        convert(base / json_name, base / parquet_name)
