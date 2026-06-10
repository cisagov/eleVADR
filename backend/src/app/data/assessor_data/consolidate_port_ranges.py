"""Consolidate expanded port definitions into contiguous ranges."""

# Standard Python Libraries
import json
import sys
from pathlib import Path


def consolidate_port_ranges(input_json_path: Path, output_json_path: Path) -> None:
    """Consolidate matching per-port definitions back into ranges.

    Read a port-keyed JSON file, expand ranges while allowing later definitions
    to overwrite earlier ones, then merge consecutive ports with identical
    service definitions and write the result to a new JSON file.
    """
    print(f"Processing {input_json_path.name}...")

    with open(input_json_path) as f:
        raw_data = json.load(f)

    # Step 1: Expand all port ranges. Later definitions overwrite earlier ones.
    # Key: port_num (int), Value: service_data (dict)
    expanded_ports_data = {}

    for key, value in raw_data.items():
        try:
            if "-" in key:
                start_port_str, end_port_str = key.split("-")
                start_port = int(start_port_str)
                end_port = int(end_port_str)

                for port_num in range(start_port, end_port + 1):
                    # Allow overwrite: if port_num is already in expanded_ports_data,
                    # the current 'value' will replace the previous one.
                    expanded_ports_data[port_num] = value
            else:
                port_num = int(key)
                # Allow overwrite for single ports as well.
                expanded_ports_data[port_num] = value
        except ValueError as e:
            print(
                f"Warning: Skipping invalid port key '{key}' in {input_json_path.name} due to: {e}",
                file=sys.stderr,
            )
            # Do not exit, just skip this malformed entry
            continue
        except Exception as e:
            print(
                f"Unexpected error processing key '{key}' in {input_json_path.name}: {e}",
                file=sys.stderr,
            )
            sys.exit(1)  # Still exit on unexpected errors

    # Sort the expanded data by port number
    sorted_ports = sorted(expanded_ports_data.keys())

    # Step 2: Consolidate back into ranges
    consolidated_output = {}
    if not sorted_ports:
        print("No ports found to consolidate.")
        with open(output_json_path, "w") as f:
            json.dump({}, f, indent=2)
        return

    current_range_start = sorted_ports[0]
    current_service_def = expanded_ports_data[sorted_ports[0]]

    for i in range(len(sorted_ports)):
        port = sorted_ports[i]
        service_def = expanded_ports_data[port]

        # Check whether this port continues the current equivalent range.
        # Note: json.dumps is used to compare dictionaries as strings for deep equality
        if (
            i + 1 < len(sorted_ports)
            and sorted_ports[i + 1] == port + 1
            and json.dumps(service_def, sort_keys=True)
            == json.dumps(expanded_ports_data[sorted_ports[i + 1]], sort_keys=True)
        ):
            # Continue the current range
            pass
        else:
            # End of a range or a single port
            if current_range_start == port:
                # Single port
                consolidated_output[str(port)] = current_service_def
            else:
                # Range of ports
                consolidated_output[f"{current_range_start}-{port}"] = current_service_def

            # Start a new range for the next port, if available
            if i + 1 < len(sorted_ports):
                current_range_start = sorted_ports[i + 1]
                current_service_def = expanded_ports_data[sorted_ports[i + 1]]

    # Step 3: Write the consolidated data to the new JSON file
    with open(output_json_path, "w") as f:
        json.dump(consolidated_output, f, indent=2)

    print(f"Consolidated data written to {output_json_path.name}")


if __name__ == "__main__":
    base = Path(__file__).parent
    input_file = base / "port_risk_v2.json"
    output_file = base / "port_risk_v3.json"

    consolidate_port_ranges(input_file, output_file)
