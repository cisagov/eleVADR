"""Set the OT System Type flag based on legacy ICS classifications."""

# Standard Python Libraries
import json

if __name__ == "__main__":
    with open("app/data/assessor_data/port_risk.json") as pr:
        port_risk = json.load(pr)
    with open("app/data/assessor_data/ports.json") as pf:
        ports = json.load(pf)

    for service_name in ports:
        it_or_ics = ports[service_name]["System Type"]
        if it_or_ics == "ICS":
            ports[service_name]["OT System Type"] = True
        else:
            ports[service_name]["OT System Type"] = False

        #     if (
        #         service_name in port_risk
        #         and "Industrial Protocol"
        #         not in port_risk[service_name]["information_categories"]
        #     ):
        #         port_risk[service_name]["information_categories"].append(
        #             "Industrial Protocol"
        #         )
        #     else:
        #         port_risk[service_name] = {
        #             "service": ports[service_name]["Service Name"],
        #             "description": ports[service_name]["Description"],
        #             "information_categories": [
        #                 "Industrial Protocol"
        #             ],
        #             "risk_categories": [],
        # }
        # else:
        # continue

    # now dump
    with open("ports.json", "w") as prw:
        json.dump(ports, prw, indent=4)
