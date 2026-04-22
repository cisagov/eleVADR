# Standard Python Libraries
import json

if __name__ == "__main__":
    with open("app/data/assessor_data/port_risk.json") as pr:
        port_risk = json.load(pr)
    with open("app/data/assessor_data/ports.json") as pf:
        ports = json.load(pf)

    for service in ports:
        it_or_ics = ports[service]["System Type"]
        if it_or_ics == "ICS":
            ports[service]["OT System Type"] = True
        else:
            ports[service]["OT System Type"] = False

        #     if service in port_risk and "Industrial Protocol" not in port_risk[service]["information_categories"]:
        #         port_risk[service]["information_categories"].append("Industrial Protocol")
        #     else:
        #         port_risk[service] = {
        #             "service": ports[service]["Service Name"],
        #             "description": ports[service]["Description"],
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
