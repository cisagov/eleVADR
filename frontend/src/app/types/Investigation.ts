export type InvestigationFilterKey = "service" | "port" | "deviceClass" | "risk" | "ip" | "connection" | "subnet" | "zeekState" | "manufacturer";

export interface InvestigationFilter {
  key: InvestigationFilterKey;
  value: string;
  label: string;
}

export type SelectedEntity =
  | { type: "device"; id: string }
  | { type: "service"; id: string }
  | { type: "connection"; id: string }
  | { type: "finding"; id: string };
