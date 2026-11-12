"""M4 Honeytokens: any use of a decoy key or decoy object."""

class Honeytoken:
    name = "M4"

    def __init__(self, cfg):
        self.keys = set(cfg["decoy_key_ids"])
        self.arns = set(cfg["decoy_arns"])

    def score(self, ev):
        hit = []
        if ev["key"] in self.keys:
            hit.append(f"decoy access key {ev['key']} was used")
        for r in ev["resources"]:
            if r in self.arns:
                hit.append(f"decoy object {r.split(':::')[-1]} was touched")
        if ev["identity"] == "pw25-backup-svc":
            hit.append("decoy identity pw25-backup-svc was used")
        return {"trip": 1 if hit else 0, "m": 0.95 if hit else 0.0, "reasons": hit}
