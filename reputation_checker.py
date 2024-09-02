import json
import virustotal_python

def check_reputation(target, api_key):
    with virustotal_python.Virustotal(api_key) as vtotal:
        # Check domain reputation
        if "." in target:
            report = vtotal.request(f"domains/{target}")
        else:
            report = vtotal.request(f"ip_addresses/{target}")

        with open("reputation.txt", "w") as f:
            json.dump(report.data, f, indent=4)

        # Extract reputation score
        last_analysis_stats = report.data["attributes"]["last_analysis_stats"]
        malicious = last_analysis_stats["malicious"]
        harmless = last_analysis_stats["harmless"]
        total = malicious + harmless
        reputation_score = malicious / total if total > 0 else 0

        return reputation_score, report