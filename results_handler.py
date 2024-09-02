import re
from config import SEVERITY_LEVELS
from console_output import console
from rich.table import Table
from ai_analysis import combine_reports_and_ask_gpt
from rich.console import Console
from report_generator import generate_html_report

cve_pattern = re.compile(r"CVE-\d+-\d+")
cves_found = set()



def handle_output(outfile):
    issues = []
    try:
        with open(outfile, "r") as f:
            for line in f:
                for level, keywords in SEVERITY_LEVELS.items():
                    for keyword in keywords:
                        if keyword.lower() in line.lower():
                            issues.append({"severity": level, "issue": line.strip()})
                            break

                if "weak" in line.lower() or "potential" in line.lower():
                    issues.append({"severity": "info", "issue": line.strip()})

    except FileNotFoundError:
        open(outfile, "w").close()
    return issues

def determine_severity(finding):
    severity = "info"

    for level, keywords in SEVERITY_LEVELS.items():
        for keyword in keywords:
            if keyword.lower() in finding.lower():
                return level

    match = cve_pattern.search(finding)
    if match:
        cve = match.group()
        cves_found.add(cve)
        return cve

    return severity

def print_results(findings):
    console = Console()
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Severity", style="dim", width=12)
    table.add_column("Issue", style="magenta")
    table.add_column("Affected Component")
    table.add_column("Remediation", justify="right")

    severity_styles = {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "bold cyan",
        "low": "bold green",
        "info": "dim",
    }

    for tool in findings:
        for issue in findings[tool]:
            severity = determine_severity(issue)
            severity_style = severity_styles.get(severity, "dim")
            table.add_row(severity, issue, tool, "Apply patch", style=severity_style)

    console.print(table)

    if cves_found:
        console.print("\nRelated CVEs:")
        for cve in cves_found:
            console.print(
                f"- {cve} - https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"
            )

def analyse_findings(findings, args):
    ai_response = ""
    if args.ai:
        ai_response = combine_reports_and_ask_gpt(findings, args)
        print("\nAI Response:")
        print(ai_response)

    # Generate HTML report
    html_report_filename = "vulnerability_scan_report.html"
    generate_html_report(findings, ai_response, html_report_filename)
    print(f"HTML report generated: {html_report_filename}")