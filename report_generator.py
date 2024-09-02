from jinja2 import Environment, FileSystemLoader
from config import TOOLS, SEVERITY_LEVELS

def generate_html_report(findings, ai_response, output_filename):
    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("report_template.html")

    tool_outputs = {}
    for tool in findings:
        with open(TOOLS[tool]["output"], "r") as f:
            tool_outputs[tool] = f.read()

    report_data = []
    for tool, issues in findings.items():
        for issue in issues:
            severity = determine_severity(issue)
            report_data.append(
                {
                    "tool": tool,
                    "issue": issue,
                    "severity": severity,
                    "remediation": "Apply patch",
                }
            )

    html_content = template.render(
        findings=report_data,
        ai_response=ai_response,
        tool_outputs=tool_outputs,
        SEVERITY_LEVELS=SEVERITY_LEVELS,
    )

    with open(output_filename, "w") as f:
        f.write(html_content)

def determine_severity(issue):
    from results_handler import determine_severity
    return determine_severity(issue)