import subprocess
import argparse
import os
from dotenv import dotenv_values
import json
import time
from urllib.parse import urlparse

from colored import fg, bg, attr
from llamaapi import LlamaAPI
import virustotal_python
import concurrent.futures
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TimeRemainingColumn

from reportlab.lib.pagesizes import letter
from jinja2 import Environment, FileSystemLoader

import re

console = Console()

# Banner
console.print(
    """
              
              
              
[bold red]Automated Vulnerability Scanner v1.5[/bold red]
[blue]Created by {{name}}[/blue]
[blue]For xss.is[/blue]
              
_______           _______ _________ _______  _______             _______  ______     _______  _______  _______  _        _        _______  _______ 
(  ____ \|\     /|(  ____ \\__   __/(  ___  )(       )  |\     /|(  ____ \(  ___ \   (  ____ \(  ____ \(  ___  )( (    /|( (    /|(  ____ \(  ____ )
| (    \/| )   ( || (    \/   ) (   | (   ) || () () |  | )   ( || (    \/| (   ) )  | (    \/| (    \/| (   ) ||  \  ( ||  \  ( || (    \/| (    )|
| |      | |   | || (_____    | |   | |   | || || || |  | | _ | || (__    | (__/ /   | (_____ | |      | (___) ||   \ | ||   \ | || (__    | (____)|
| |      | |   | |(_____  )   | |   | |   | || |(_)| |  | |( )| ||  __)   |  __ (    (_____  )| |      |  ___  || (\ \) || (\ \) ||  __)   |     __)
| |      | |   | |      ) |   | |   | |   | || |   | |  | || || || (      | (  \ \         ) || |      | (   ) || | \   || | \   || (      | (\ (   
| (____/\| (___) |/\____) |   | |   | (___) || )   ( |  | () () || (____/\| )___) )  /\____) || (____/\| )   ( || )  \  || )  \  || (____/\| ) \ \__
(_______/(_______)\_______)   )_(   (_______)|/     \|  (_______)(_______/|/ \___/   \_______)(_______/|/     \||/    )_)|/    )_)(_______/|/   \__/
                                                                                                                                                    
          _______  _______    _________ _______                                                                                                     
|\     /|(  ____ \(  ____ \   \__   __/(  ____ \                                                                                                    
( \   / )| (    \/| (    \/      ) (   | (    \/                                                                                                    
 \ (_) / | (_____ | (_____       | |   | (_____                                                                                                     
  ) _ (  (_____  )(_____  )      | |   (_____  )                                                                                                    
 / ( ) \       ) |      ) |      | |         ) |                                                                                                    
( /   \ )/\____) |/\____) | _ ___) (___/\____) |                                                                                                    
|/     \|\_______)\_______)(_)\_______/\_______)                                                                                                    
                                                                                                                                                    

"""
)

TOOLS = {
    "nmap": {"cmd": "nmap", "args": ["-T4", "-F"], "output": "nmap.txt"},
    "Nuclei": {"cmd": "nuclei", "args": ["-t", "cves", "-o", "nuclei.txt", "-u"], "output": "nuclei.txt"},
    "sqlmap": {"cmd": "sqlmap", "args": ["--batch", "--random-agent", "--level", "5", "--risk", "3", "-u"], "output": "sqlmap.txt"},
    "sslscan": {"cmd": "sslscan", "args": ["--no-failed"], "output": "sslscan.txt"},
    "dnsrecon": {"cmd": "dnsrecon", "args": ["-d"], "output": "dnsrecon.txt"},
}

NUCLEI_TEMPLATES = {
    "cve": ["-t", "cves"],
    "common_web_vulnerabilities": ["-t", "common-web-vulnerabilities"],
}

def check_and_install_tools():
    for tool, details in TOOLS.items():
        try:
            subprocess.run([details["cmd"], "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            console.print(f"[green]{tool} is installed ✓[/green]")
        except subprocess.CalledProcessError:
            try:
                console.print(f"[yellow]Tool '{tool}' not found. Attempting to install...[/yellow]")
                subprocess.run(["sudo", "apt-get", "install", "-y", tool], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                console.print(f"[green]Tool '{tool}' has been installed successfully.[/green]")
            except subprocess.CalledProcessError as e:
                console.print(f"[red]Failed to install '{tool}': {e}[/red]")
                exit(1)

check_and_install_tools()

def add_nse_to_nmap():
    use_nse = input("Do you want to include NSE scripts in the Nmap scan? (yes/no): ").lower()
    if use_nse not in ['yes', 'no']:
        console.print("[red]Invalid input. Please enter 'yes' or 'no'.[/red]")
        return
    if use_nse == "yes":
        console.print("[bold green]Including NSE scripts in the Nmap scan...[/bold green]")
        TOOLS["nmap"]["args"].append("--script=default")
    else:
        console.print("[bold yellow]NSE scripts will not be included in the Nmap scan.[/bold yellow]")

parser = argparse.ArgumentParser(
    description="Web Vulnerability Scanner v1.1",
    formatter_class=argparse.RawTextHelpFormatter,
)
parser.add_argument("target", help="Target URL or IP address")

parser.add_argument(
    "-a", "--aggro", action="store_true",
    help="Enable aggressive scan mode, which includes more thorough checks but may take longer."
)
parser.add_argument(
    "-d",
    "--disable",
    metavar="TOOL",
    help="Disable a security tool (nmap,nikto,etc) (test)",
)
parser.add_argument(
    "-ai", "--ai", action="store_true", help="Enable ChatGPT integration"
)
parser.add_argument(
    "-c", "--custom", action="store_true", help="Add a custom tool (beta)"
)
parser.add_argument("-p", "--prompt", help="Custom AI prompt")
parser.add_argument(
    "-pr", "--profile",
    choices=["friendly", "special", "hacker", "paranoid"],
    default="professional",
    help="Choose an AI profile: professional, casual, edgy"
)
parser.add_argument(
    "-s",
    "--save-config",
    help="Save the current scan configuration with the given name",
)
parser.add_argument(
    "-l", "--load-config", help="Load a saved scan configuration with the given name"
)
parser.add_argument(
    "--nuclei-template", help="Specify a Nuclei template for scanning"
)

args = parser.parse_args()
target = urlparse(args.target).netloc

# REMOVE COMMENTS AND ADD YOUR PROXIES AND GO TO 148 LINE
# proxies = {
#     "http": "http://your-http-proxy",
#     "https": "https://your-https-proxy",
# }


cve_pattern = re.compile(r"CVE-\d+-\d+")

cves_found = set()


def save_configuration(config_name):
    config = {
        "target": args.target,
        "aggro": args.aggro,
        "disable": args.disable,
        "ai": args.ai,
        "custom": args.custom,
        "prompt": args.prompt,
        "profile": args.profile,
    }
    try:
        with open(f"{config_name}.json", "w") as config_file:
            json.dump(config, config_file)
        print(f"Configuration saved as {config_name}.json")
    except Exception as e:
        print(f"Error saving configuration: {e}")


def load_configuration(config_name):
    if not config_name.endswith(".json"):
        config_name += ".json"
    try:
        with open(config_name, "r") as config_file:
            config = json.load(config_file)
        required_keys = ["aggro", "ai", "profile"]
        for key in required_keys:
            if key not in config:
                console.print(f"[red]Missing required key '{key}' in configuration file.[/red]")
                exit(1)
        console.print(f"Configuration loaded from {config_name}")
        return config
    except FileNotFoundError:
        console.print(f"[red]Configuration file {config_name} not found.[/red]")
        exit(1)
    except json.JSONDecodeError:
        console.print(f"[red]Error loading configuration: Invalid JSON format.[/red]")
        exit(1)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        exit(1)


def generate_html_report(findings, ai_response, output_filename):
    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("report_template.html")

    tool_outputs = {}
    for tool in findings:
        with open(TOOLS[tool]["output"], "r") as f:
            tool_outputs[tool] = f.read()

    html_content = template.render(
        findings=findings, ai_response=ai_response, tool_outputs=tool_outputs
    )

    with open(output_filename, "w") as f:
        f.write(html_content)


class AIProfile:
    def __init__(self, name, prompt_modifier):
        self.name = name
        self.prompt_modifier = prompt_modifier


friendly_mentor_profile = AIProfile(
    "friendly_mentor",
    "You are a seasoned yet amicable cybersecurity mentor. You explain vulnerabilities and mitigations in a simple, easy-to-grasp manner, like guiding a mentee. Your warmth shows this is for learning, not lecturing.",
)

special_agent_profile = AIProfile(
    "special_agent",
    "You are a cyber intelligence special agent briefing high-level government officials on security threats. You analyze methodically, profiling adversary tradecraft, capabilities, and recommended counter-operations for the targeted organization.",
)

hacker_guru_profile = AIProfile(
    "hacker_guru",
    "You're the zen-like hacker guru, seeing vulnerabilities as puzzles to solve over cups of green tea. For each finding, you philosophize on root causes and ponderously guide the grasshopper to patches, wisdom, and improved security hygiene.",
)

paranoid_expert_profile = AIProfile(
    "paranoid_expert",
    "You're the paranoid cybersecurity expert seeing threats everywhere. Your analysis wildly speculates possible worst-case scenarios from the findings, while your mitigation advice involves heavy-handed measures like air-gapping, encryption, threat hunting operations centers, and resisting use of all technology.",
)

selected_profile = None

if args.profile == "friendly":
    selected_profile = friendly_mentor_profile
elif args.profile == "special":
    selected_profile = special_agent_profile
elif args.profile == "hacker":
    selected_profile = hacker_guru_profile
elif args.profile == "paranoid":
    selected_profile = paranoid_expert_profile

if args.profile is None:
    args.profile = "professional"

def run_tool(tool, outfile):
    if tool == "Nuclei" and args.nuclei_template:
        cmd = [TOOLS[tool]["cmd"], "-t", args.nuclei_template, "-o", outfile, "-u", target]
    else:
        cmd = [TOOLS[tool]["cmd"]] + TOOLS[tool]["args"] + [target]
    try:
        cmd = [TOOLS[tool]["cmd"]] + TOOLS[tool]["args"] + [target]
        print(f"Running {tool}...")
        if args.disable != tool:
            if tool == "custom":
                cmd = [TOOLS[tool]["cmd"]] + TOOLS[tool]["args"] + [target]
                print(f"Running {tool}...")
                with open(outfile, 'w') as output_file:
                    subprocess.run(cmd, stdout=output_file, stderr=output_file, text=True)
            else:
                cmd = [TOOLS[tool]["cmd"]] + TOOLS[tool]["args"] + [target]
                result = subprocess.run(cmd, capture_output=True, text=True)
                with open(outfile, "w") as output_file:
                    output_file.write(result.stdout)
                if result.returncode != 0:
                    console.print(f"[red]Error running {tool}: {result.stderr}[/red]")
    except FileNotFoundError:
        print(f"The output file {outfile} does not exist.")
        if args.custom and tool == "custom":
            with open(outfile, "w"):
                print(f"Created {outfile} for the custom tool.")
        else:
            print(f"Tool {tool} is disabled.")
    except Exception as e:
        print(f"An error occurred while running {tool}: {e}")

def handle_output(outfile):
    # Read the output file and extract any vulnerabilities found
    issues = []
    try:
        with open(outfile, "r") as f:
            for line in f:
                if "VULNERABLE" in line.upper():
                    issues.append(line.strip())
    except FileNotFoundError:
        print(f"The output file {outfile} does not exist. Creating it...")
        open(outfile, "w").close()
    return issues


def add_custom_tool():
    try:
        custom_tool = input("Enter the name of your custom tool: ")
        custom_cmd = input(f"Enter the command for {custom_tool}: ")
        custom_url = input(f"Enter the URL to scan with {custom_tool}: ")
        custom_output = input(f"Enter the desired output file name for {custom_tool}: ")
        TOOLS[custom_tool] = {"cmd": custom_cmd.split(), "args": [custom_url], "output": custom_output}
    except Exception as e:
        print(f"Error adding custom tool: {e}")

def check_reputation(target, api_key):
    with virustotal_python.Virustotal(api_key) as vtotal:
        # Check domain reputation
        if '.' in target:
            report = vtotal.request(f"domains/{target}")
        else:
            report = vtotal.request(f"ip_addresses/{target}")

        with open('reputation.txt', 'w') as f:
            json.dump(report.data, f, indent=4)

        # Extract reputation score
        last_analysis_stats = report.data['attributes']['last_analysis_stats']
        malicious = last_analysis_stats['malicious']
        harmless = last_analysis_stats['harmless']
        total = malicious + harmless
        reputation_score = malicious / total if total > 0 else 0

        return reputation_score, report
def scan():
    # Prompt for reputation scan
    user_input = input("Do you want to perform a reputation scan? (yes/no): ")
    if user_input.lower() == "yes":
        api_key = input("Please enter your VirusTotal API key: ")
        reputation_score, report = check_reputation(target, api_key)
        print(f"Reputation Score: {reputation_score:.2f}. Full report: reputation.txt")
        if reputation_score >= 0.5:
            print("The target has a high reputation score of {:.2f}. It might be useless to further continue.".format(reputation_score))
            user_input = input("Do you want to proceed with a full scan? (yes/no): ")
            if user_input.lower() != "yes":
                print("Exiting the scan process.")
                exit(0)

    findings = {}

    with Progress(
        "[progress.description]{task.description}",
        BarColumn(bar_width=40, complete_style="bright_green", finished_style="dim"),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[blue]Scanning...", total=len(TOOLS))

        print(fg("cyan") + f"\n[*] Starting vulnerability scan on {target}" + attr(0))
        if args.aggro:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(run_tool, tool, TOOLS[tool]["output"])
                    for tool in TOOLS
                    if tool != "custom"
                ]
                if args.custom and "custom" in TOOLS:
                    futures.append(
                        executor.submit(run_tool, "custom", TOOLS["custom"]["output"])
                    )
                for future in concurrent.futures.as_completed(futures):
                    progress.update(task, advance=1)
        else:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [
                    executor.submit(run_tool, tool, TOOLS[tool]["output"])
                    for tool in TOOLS
                    if tool != "custom"
                ]
                if args.custom and "custom" in TOOLS:
                    futures.append(
                        executor.submit(run_tool, "custom", TOOLS["custom"]["output"])
                    )
                for future in concurrent.futures.as_completed(futures):
                    progress.update(task, advance=1)

    for tool in findings:
        for issue in findings[tool]:
            cve = determine_severity(issue)
    print_results(findings)
    analyse_findings()


def analyse_findings():
    # Analyze the findings from the vulnerability scan
    findings = {}
    for tool in TOOLS:
        if args.disable != tool and tool != "custom":
            outfile = TOOLS[tool]["output"]
            found_issues = handle_output(outfile)
            findings[tool] = found_issues

    ai_response = ""
    if args.ai:
        ai_response = combine_reports_and_ask_gpt(findings)
        print("\nAI Response:")
        print(ai_response)

    # Generate HTML report
    html_report_filename = "vulnerability_scan_report.html"
    generate_html_report(findings, ai_response, html_report_filename)
    print(f"HTML report generated: {html_report_filename}")


def combine_reports_and_ask_gpt(findings):
    # Combine the reports from the vulnerability scan and ask the AI for recommendations
    api_key = os.getenv("LLAMA_API_KEY")

    if not api_key:
        api_key = input("Enter your Llama API key: ")
        # Save the API key in the .env file
        with open(".env", "a") as env_file:
            env_file.write(f"LLAMA_API_KEY={api_key}\n")
        os.environ.update(dotenv_values(".env"))
    llama = ConsultantAI(api_key)
    vulnerability_summary = ""
    for tool, issues in findings.items():
        vulnerability_summary += f"\n{tool.upper()} findings:"
        if issues:
            vulnerability_summary += "\nVulnerabilities detected:"
            for issue in issues:
                vulnerability_summary += f"\n - {issue}"
        else:
            vulnerability_summary += "\nNo vulnerabilities detected"

    default_prompt = """
    You are a penetration tester and security consultant. The vulnerability scan on [TARGET] has revealed the following findings:

    [TOOL] findings:
    - [VULNERABILITY_DESCRIPTION]
    - [ANOTHER_VULNERABILITY_DESCRIPTION]

    ...

    No vulnerabilities detected.

    Analyze the identified vulnerabilities and recommend possible variants or scenarios that might lead to additional security issues in the future. Provide insights into potential attack vectors, exploitation techniques, or misconfigurations that could be exploited by malicious actors.

    Consider the current security posture and suggest improvements to mitigate the identified vulnerabilities. Your recommendations should focus on enhancing the overall resilience of the target system.

    [USER_PROMPT]
    """

    prompt = (
        default_prompt.replace("[TOOL]", tool.upper())
        .replace("[TARGET]", target)
        .replace("[VULNERABILITY_DESCRIPTION]", "Sample vulnerability description")
        .replace(
            "[ANOTHER_VULNERABILITY_DESCRIPTION]",
            "Another sample vulnerability description",
        )
        .replace("[USER_PROMPT]", "")
    )

    if selected_profile:
        prompt += vulnerability_summary + selected_profile.prompt_modifier
    else:
        prompt += vulnerability_summary

    api_request_json = {
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }
    try:
        response = llama.generate_solution(api_request_json)
        return response
    except Exception as e:
        print("Error interacting with Llama API:", e)
        return "AI response could not be obtained due to an error."


class ConsultantAI:
    def __init__(self, api_key):
        self.llama = LlamaAPI(api_key)

    def generate_solution(self, api_request_json):
        try:
            response = self.llama.run(api_request_json)
            message = response.json()["choices"][0]["message"]["content"]
            return message
        except Exception as e:
            raise RuntimeError(f"Error interacting with Llama API: {e}")


SEVERITY_LEVELS = {
    "critical": ["remote code execution", "sql injection"],
    "high": ["xss", "broken auth"],
    "medium": ["info disclosure", "csrf"],
    "low": ["clickjacking", "ssl issues"],
}


def determine_severity(finding):
    # Determine the severity level of a vulnerability based on keywords in the finding

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
    # Print the results of the vulnerability scan
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
        "info": "dim"
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


if __name__ == "__main__":
    start_time = time.time()
    if args.custom:
        console.print("[bold green]Adding a custom tool...[/bold green]")
        add_custom_tool()
    if args.save_config:
        save_configuration(args.save_config)
    if args.load_config:
        loaded_config = load_configuration(args.load_config)
        if loaded_config:
            for key, value in loaded_config.items():
                setattr(args, key, value)
    add_nse_to_nmap()
    scan()
    end_time = time.time()
    console.print(f"Scan completed in {end_time - start_time:.2f} seconds", style="bold cyan")