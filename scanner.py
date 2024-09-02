import concurrent.futures
from utils import run_tool
from config import TOOLS
from reputation_checker import check_reputation
from results_handler import handle_output, print_results, analyse_findings
from console_output import console
from rich.progress import Progress, BarColumn, TimeRemainingColumn

def scan(args):
    target = args.target
    
    # Prompt for reputation scan
    user_input = input("Do you want to perform a reputation scan? (yes/no): ")
    if user_input.lower() == "yes":
        api_key = input("Please enter your VirusTotal API key: ")
        reputation_score, report = check_reputation(target, api_key)
        print(f"Reputation Score: {reputation_score:.2f}. Full report: reputation.txt")
        if reputation_score >= 0.5:
            print(
                "The target has a high reputation score of {:.2f}. It might be useless to further continue.".format(
                    reputation_score
                )
            )
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

        print(f"\n[*] Starting vulnerability scan on {target}")
        if args.aggro:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(run_tool, tool, TOOLS[tool]["output"], target, args)
                    for tool in TOOLS
                    if tool != "custom"
                ]
                if args.custom and "custom" in TOOLS:
                    futures.append(
                        executor.submit(run_tool, "custom", TOOLS["custom"]["output"], target, args)
                    )
                for future in concurrent.futures.as_completed(futures):
                    progress.update(task, advance=1)
        else:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [
                    executor.submit(run_tool, tool, TOOLS[tool]["output"], target, args)
                    for tool in TOOLS
                    if tool != "custom"
                ]
                if args.custom and "custom" in TOOLS:
                    futures.append(
                        executor.submit(run_tool, "custom", TOOLS["custom"]["output"], target, args)
                    )
                for future in concurrent.futures.as_completed(futures):
                    progress.update(task, advance=1)

    for tool in TOOLS:
        if args.disable != tool and tool != "custom":
            outfile = TOOLS[tool]["output"]
            found_issues = handle_output(outfile)
            findings[tool] = found_issues

    print_results(findings)
    analyse_findings(findings, args)