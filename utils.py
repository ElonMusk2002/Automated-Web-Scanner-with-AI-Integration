import os
import ctypes
import json
import subprocess
from console_output import console

def clear_terminal():
    if os.name == "nt":  # Windows
        kernel32 = ctypes.windll.kernel32
        hStdOut = kernel32.GetStdHandle(-11)
        kernel32.SetConsoleTextAttribute(hStdOut, 0x07)
        kernel32.FillConsoleOutputCharacterA(
            hStdOut,
            b" ",
            ctypes.c_ulong(120 * 30),
            ctypes.pointer(ctypes.c_ulong(0)),
            ctypes.byref(ctypes.c_ulong(0)),
        )
    else:
        os.system("clear")

def check_tools():
    from config import TOOLS
    import shutil
    
    for tool, details in TOOLS.items():
        try:
            shutil.which(details["cmd"])
            console.print(f"[green]{tool} is installed ✓[/green]")
        except shutil.Error:
            console.print(
                f"[red]Tool '{tool}' is not installed. You can install it from https://www.kali.org/tools/{tool}[/red]"
            )
            exit(1)

def add_nse_to_nmap():
    from config import TOOLS
    
    use_nse = input(
        "Do you want to include NSE scripts in the Nmap scan? (yes/no): "
    ).lower()
    if use_nse not in ["yes", "no"]:
        console.print("[red]Invalid input. Please enter 'yes' or 'no'.[/red]")
        return
    if use_nse == "yes":
        console.print(
            "[bold green]Including NSE scripts in the Nmap scan...[/bold green]"
        )
        TOOLS["nmap"]["args"].append("--script=default")
    else:
        console.print(
            "[bold yellow]NSE scripts will not be included in the Nmap scan.[/bold yellow]"
        )

def save_configuration(config_name, args):
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
                console.print(
                    f"[red]Missing required key '{key}' in configuration file.[/red]"
                )
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

def add_custom_tool():
    from config import TOOLS
    
    try:
        custom_tool = input("Enter the name of your custom tool: ")
        if not custom_tool:
            print("Tool name cannot be empty.")
            return
        custom_cmd = input(f"Enter the command for {custom_tool}: ")
        if not custom_cmd:
            print("Command cannot be empty.")
            return
        custom_url = input(f"Enter the URL to scan with {custom_tool}: ")
        if not custom_url:
            print("URL cannot be empty.")
            return
        custom_output = input(f"Enter the desired output file name for {custom_tool}: ")
        if not custom_output:
            print("Output file name cannot be empty.")
            return
        TOOLS[custom_tool] = {
            "cmd": custom_cmd.split(),
            "args": [custom_url],
            "output": custom_output,
        }
    except Exception as e:
        print(f"Error adding custom tool: {e}")

def run_tool(tool, outfile, target, args):
    from config import TOOLS, NUCLEI_TEMPLATES
    
    try:
        if tool == "Nuclei":
            if args.nuclei_template_path:
                cmd = [
                    TOOLS[tool]["cmd"],
                    "-t",
                    args.nuclei_template_path,
                    "-o",
                    outfile,
                    "-u",
                    target,
                ]
            elif args.nuclei_template:
                template_args = NUCLEI_TEMPLATES[args.nuclei_template]
                cmd = [
                    TOOLS[tool]["cmd"],
                    *template_args,
                    "-o",
                    outfile,
                    "-u",
                    target,
                ]
            else:
                cmd = [
                    TOOLS[tool]["cmd"],
                    *TOOLS[tool]["args"],
                    "-u",
                    target,
                ]
        else:
            if tool == "ZAP":
                cmd = [TOOLS[tool]["cmd"]] + TOOLS[tool]["args"] + ["-quickurl", target]
            else:
                cmd = [TOOLS[tool]["cmd"]] + TOOLS[tool]["args"] + [target]
        print(f"Running {tool}...")
        if args.disable != tool:
            if tool == "custom":
                cmd = [TOOLS[tool]["cmd"]] + TOOLS[tool]["args"] + [target]
                print(f"Running {tool}...")
                with open(outfile, "w") as output_file:
                    subprocess.run(
                        cmd, stdout=output_file, stderr=output_file, text=True
                    )
            else:
                result = subprocess.run(cmd, capture_output=True, text=True)
                with open(outfile, "w") as output_file:
                    output_file.write(result.stdout)
                if result.returncode != 0:
                    console.print(
                        f"[red]Error running {tool}: {result.stderr}[/red]"
                    )
    except FileNotFoundError:
        console.print(
            f"[bold red]Error: The output file {outfile} does not exist. Please check the file path.[/bold red]"
        )
        if args.custom and tool == "custom":
            with open(outfile, "w"):
                print(f"Created {outfile} for the custom tool.")
        else:
            console.print(f"Tool {tool} is disabled.")
    except Exception as e:
        console.print(
            f"[bold red]An error occurred while running {tool}: {e}. Please ensure the tool is correctly installed and accessible.[/bold red]"
        )