import argparse
from utils import clear_terminal, check_tools, add_nse_to_nmap, save_configuration, load_configuration, add_custom_tool
from scanner import scan
from console_output import console, print_banner
import time

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner v1.7",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target", help="Target URL or IP address")
    parser.add_argument(
        "-a",
        "--aggro",
        action="store_true",
        help="Enable aggressive scan mode, which includes more thorough checks but may take longer.",
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
        "-pr",
        "--profile",
        choices=["friendly", "special", "hacker", "paranoid", "security_expert"],
        default="professional",
        help="Choose an AI profile: professional, casual, edgy, security_expert",
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
        "--nuclei-template",
        action="store_true",
        help="Specify a Nuclei template for scanning. Available templates: %(choices)s",
    )
    parser.add_argument(
        "--nuclei-template-path",
        help="Specify the path to a custom Nuclei template for scanning",
    )
    return parser.parse_args()

def main():
    clear_terminal()
    print_banner()
    
    args = parse_arguments()
    
    check_tools()
    
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
    
    start_time = time.time()
    scan(args)
    end_time = time.time()
    
    console.print(
        f"Scan completed in {end_time - start_time:.2f} seconds", style="bold cyan"
    )

if __name__ == "__main__":
    main()