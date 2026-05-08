import subprocess
import argparse
import requests
from rich.console import Console
import json

console = Console() 

parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
parser.add_argument("--target", required=True, help="Specify the domain to enumerate")
parser.add_argument("--api-key", required=True, help="Specify Claude API KEY")
args = parser.parse_args()

domain = args.target
api_key = args.api_key

def run_subfinder(domain):

    console.print(f"[bold cyan][*][/bold cyan] Scanning: [green]{domain}[/green]")

    try:
        subdomain = subprocess.run(["subfinder", "-d", domain], capture_output=True, text=True, timeout=60)

    except FileNotFoundError:
        console.print("[bold red][-] subfinder is not installed or not in PATH[/bold red]")
        exit(1)

    except subprocess.TimeoutExpired:
        console.print("[bold red][-] subfinder timed out[/bold red]")
        exit(1)    

    if subdomain.returncode != 0:
        console.print(f"[bold red][-] subfinder crashed: {subdomain.stderr}[/bold red]")

    if not subdomain.stdout.strip():
            console.print("[bold red][-] No output from subfinder[/bold red]")
            exit(1)

    subdomains = subdomain.stdout.strip().split("\n")  # turn output into a list
    
    if not subdomains or subdomains == [""]:
        console.print("[bold red][-] No subdomains found[/bold red]")
        exit(1)

    return subdomain

def run_httpx(subdomains):

    console.print(f"[bold cyan][*][/bold cyan] Checking alive subdomains...")

    subdomains_with_https = [f"https://{sub}" for sub in subdomains]

    try:
        alive = subprocess.run(["httpx", "-silent", "-sc", "-cl"], input="\n".join(subdomains_with_https), capture_output=True, text=True, timeout=120)
    
    except FileNotFoundError:
        console.print("[bold red][-] httpx is not installed or not in PATH[/bold red]")
        exit(1)

    except subprocess.TimeoutExpired:
        console.print("[bold red][-] httpx timed out[/bold red]")
        exit(1)

    if not alive.stdout.split():
        console.print("[bold red][-] No alive subdomains[/bold red]")
        exit(1)

    
    return alive

def analyze_with_ai(alive_list, api_key):

    console.print(f"[bold cyan][*][/bold cyan] Sending to AI for analysis...")
    
    try:
        response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",

        headers={
            "Authorization": f"Bearer {api_key}",
            "content-type": "application/json" 
        },
        json={
            "model": "llama-3.3-70b-versatile",
            "max_tokens": 1024,
            "messages": [
                {
                    "role": "user",
                    "content": f"""Here is a list of subdomains and their HTTP status codes.
Which ones look suspicious and why?
Rank them by risk level: Critical, High, Medium, Low.

    {json.dumps(alive_list, indent=2)}"""
                    }
                ]
            }

        )

        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]

        else:
            console.print(f"[bold red][-] Groq API error: {response.status_code}[/bold red]")
            return "AI analysis failed"

    except Exception as e:
        console.print(f"[bold red][-] AI request failed: {e}[/bold red]")
        return "AI analysis failed"
    # Step 4: save to json

def save_results(domain, subdomains, alive_list, ai_analysis):

    data = {
        "domain": domain,
        "total_subdomain": len(subdomains),
        "total_alive": len(alive_list),
        "subdomains": subdomains,
        "alive": alive_list,
        "ai_analysis": ai_analysis
    }


    filename = f"{domain}.json"

    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        console.print(f"[bold green][+][/bold green] Results saved to [yellow]{filename}[/yellow]")
    except Exception as e:
        console.print(f"[bold red][-] Failed to save file: {e}[/bold red]")
        exit(1)

def main():

    subdomain = run_subfinder(domain)
    subdomains = subdomain.stdout.strip().split("\n")
    console.print(f"[bold green][+][/bold green] Found [yellow]{len(subdomains)}[/yellow] subdomains")

    alive = run_httpx(subdomains)
    alive_list = alive.stdout.strip().split("\n")
    console.print(f"[bold green][+][/bold green] Found [yellow]{len(alive_list)}[/yellow] alive subdomains")

    ai_analysis = analyze_with_ai(alive_list, api_key)
    console.print(f"\n[bold green][+][/bold green] AI Analysis:\n[cyan]{ai_analysis}[/cyan]")

    save_results(domain, subdomains, alive_list, ai_analysis)

main()
