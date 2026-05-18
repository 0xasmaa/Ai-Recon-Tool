import subprocess
import argparse
import requests
from rich.console import Console
import re
import json

console = Console() 

parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
parser.add_argument("--target", required=True, help="Specify the domain to enumerate")
parser.add_argument("--api-key", required=True, help="Specify Groq API KEY")
args = parser.parse_args()

domain = args.target
api_key = args.api_key

def run_subfinder(domain):

    console.print(f"[bold cyan][*][/bold cyan] Scanning: [green]{domain}[/green]")

    try:
        subdomain = subprocess.run(["subfinder", "-d", domain], capture_output=True, text=True, timeout=120)

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

    try:
        alive = subprocess.run(["httpx", "-silent", "-sc", "-tech-detect", "-follow-redirects"], input="\n".join(subdomains), capture_output=True, text=True, timeout=120)
    
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

def parse_httpx_output(alive_list):
    alive_url = []

    for line in alive_list:
        line = line.strip()
        if not line:
            continue

        clean = re.sub(r"\x1b\[[0-9;]*m|\[[0-9;]*m", "", line)

        match = re.match(r"(https?://\S+)\s+\[(\d+)\](?:\s+\[(.*?)\])?", clean)
        if match:
            url = match.group(1)
            status = int(match.group(2))
            tech = match.group(3) if match.group(3) else "unknown"

            alive_url.append(
                {
                    "url": url,
                    "status_code": status,
                    "tech": tech,
                    "alive": True
                }
            )
    return alive_url
   

def run_nuclei(alive_url):
    console.print(f"[bold cyan][*][/bold cyan] Scanning for vulnerabilities...")
    all_vulns= []

    for url in alive_url:
        target_url = url["url"]
        console.print(f"[bold cyan][*][/bold cyan] Scanning: [green]{url}[/green]")

        try:
            check_vuln = subprocess.run(
                [
                    "nuclei",
                    "-u", target_url,
                    "-severity", "critical,high,medium",
                    "-timeout", "10",
                    "-rate-limit", "50",
                    "-no-color"
                ],
                capture_output=True,
                text=True,
                timeout=600)
            
        except FileNotFoundError:
            console.print("[bold red][-] nuclei not installed[/bold red]")
            exit(1)

        except subprocess.TimeoutExpired:
            console.print(f"[bold yellow][!][/bold yellow] Timed out: {target_url} skipping...")
            continue    # ← skip this url go to next       

        if check_vuln.stdout.strip():
            vulns = check_vuln.stdout.strip().split("\n")
            all_vulns.extend(vulns)
            console.print(f"[bold red][!][/bold red] Found {len(vulns)} issues")
        else:
                console.print(f"[bold green][+][/bold green] Clean: {target_url}")

    return all_vulns

def analyze_with_ai(alive_url, all_vulns, api_key):

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
                        "content": f"""You are a bug bounty security expert. Analyze these recon results:

## Alive Subdomains with Status Codes:
{json.dumps(alive_url, indent=2)}

## Nuclei Vulnerability Scan Results:
{json.dumps(all_vulns, indent=2)}

Please provide:
1. VULNERABILITY SUMMARY
   - List all confirmed vulnerabilities from nuclei
   - Rank by severity: Critical, High, Medium, Low

2. SUSPICIOUS SUBDOMAINS
   - Which subdomains look interesting and why
   - Focus on admin panels, dev environments, APIs

3. RECOMMENDED NEXT STEPS
   - What to manually test next
   - Which findings to report first

Be specific and actionable."""
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

def save_results(domain, subdomains, alive_url, all_vulns, ai_analysis):
    
    filename = f"{domain}_report.md"

   # 1. Start building the Markdown document
    md_content = f"# Security Reconnaissance Report: {domain}\n\n"
   # Quick Stats Section
    md_content += "## Summary Metrics\n"
    md_content += f"- **Total Subdomains Discovered:** {len(subdomains)}\n"
    md_content += f"- **Total Alive Hosts:** {len(alive_url)}\n"
    md_content += f"- **Total Vulnerabilities Identified:** {len(all_vulns)}\n\n"
    md_content += "---\n\n"
    # 2. Add Alive Subdomains & Tech Stacks as a Clean Table
    md_content += "## Alive Subdomains & Technologies\n"
    md_content += "| URL | Status Code | Identified Technologies |\n"
    md_content += "| :--- | :--- | :--- |\n"
   
    for item in alive_url:
        # Check if tech is a list or a string to handle it safely
        tech_str = ", ".join(item["tech"]) if isinstance(item["tech"], list) else str(item["tech"])
        md_content += f"| {item['url']} | {item['status_code']} | {tech_str} |\n"
    
    md_content += "\n---\n\n"

    # 3. Add Raw Nuclei Vulnerability Output inside a code block
    md_content += "## Raw Nuclei Scan Output\n"
    if all_vulns:
        md_content += "```text\n"
        for vuln in all_vulns:
            md_content += f"{vuln}\n"
        md_content += "```\n\n"
    else:
        md_content += "*No vulnerabilities were detected by Nuclei.*\n\n"
        
    md_content += "---\n\n"

    # 4. Append the AI Analysis seamlessly at the end
    md_content += "## AI Security Analysis & Recommendations\n"
    md_content += f"{ai_analysis}\n"

    # 5. Write everything out to a single file
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(md_content)
        console.print(f"[bold green][+][/bold green] All results successfully compiled into [yellow]{filename}[/yellow]")
    except Exception as e:
        console.print(f"[bold red][-] Failed to save Markdown file: {e}[/bold red]")
        exit(1)

def main():

    subdomain = run_subfinder(domain)
    subdomains = subdomain.stdout.strip().split("\n")
    console.print(f"[bold green][+][/bold green] Found [yellow]{len(subdomains)}[/yellow] subdomains")

    alive = run_httpx(subdomains)
    alive_list = alive.stdout.strip().split("\n")

    alive_url = parse_httpx_output(alive_list)
    console.print(f"[bold green][+][/bold green] Found [yellow]{len(alive_url)}[/yellow] alive subdomains")

    all_vulns = run_nuclei(alive_url)
    console.print(f"[bold green][+][/bold green] Found [yellow]{len(all_vulns)}[/yellow]  vulnirabilities")

    raw_content = analyze_with_ai(alive_url, all_vulns, api_key)
    console.print(f"\n[bold green][+][/bold green] AI Analysis Complete.")

    save_results(domain, subdomains, alive_url, all_vulns, raw_content)
main()

