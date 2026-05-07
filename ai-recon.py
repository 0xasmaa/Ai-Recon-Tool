import subprocess
import argparse
import requests
import json

#nmap.org domain for test

parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
parser.add_argument("--target", help="Specify the domain to enumerate", required=True)
args = parser.parse_args()

domain = args.target
print(f"[*]scanning: {domain}")

try:
    subdomain = subprocess.run(["subfinder", "-d", domain], capture_output=True, text=True, timeout=60)
    print(subdomain.stdout)

except FileNotFoundError:
    print("[-] subfinder is not installed or not in PATH")
    exit(1)

except subprocess.TimeoutExpired:
    print("[-] subfinder timed out")
    exit(1)    

if subdomain.returncode != 0:
    print(f"[-] subfinder failed: {subdomain.stderr}")
    exit(1)

subdomains = subdomain.stdout.strip().split("\n")  # turn output into a list
    
if not subdomains or subdomains == [""]:
    print("[-] No subdmaomains found")
    exit(1)

print(f"[+] Found {len(subdomains)} subdomains")

subdomains_with_https = [f"https://{sub}" for sub in subdomains]

print(f"[*] Checking alive subdomains...")

try:
    alive = subprocess.run(["httpx", "-silent", "-sc", "-cl"], input="\n".join(subdomains_with_https), capture_output=True, text=True, timeout=120)
    print(alive.stdout)

except FileNotFoundError:
    print("[-] httpx is not installed or not in PATH")
    exit(1)

except subprocess.TimeoutExpired:
    print("[-] httpx timed out")
    exit(1)

if not alive.stdout.split():
    print("[-] No alive subdomains")
    exit(1)

alive_list = alive.stdout.strip().split("\n")
print(f"[+] Found {len(alive_list)} alive subdomains")

    # Step 4: save to json
data = {
        "domain": domain,
        "total_subdomain": len(subdomains),
        "total_alive": len(alive_list),
        "subdomains": subdomains,
        "alive": alive_list
    }


filename = f"{domain}.json"

try:
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Results saved to {filename}")
except Exception as e:
    print(f"[-] Failed to save file: {e}")
    exit(1)
