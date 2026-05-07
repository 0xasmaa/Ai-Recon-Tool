import subprocess
import argparse
import json

#nmap.org domain for test

parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
parser.add_argument("--target", help="Specify the domain to enumerate")
args = parser.parse_args()

domain = args.target
print(f"[*]scanning: {domain}")

try:
    subdomain = subprocess.run(["subfinder", "-d", domain], capture_output=True, text=True)
    print(subdomain.stdout)

except FileNotFoundError:
    print("[-] subfinder is not installed or not in PATH")
    exit(1)

except subprocess.TimeoutExpired:
    print("[-] subfinder timed out")
    exit(1)    

if subdomain.returncode == 0:
    subdomains = subdomain.stdout.strip().split("\n")  # turn output into a list
    print(f"[+] Found {len(subdomains)} subdomains")

    subdomains_with_https = [f"https://{sub}" for sub in subdomains]

    print(f"[*] Checking alive subdomains...")
    alive = subprocess.run(["httpx", "-silent", "-sc", "-cl"], input="\n".join(subdomains_with_https), capture_output=True, text=True)
    print(alive.stdout)

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
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    print(f"[+] Results saved to {filename}")

else:
    print(f"[-] Error: {subdomain.stderr}")
