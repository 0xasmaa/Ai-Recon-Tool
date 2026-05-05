import subprocess
import argparse
import json


parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
parser.add_argument("--target", help="Specify the domain to enumerate")
args = parser.parse_args()

domain = args.target
print(f"[*]scanning: {domain}")


subdomain = subprocess.run(["subfinder", "-d", domain], capture_output=True, text=True)
print(subdomain.stdout)


if subdomain.returncode == 0:
    subdomains = subdomain.stdout.strip().split("\n")  # turn output into a list
    print(f"[+] Found {len(subdomains)} subdomains")

    # Step 4: save to json
    data = {
        "domain": domain,
        "total": len(subdomains),
        "subdomains": subdomains
    }

    filename = f"{domain}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    print(f"[+] Results saved to {filename}")

else:
    print(f"[-] Error: {subdomain.stderr}")
