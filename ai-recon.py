import subprocess
import argparse
import requests
import json

#nmap.org domain for test

parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
parser.add_argument("--target", required=True, help="Specify the domain to enumerate")
parser.add_argument("--api-key", required=True, help="Specify Claude API KEY")
args = parser.parse_args()

domain = args.target
api_key = args.api_key

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

print(f"[*] Sending to Ai for analysis...")

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
        ai_analysis = response.json()["choices"][0]["message"]["content"]
        print(f"\n[+] AI Analysis:\n{ai_analysis}") 

    else:
        print(f"[-] Groq API error: {response.status_code}")
        print(f"[-] Details: {response.text}")
        ai_analysis = "AI analysis failed"

except Exception as e:
    print(f"[-] AI request failed: {e}")
    ai_analysis = "AI analysis failed"

    # Step 4: save to json
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
    print(f"[+] Results saved to {filename}")
except Exception as e:
    print(f"[-] Failed to save file: {e}")
    exit(1)
