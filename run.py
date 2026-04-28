# run.py

"""
"""

import csv
from jamf_credential import JAMF_URL, check_token_expiration, get_token, invalidate_token
import json
import os
import requests
import time
import urllib3

TESTING = False

# ==================================================================================

def jamf_get(endpoint, token):
  token["t"], token["expiration"] = check_token_expiration(token["t"], token["expiration"])
  url = f"{JAMF_URL}{endpoint}"
  headers = {
    "accept": "application/json",
    "authorization": f"Bearer {token["t"]}"
  }
  response = requests.get(url, headers=headers, verify=False)
  return response

def jamf_patch(payload, endpoint, token):
  token["t"], token["expiration"] = check_token_expiration(token["t"], token["expiration"])
  url = f"{JAMF_URL}{endpoint}"
  headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": f"Bearer {token["t"]}"
  }
  response = requests.patch(url, json=payload, headers=headers, verify=False)
  return response

# ==================================================================================

def main():
  # create jamf access token
  access_token, expires_in = get_token()
  token = {
    "t": access_token,
    "expiration": int(time.time()) + expires_in,
  }
  print(f"Token valid for {expires_in} seconds")

  # print jamf pro version
  version_url = f"{JAMF_URL}/api/v1/jamf-pro-version"
  headers = {"Authorization": f"Bearer {access_token}"}
  version = requests.get(version_url, headers=headers, verify=False)
  print("Jamf Pro version:", version.json()["version"])

  # GET all computers
  computers = jamf_get("/api/v3/computers-inventory?section=GENERAL&section=HARDWARE&page=0&page-size=2000&sort=id%3Aasc", token).json()
  # computers = jamf_get("/api/v3/computers-inventory?section=GENERAL&section=HARDWARE&section=LOCAL_USER_ACCOUNTS&page=0&page-size=2000&sort=id%3Aasc", token).json()

  # write for debug
  if not os.path.exists("debug"):
    os.makedirs("debug")
  with open("debug/c.json", "w") as f:
    f.write(json.dumps(computers, indent=2))

  count = 10
  output = []

  for c in computers["results"]:
    if TESTING:
      if c["hardware"]["serialNumber"] != "LF0W72L9FR":
        continue
      # count -= 1
      # if count < 1:
      #   break

    entry = {
      "jamf_id": c["id"],
      "name": c["general"]["name"],
      "sn": c["hardware"]["serialNumber"],
    }

    # GET all admin accounts on this computer + extract rundleadmin if it exists
    accs = jamf_get(f"/api/v2/local-admin-password/{c["general"]["managementId"]}/accounts", token).json()
    rundleadmin = next((a for a in accs["results"] if a["username"] == "rundleadmin"), None)
    if rundleadmin:
      print(f"Grabbing rundleadmin password on {c["general"]["name"]} {c["hardware"]["serialNumber"]}...")
      client_mgmt_id = rundleadmin["clientManagementId"]
      guid = rundleadmin["guid"]
      # GET rundleadmin password
      response = jamf_get(f"/api/v2/local-admin-password/{client_mgmt_id}/account/{rundleadmin['username']}/{guid}/password", token)

      # HTTP response handling
      if response.status_code == 200:
        entry["password"] = response.json().get("password")
      elif response.json().get("errors", [{}])[0].get("code") == "NOT_FOUND":
        # print("No LAPS password exists on this machine")
        entry["password"] = None
        entry["note"] = "No LAPS password configured on this machine"
      else:
        # print(f"Unexpected error: {response.status_code}", response.json())
        entry["password"] = None
        entry["note"] = f"Unexpected error: {response.status_code} {response.json()}"
      output.append(entry)

  # kill jamf access token
  invalidate_token(access_token)

  # write to csv
  with open("output.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["jamf_id", "name", "sn", "password", "note"])
    writer.writeheader()
    for row in output:
      writer.writerow(row)

print("Done")

# ==================================================================================

if __name__ == "__main__":
  urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
  main()
