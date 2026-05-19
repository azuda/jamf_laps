# lookup_laps.py

import argparse
from jamf_credential import JAMF_URL, check_token_expiration, get_token, invalidate_token
import requests
import time
import urllib3

ADMIN_ACC = "rundleadmin"

# =====================================================================================================

def jamf_get(endpoint, token, session):
  token["t"], token["expiration"] = check_token_expiration(token["t"], token["expiration"])
  url = f"{JAMF_URL}{endpoint}"
  headers = {
    "accept": "application/json",
    "authorization": f"Bearer {token["t"]}"
  }
  response = session.get(url, headers=headers, verify=False)
  return response

def make_session():
  session = requests.Session()
  retry = urllib3.util.retry.Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET", "PATCH"],
    raise_on_status=False,
  )
  adapter = requests.adapters.HTTPAdapter(max_retries=retry)
  session.mount("https://", adapter)
  return session

# =====================================================================================================

def lookup(c, token, session):
  global ADMIN_ACC
  accs = jamf_get(f"/api/v2/local-admin-password/{c["general"]["managementId"]}/accounts", token, session).json()
  admin = next((a for a in accs["results"] if a["username"] == ADMIN_ACC), None)
  if admin:
    print(f"Grabbing {ADMIN_ACC} password on {c["general"]["name"]} {c["hardware"]["serialNumber"]}...")
    client_mgmt_id = admin["clientManagementId"]
    username = admin["username"]
    guid = admin["guid"]

    # GET admin password
    # https://developer.jamf.com/jamf-pro/reference/get_v2-local-admin-password-clientmanagementid-account-username-guid-password
    return jamf_get(f"/api/v2/local-admin-password/{client_mgmt_id}/account/{username}/{guid}/password", token, session)

# =====================================================================================================

def main():
  access_token, expires_in = get_token()
  token = {
    "t": access_token,
    "expiration": int(time.time()) + expires_in,
  }
  print(f"Token valid for {expires_in} seconds")
  version_url = f"{JAMF_URL}/api/v1/jamf-pro-version"
  headers = {"Authorization": f"Bearer {access_token}"}
  version = requests.get(version_url ,headers=headers, verify=False)
  print("Jamf Pro version:", version.json()["version"])

  session = make_session()
  COMPUTERS = jamf_get("/api/v3/computers-inventory?section=GENERAL&section=HARDWARE&page=0&page-size=2000&sort=id%3Aasc", token, session).json()

  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
    "sn",
    metavar="serialnumber",
    help="serial number of computer to lookup"
  )
  args = parser.parse_args()
  print(f"Looking up [ {args.sn if args else 'None'} ]")
  computer = next((c for c in COMPUTERS["results"] if c["hardware"]["serialNumber"] == args.sn), None)
  results = lookup(computer, token, session)
  print(f"\n{results.json()['password']}\n")

  invalidate_token(access_token)

if __name__ == "__main__":
  urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
  main()
