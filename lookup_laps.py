# lookup_laps.py

import argparse
from jamf_credential import JAMF_URL, check_token_expiration, get_token, invalidate_token
import json
import os
import requests
import time
import truststore
import urllib3

truststore.inject_into_ssl()

# if testing lookup osxadmin else lookup rundleadmin
TESTING = False

# =====================================================================================================

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

def jamf_get(endpoint, token, session):
  token["t"], token["expiration"] = check_token_expiration(token["t"], token["expiration"])
  url = f"{JAMF_URL}{endpoint}"
  headers = {
    "accept": "application/json",
    "authorization": f"Bearer {token["t"]}"
  }
  response = session.get(url, headers=headers)
  return response

def lookup(computer, token, session, username="rundleadmin"):
  if TESTING:
    username = "osxadmin"
  # GET laps enabled accounts on computer
  # https://developer.jamf.com/jamf-pro/reference/get_v2-local-admin-password-clientmanagementid-accounts
  accs = jamf_get(f"/api/v2/local-admin-password/{computer["general"]["managementId"]}/accounts", token, session).json()
  admin = next((a for a in accs["results"] if a["username"] == username), None)
  if admin:
    print(f"Getting {username} password on {computer["general"]["name"]} {computer["hardware"]["serialNumber"]}...\n")
    client_mgmt_id = admin["clientManagementId"]
    username = admin["username"]
    guid = admin["guid"]
    # GET laps password of specific account
    # https://developer.jamf.com/jamf-pro/reference/get_v2-local-admin-password-clientmanagementid-account-username-guid-password
    return jamf_get(f"/api/v2/local-admin-password/{client_mgmt_id}/account/{username}/{guid}/password", token, session)

# =====================================================================================================

def main():
  # create argparser
  parser = argparse.ArgumentParser(description=__doc__, prog="getlaps")
  parser.add_argument(
    "sn",
    metavar="serialnumber",
    help="serial number of computer"
  )
  args = parser.parse_args()

  # create jamf access token
  access_token, expires_in = get_token()
  token = {
    "t": access_token,
    "expiration": int(time.time()) + expires_in,
  }

  # create retry session
  session = make_session()

  # GET all computers from jamf
  # https://developer.jamf.com/jamf-pro/reference/get_v3-computers-inventory
  COMPUTERS = jamf_get("/api/v3/computers-inventory?section=GENERAL&section=HARDWARE&page=0&page-size=2000&sort=id%3Aasc", token, session).json()
  # if not os.path.exists("debug"):
  #   os.makedirs("debug")
  # with open("debug/c.json", "w") as f:
  #   f.write(json.dumps(COMPUTERS, indent=2))

  # check if computer exists and lookup laps password
  computer = next((c for c in COMPUTERS["results"] if c["hardware"]["serialNumber"] == args.sn.upper()), None)
  if computer is None:
    print(f"Computer {args.sn.upper()} not found")
    return
  response = lookup(computer, token, session)

  # kill jamf access token
  invalidate_token(access_token)

  # HTTP response handling + output result
  try:
    if response.status_code == 200:
      print({response.json().get("password")})
    elif response.json().get("errors", [{}])[0].get("code") == "NOT_FOUND":
      print("No LAPS password found")
    else:
      print(f"Unexpected error: {response.status_code}", response.json())
  except Exception as e:
    print(f"Error parsing response: {e}", response)

# =====================================================================================================

if __name__ == "__main__":
  main()
