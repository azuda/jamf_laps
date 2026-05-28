# lookup_laps.py

import argparse
from jamf_credential import JAMF_URL, check_token_expiration, get_token, invalidate_token
import json
import os
import pandas as pd
import re
import requests
import time
import truststore
import urllib3

truststore.inject_into_ssl()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TIMESTAMP_PATH = os.path.join(SCRIPT_DIR, "last_run.timestamp")
LOOKUP_PATH = os.path.join(SCRIPT_DIR, "data/c.json")

# if testing lookup osxadmin else lookup rundleadmin
TESTING = False

# =====================================================================================================

def query_check():
  try:
    with open(TIMESTAMP_PATH, "r") as f:
      last_epoch = int(f.read().strip())
  except (OSError, ValueError):
    return True
  if not os.path.isfile(LOOKUP_PATH):
    return True
  return int(time.time()) - last_epoch > 604800 # 604800s == 7d

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
    client_mgmt_id = admin.get("clientManagementId")
    username = admin.get("username")
    guid = admin.get("guid")
    # GET laps password of specific account
    # https://developer.jamf.com/jamf-pro/reference/get_v2-local-admin-password-clientmanagementid-account-username-guid-password
    return jamf_get(f"/api/v2/local-admin-password/{client_mgmt_id}/account/{username}/{guid}/password", token, session)

def is_sn(arg):
  # return arg.replace("-", "").isalnum() and " " not in arg and len(arg) >= 12
  return bool(re.fullmatch(r"[A-Z0-9]{10,12}", arg))

def name_search(query, computers):
  query = query.lower()
  return [ c for c in computers if query in c.get("general").get("name").lower() ]

def handle_response(response):
  try:
    if response.status_code == 200:
      print(response.json().get("password"))
    elif response.json().get("errors", [{}])[0].get("code") == "NOT_FOUND":
      print("No LAPS password found")
    else:
      print(f"Unexpected error: {response.status_code}", response.json())
  except Exception as e:
    print(f"Error parsing response: {e}", response)

# =====================================================================================================

def main():
  # create argparser
  parser = argparse.ArgumentParser(description=__doc__, prog="getlaps")
  parser.add_argument(
    "computer",
    metavar="computer",
    help="sn or name of computer"
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

  # check if we need to run new query for all computers
  if query_check():
    os.makedirs("data", exist_ok=True)
    # GET all computers from jamf
    # https://developer.jamf.com/jamf-pro/reference/get_v3-computers-inventory
    COMPUTERS = jamf_get("/api/v3/computers-inventory?section=GENERAL&section=HARDWARE&page=0&page-size=2000&sort=id%3Aasc", token, session).json()
    with open(LOOKUP_PATH, "w") as f:
      f.write(json.dumps(COMPUTERS, indent=2))
    with open(TIMESTAMP_PATH, "w") as f:
      f.write(str(int(time.time())))
  else:
    with open(LOOKUP_PATH, "r") as f:
      COMPUTERS = json.load(f)

  # sn search
  if is_sn(args.computer):
    computer = next((c for c in COMPUTERS.get("results") if c["hardware"]["serialNumber"] == args.computer.upper()), None)
    if computer is None:
      print(f"Computer {args.computer.upper()} not found")
      invalidate_token(access_token)
      return
    response = lookup(computer, token, session)
    invalidate_token(access_token)
    handle_response(response)
    return

  # name search
  matches = name_search(args.computer, COMPUTERS.get("results"))
  if not matches:
    print(f"No computers found matching '{args.computer}'")
    invalidate_token(access_token)
    return

  # output search results
  df = pd.DataFrame([{
    "name": c["general"]["name"],
    "sn": c["hardware"]["serialNumber"],
    "model": c["hardware"]["model"],
  } for c in matches ])
  df.index += 1

  if len(matches) == 1:   # exactly 1 match
    computer = matches[0]
  else:                   # multiple matches, prompt user to select
    print(f"{df.to_string()}\n")
    try:
      choice = int(input("Which computer? Enter row number: "))
      if choice < 1 or choice > len(matches):
        print("Bad index, quitting")
        invalidate_token(access_token)
        return
    except ValueError:
      print("Bad input, quitting")
      invalidate_token(access_token)
      return
    computer = matches[choice - 1]

  # done
  response = lookup(computer, token, session)
  invalidate_token(access_token)
  handle_response(response)

# =====================================================================================================

if __name__ == "__main__":
  main()
