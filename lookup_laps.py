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

# =====================================================================================================

def query_check():
  """
  - check if we need to query jamf for all computers
  - if timestamp file or lookup file dne, or if timestamp > 7d ago, return True
  - else use existing lookup file, return False
  """
  try:
    with open(TIMESTAMP_PATH, "r") as f:
      last_epoch = int(f.read().strip())
  except (OSError, ValueError):
    return True
  if not os.path.isfile(LOOKUP_PATH):
    return True
  return int(time.time()) - last_epoch > 604800 # 604800s == 7d

def make_session():
  """
  - create retry requests session
  """
  session = requests.Session()
  retry = urllib3.util.retry.Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"],
    raise_on_status=False,
  )
  adapter = requests.adapters.HTTPAdapter(max_retries=retry)
  session.mount("https://", adapter)
  return session

def jamf_get(endpoint, token, session):
  """
  - GET request to jamf
  """
  token["t"], token["expiration"] = check_token_expiration(token["t"], token["expiration"])
  url = f"{JAMF_URL}{endpoint}"
  headers = {
    "accept": "application/json",
    "authorization": f"Bearer {token['t']}"
  }
  response = session.get(url, headers=headers)
  return response

def get_all_computers(token, session):
  """
  - handle pagination when getting all computers from jamf
  """
  results = []
  page = 0
  page_size = 200
  while True:
    # GET all computers from jamf
    # https://developer.jamf.com/jamf-pro/reference/get_v3-computers-inventory
    response = jamf_get(
      f"/api/v3/computers-inventory?section=GENERAL&section=HARDWARE&page={page}&page-size={page_size}&sort=id%3Aasc",
      token, session
    )
    response.raise_for_status()
    data = response.json()
    results.extend(data.get("results", []))
    if len(results) >= data.get("totalCount", 0):
      break
    page += 1
  return { "results": results, "totalCount": len(results) }

def lookup(computer, token, session, username):
  """
  - lookup laps password for username on specified computer
  - raise LookupError if no account is found
  """
  accs = jamf_get(f"/api/v2/local-admin-password/{computer['general']['managementId']}/accounts", token, session).json()
  admin = next((a for a in accs["results"] if a["username"] == username), None)
  if admin is None:
    raise LookupError(f"Account '{username}' has no LAPS entry on {computer['general']['name']} {computer['hardware']['serialNumber']})")
  print(f"Getting {username} password on {computer['general']['name']} {computer['hardware']['serialNumber']}...\n")
  return jamf_get(
    f"/api/v2/local-admin-password/{admin['clientManagementId']}"
    f"/account/{admin['username']}/{admin['guid']}/password",
    token, session
  )

def is_sn(arg):
  """
  - check if arg is a valid sn
  """
  return (
    bool(re.fullmatch(r"[A-Za-z0-9]{10,12}", arg)) and  # 10-12 alphanum chars
    (arg == arg.upper() or arg == arg.lower()) and      # all chars are the same case
    any(c.isdigit() for c in arg)                       # contains at least 1 num
  )

def name_search(query, computers):
  """
  - search for query in computer names
  - return a list of matches
  """
  query = query.lower()
  return [ c for c in computers if query in c.get("general", {}).get("name", "").lower()]

def handle_response(response):
  """
  - process http response from password lookup
  - if found print laps password
  - else print appropriate error message
  """
  try:
    data = response.json()
    if response.status_code == 200:
      print(data.get("password"))
    elif data.get("errors", [{}])[0].get("code") == "NOT_FOUND":
      print("No LAPS password found")
    else:
      print(f"Unexpected error: {response.status_code}", data)
  except Exception as e:
    print(f"Error parsing response: {e}", response)

# =====================================================================================================

def main():
  # create argparser
  parser = argparse.ArgumentParser(description=__doc__, prog="getlaps")
  parser.add_argument(
    "computer",
    metavar="computer",
    nargs="?",
    help="sn or name of computer"
  )
  parser.add_argument(
    "-r",
    action="store_true",
    help="refresh cached computer list"
  )
  parser.add_argument(
    "--username",
    default="rundleadmin",
    metavar="USERNAME",
    help="username of admin account to lookup (default: rundleadmin)"
  )
  args = parser.parse_args()

  if not args.r and args.computer is None:
    parser.print_help()
    return

  if args.r:
    if os.path.isfile(LOOKUP_PATH):
      os.remove(LOOKUP_PATH)
      print("Cleared cache")
    if not args.computer:
      return

  # create jamf access token
  access_token, expires_in = get_token()
  token = {
    "t": access_token,
    "expiration": int(time.time()) + expires_in,
  }

  # create retry session
  session = make_session()

  try:
    # check if we need to run new query for all computers
    if query_check():
      os.makedirs(os.path.dirname(LOOKUP_PATH), exist_ok=True)
      computers = get_all_computers(token, session)
      with open(LOOKUP_PATH, "w") as f:
        f.write(json.dumps(computers, indent=2))
      with open(TIMESTAMP_PATH, "w") as f:
        f.write(str(int(time.time())))
    else:
      with open(LOOKUP_PATH, "r") as f:
        computers = json.load(f)

    # sn search
    if is_sn(args.computer):
      computer = next((c for c in computers.get("results", []) if c["hardware"]["serialNumber"] == args.computer.upper()), None)
      if computer is None:
        print(f"Computer {args.computer.upper()} not found")
        return  # finally still runs
      try:
        response = lookup(computer, token, session, args.username)
        handle_response(response)
      except LookupError as e:
        print(e)
      return

    # name search
    matches = name_search(args.computer, computers.get("results"))
    if not matches:
      print(f"No computers found matching '{args.computer}'")
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
          return
      except ValueError:
        print("Bad input, quitting")
        return
      computer = matches[choice - 1]

    # done
    try:
      response = lookup(computer, token, session, args.username)
      handle_response(response)
    except LookupError as e:
      print(e)

  finally:
    invalidate_token(token["t"])

# =====================================================================================================

if __name__ == "__main__":
  main()
