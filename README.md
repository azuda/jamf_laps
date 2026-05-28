# jamf_laps

## prereqs

- python 3.10 or newer
- git
- homebrew
- rwx perms in script dir

## setup

```bash
brew install gnupg
git clone https://github.com/azuda/jamf_laps.git
cd jamf_laps
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
echo "alias getlaps=\"$PWD/.venv/bin/python3 $PWD/lookup_laps.py\"" >> ~/.zshrc
source ~/.zshrc
gpg .env.gpg
```

## usage

```bash
getlaps -h
```
