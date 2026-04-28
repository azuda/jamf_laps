#!/bin/sh

PROJECT="$PWD"
VENV="$PROJECT/.venv/bin/python3"

echo "Script start @ $(date)"

$VENV run.py

echo "\nScript done @ $(date)"
