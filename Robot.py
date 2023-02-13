#!/usr/bin/python3
import sys
import os
import nacl.utils
import base64
from nacl.public import PrivateKey, PublicKey, Box


def Encrypter(user_public):
    # WireGuard private key
    wg_private = ""
    # Convert byte string to Private Key object
    wg_private = nacl.public.PrivateKey(wg_private)
    
    # Create a WireGuard Box
    wg_box = Box(wg_private, user_public)
    
    # Generate IP and preshared key
    user_ip = "10.77.0.7" # Set as this IP for now
    user_psk = wg_box.shared_key()
    
    # Combine both values into a string
    message = f"USER_IP={user_ip} | PSK={user_psk}"
    # print(message) 
    
    # Encrypt IP and PSK in base64 and return
    encrypted = base64.b64encode(wg_box.encrypt(message.encode()))
    return encrypted


# Command Line Arguments
if len(sys.argv) == 2:
    # Open User Public Key
    with open('User_Public.txt', 'rb') as f:
        data = f.read()
        byte_string = data.decode('UTF-8').strip()
        user_public = byte_string
        # Convert byte string to Public Key Object
        user_public = nacl.public.PublicKey(user_public)
    Encrypter(user_public)
else:
    # Invalid Command
    print("Usage: Robot.py <User_Public.txt>", file=sys.stderr)
