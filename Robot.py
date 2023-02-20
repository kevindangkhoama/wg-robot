#!/usr/bin/python3
import sys
import os
import nacl.utils
import base64
from nacl.public import PrivateKey, PublicKey, Box

def getPrivateKey():
    # os.system("sudo -i")
    home_dir = os.path.expanduser('~')
    file_object = open(os.path.join(home_dir, 'wg0.txt'), 'r')
    data = file_object.read().splitlines()
    private_key = data[2].split(' ')[-1].strip()
    return(private_key)

def Encrypter(user_public):
    # Decode and assign wg_private as a Private Key object
    wg_private = getPrivateKey()
    wg_private = base64.b64decode(wg_private)
    wg_private = nacl.public.PrivateKey(wg_private)
    
    # Decode User and assign user_public as a Public Key object
    user_public = base64.b64decode(user_public)
    user_public = nacl.public.PublicKey(user_public)

    # Create a WireGuard Box
    wg_box = Box(wg_private, user_public)
    
    # Generate IP and preshared key
    user_ip = "10.77.0.7" # Set as this IP for now
    user_psk = wg_box.shared_key()
    
    # Combine both values into a string
    message = f"USER_IP={user_ip} | PSK={user_psk}"
    
    # Encrypt IP and PSK and return
    encrypted = base64.b64encode(wg_box.encrypt(message.encode()))
    print(f"Here is your encrypted config: {encrypted.decode()}")
    
    # # Export to text file
    # home_dir = os.path.expanduser('~')
    # with open(os.path.join(home_dir, 'Encrypted_Config.txt'), 'wb') as fp:
    #     # fp.write(encrypted)


# # Command Line Arguments
if len(sys.argv) == 2:
    print("Encrypting...")
    
    sys.argv.pop(0)
    user_public = sys.argv.pop(0)
    
    # Open text file and store as a variable
    # with open('User_Public.txt', 'r') as fp:
    #     user_public = fp.read()
        
    # Run Encrypter    
    Encrypter(user_public)
    print("Done")
    
else:
    # Invalid Command
    print("Usage: Robot.py <User_Public.txt>", file=sys.stderr) 