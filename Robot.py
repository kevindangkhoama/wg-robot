#!/usr/bin/python3
import ipaddress
import sys
import os
import json
import base64
import subprocess
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

def json_location(file_name):
    home_dir = os.path.expanduser('~')
    full_path = os.path.join(home_dir, file_name)
    return os.path.exists(full_path)

def state():
    home_dir = os.path.expanduser('~') 
    
    # If state.json is present, load
    if json_location('state.json'):
        with open(os.path.join(home_dir, 'state.json'),'r') as file:
            state = json.load(file)
            # print(state)
    else:
        # Create state.json
        state = {
            "Latest_IP": "",
            "Users": {}
            }
        json_object = json.dumps(state, indent=4)
        with open(os.path.join(home_dir, 'state.json'), 'w') as file:
            file.write(json_object)
            # print(state)  
    
def getPrivateKey():
    with subprocess.Popen(["sudo", "cat", "wg0.txt"], stdout=subprocess.PIPE) as p:
        output = p.stdout.read().decode()
    data = output.splitlines()
    private_key = data[2].split(' ')[-1].strip()
    return private_key

def assignIP(file_data):    
    # Assigning IPs if first entry default to 10.77.0.2 else increment latest IP by 1
    if file_data["Latest_IP"] == "":
        file_data["Latest_IP"] = "10.77.0.2"
        user_ip = "10.77.0.2"
    else:
        latest_IP_int = ipaddress.IPv4Address(file_data["Latest_IP"])
        latest_IP_int +=1
        file_data["Latest_IP"] = str(ipaddress.IPv4Address(latest_IP_int))
        user_ip = str(ipaddress.IPv4Address(latest_IP_int))
    return user_ip

def Encrypter(username, device, user_public):
    # Decode and assign wg_private as a Private Key object
    wg_private = getPrivateKey()
    wg_private = base64.b64decode(wg_private)
    wg_private = nacl.public.PrivateKey(wg_private)
    # Decode User and assign user_public as a Public Key object
    user_public = base64.b64decode(user_public)
    user_public = nacl.public.PublicKey(user_public)
    # Create a WireGuard Box
    wg_box = Box(wg_private, user_public)
    user_psk = wg_box.shared_key()
    user_psk = base64.b64encode(user_psk)
    
    # Encode the public key in base64
    user_public = base64.b64encode(user_public.encode())
    
    # Robot side:
    state()

    # Load state.json
    home_dir = os.path.expanduser('~')
    with open(os.path.join(home_dir, 'state.json'),'r') as file:
        file_data = json.load(file)

    # Assign IP:
    user_ip = assignIP(file_data)
    
    # New User to be added    
    Entry = {
        f"{device}": {
            "PublicKey" : user_public.decode(),
            "PreSharedKey" : str(user_psk.decode()),
            "AllowedIPs" : user_ip,
        }
    }
    
    # If user does not have a preexisting username, create one. If so, add new device to the list of devices asssociated with the username
    if f"{username}" not in file_data["Users"]:
        file_data["Users"][f"{username}"] = Entry
    else:
        if f"{device}" in file_data["Users"][f"{username}"]:
            print("Error: Device Already Added")
            sys.exit()
        else:
            file_data["Users"][f"{username}"] |= Entry
    
    # Output newly updated json file
    json_object = json.dumps(file_data, indent=4)
    with open(os.path.join(home_dir, 'state.json'), 'w') as outfile:
        outfile.write(json_object)
    
    formatted_entry = f"\n\n[Peer]\n" \
                          f"# {username} | {device} \n" \
                          f"PublicKey = {Entry[device]['PublicKey']}\n" \
                          f"PreSharedKey = {Entry[device]['PreSharedKey']}\n" \
                          f"AllowedIPs = {Entry[device]['AllowedIPs']}\n" \
                          f"PersistentKeepAlive = 25"
    
    with subprocess.Popen(["sudo", "tee", "-a", "wg0.txt"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL) as p:
        p.communicate(formatted_entry.encode())

    # User side:
    # Combine both values into a string
    message = f"USER_IP = {user_ip} | PSK = {user_psk.decode()}"
    
    # Encrypt IP and PSK and return
    encrypted = base64.b64encode(wg_box.encrypt(message.encode()))
    print(f"\nHere is your Encrypted Config: {encrypted.decode()}\n")

# # Command Line Arguments
if len(sys.argv) == 4:
    
    # Assign variables
    sys.argv.pop(0)
    username = sys.argv.pop(0)
    username = username.lower()
    device = sys.argv.pop(0)
    device = device.lower()
    user_public = sys.argv.pop(0)

    # Run Encrypter
    print("Encrypting...")
    Encrypter(username, device, user_public)
    print("Done")
else:
    # Invalid Command
    print("Usage: Robot.py <User>, <Device>, <Device_Public>", file=sys.stderr) 