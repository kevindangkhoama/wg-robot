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
        state = {}
        json_object = json.dumps(state, indent=4)
        with open(os.path.join(home_dir, 'state.json'), 'w') as file:
            file.write(json_object)
            # print(state)  
    
def getPrivateKey():
    home_dir = os.path.expanduser('~') 
    file_object = open(os.path.join(home_dir, 'wg0.txt'), 'r')
    data = file_object.read().splitlines()
    private_key = data[2].split(' ')[-1].strip()
    return(private_key)

def assignIP(file_data):    
    # Assigning IPs if first entry default to 10.77.0.2 else increment greatest IP by 1
    # TO DO: Find a way to do this faster
    if len(file_data) == 0:
        user_ip = "10.77.0.2"
    else:
        greatest_IP_int = ipaddress.IPv4Address("10.77.0.2")
        for device_entry in file_data.values():
            for device_info in device_entry.values():
                current_IP = ipaddress.IPv4Address(device_info["IP"])
                if current_IP > greatest_IP_int:
                    greatest_IP_int = current_IP
        greatest_IP_int +=1
        user_ip = str(ipaddress.IPv4Address(greatest_IP_int))
    return user_ip

def Encrypter(username, user_public):
    # Decode and assign wg_private as a Private Key object
    wg_private = getPrivateKey()
    wg_private = base64.b64decode(wg_private)
    wg_private = nacl.public.PrivateKey(wg_private)
    # Decode User and assign user_public as a Public Key object
    public_key = user_public
    user_public = base64.b64decode(user_public)
    user_public = nacl.public.PublicKey(user_public)
    # Create a WireGuard Box
    wg_box = Box(wg_private, user_public)
    user_psk = wg_box.shared_key()
    user_psk = base64.b64encode(user_psk)
    
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
            "Public_Key" : str(public_key),
            "PreShared_Key" : str(user_psk.decode()),
            "IP" : user_ip,
        }
    }
    
    # If user does not have a preexisting username, create one. If so, add new device to the list of devices asssociated with the username
    if f"{username}" not in file_data:
        file_data[f"{username}"] = Entry
    else:
        file_data[f"{username}"] |= Entry
    
    # Output newly updated json file
    json_object = json.dumps(file_data, indent=4)
    with open(os.path.join(home_dir, 'state.json'), 'w') as outfile:
        outfile.write(json_object)
    
    formatted_entry = f"\n\n[Peer]\n" \
                          f"# {username} | {device} \n" \
                          f"PublicKey = {Entry[device]['Public_Key']}\n" \
                          f"PresharedKey = {Entry[device]['PreShared_Key']}\n" \
                          f"AllowedIPs = {Entry[device]['IP']}\n" \
                          f"PersistentKeepalive = 25"
    
    with subprocess.Popen(["sudo", "tee", "-a", "wg0.txt"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL) as p:
        p.communicate(formatted_entry.encode())

    # User side:
    # Combine both values into a string
    message = f"USER_IP={user_ip} | PSK={user_psk.decode()}"
    
    # Encrypt IP and PSK and return
    encrypted = base64.b64encode(wg_box.encrypt(message.encode()))
    print(f"Here is your encrypted config: {encrypted.decode()}")
    
    # Export to text file
    home_dir = os.path.expanduser('~')
    with open(os.path.join(home_dir, f'{device}_Encrypted_Config.txt'), 'wb') as fp:
         fp.write(encrypted)


# # Command Line Arguments
if len(sys.argv) == 3:
    print("Encrypting...")
    
    # Assign variables
    sys.argv.pop(0)
    username = sys.argv.pop(0)
    user_public = sys.argv.pop(0)
    # Remove "_public.txt" from arg2 to get device name variable
    device = os.path.splitext(user_public)[0].replace('_Public', '')

    # Open device public key and store as a variable
    with open(f'{user_public}', 'r') as fp:
        user_public = fp.read()
        
    # Run Encrypter
    Encrypter(username, user_public)
    print("Done")
else:
    # Invalid Command
    print("Usage: Robot.py <Username>, <Device_Public.txt>", file=sys.stderr) 