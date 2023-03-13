#!/usr/bin/python3
import ipaddress
import sys
import os
import json
import nacl.utils
import base64
import random
from random import randint
from nacl.public import PrivateKey, PublicKey, Box


def json_location(file_name):
    home_dir = os.path.expanduser('~')
    full_path = os.path.join(home_dir, file_name)
    return os.path.exists(full_path)

# def generate_private_ip():
#     ip = ["10"]
#     # Generate random numbers from start range to end range 
#     for i in range(4):
#         ip.append(str(random.randint(0, 255)))
#     # Join the list with '.' separator 
#     return '.'.join(ip)

def state():
    home_dir = os.path.expanduser('~') 
    
    if json_location('state.json'):
        with open(os.path.join(home_dir, 'state.json'),'r') as file:
            state = json.load(file)
            # print(state)
    else:
        state = {}
        json_object = json.dumps(state, indent=4)
        with open(os.path.join(home_dir, 'state.json'), 'w') as file:
            file.write(json_object)
            # print(state)  
    
def getPrivateKey():
    # os.system("sudo -i")
    home_dir = os.path.expanduser('~') 
    file_object = open(os.path.join(home_dir, 'wg0.txt'), 'r')
    data = file_object.read().splitlines()
    private_key = data[2].split(' ')[-1].strip()
    return(private_key)

def Encrypter(username, device, user_public):
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
    # Check if a state.json is present, if not, create one
    state()
    
    # Add user info to state.json
    home_dir = os.path.expanduser('~')
    with open(os.path.join(home_dir, 'state.json'),'r') as file:
        # First we load existing data into a dict.
        file_data = json.load(file)
        
    if len(file_data) == 0:
        user_ip = "10.77.0.2"
    else:
        latest_IP_entry = file_data[list(file_data)[-1]]["IP"]
        user_ip = str(ipaddress.ip_address(latest_IP_entry) + 1)
    
    # New User to be added    
    Entry = {
        "Public_Key" : str(public_key),
        "PSK" : str(user_psk.decode()),
        "IP" : user_ip,
        }
    
    file_data[f"{username}"] = Entry
    
    # Output newly updated json file
    json_object = json.dumps(file_data, indent=4)
    with open(os.path.join(home_dir, 'state.json'), 'w') as outfile:
        outfile.write(json_object)
    
    with open('wg0.txt', 'r') as f:
    # read the existing contents of the file into a string variable
        existing_entries = f.read()
    
    # Update wg0 with the new json file        
    with open('wg0.txt', 'a') as f:
    # loop through all entries in the dictionary
        for user, entry in file_data.items():
        # format the entry as desired
            formatted_entry = f"\n\n[Peer]\n" \
                              f"# {username} | {device}\n" \
                              f"PublicKey = {entry['Public_Key']}\n" \
                              f"PresharedKey = {entry['PSK']}\n" \
                              f"AllowedIPs = {entry['IP']}\n" \
                              f"PersistentKeepalive = 25"
            # write the formatted entry to the text file
            if formatted_entry not in existing_entries:
            # write the formatted entry to the file
                f.write(formatted_entry)
            # update the existing entries variable to include the new entry
                existing_entries += formatted_entry
      
    # User side:
    # Combine both values into a string
    message = f"USER_IP={user_ip} | PSK={user_psk.decode()}"
    
    # Encrypt IP and PSK and return
    encrypted = base64.b64encode(wg_box.encrypt(message.encode()))
    print(f"Here is your encrypted config: {encrypted.decode()}")
    
    # # Export to text file
    # home_dir = os.path.expanduser('~')
    # with open(os.path.join(home_dir, 'Encrypted_Config.txt'), 'wb') as fp:
    #     # fp.write(encrypted)


# # Command Line Arguments
if len(sys.argv) == 4:
    print("Encrypting...")
    
    sys.argv.pop(0)
    username = sys.argv.pop(0)
    device = sys.argv.pop(0)
    user_public = sys.argv.pop(0)
    
    # Open text file and store as a variable
    # with open('User_Public.txt', 'r') as fp:
    #     user_public = fp.read()
        
    # Run Encrypter    
    Encrypter(username, device, user_public)
    print("Done")
    
else:
    # Invalid Command
    print("Usage: Robot.py <Username>, <Device>, <User_Public.txt>", file=sys.stderr) 