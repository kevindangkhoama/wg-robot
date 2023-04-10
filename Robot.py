#!/usr/bin/python3
import ipaddress
import sys
import os
import json
import base64
import subprocess
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

home_dir = os.path.expanduser('~')

def read_state():
    state_path = os.path.join(home_dir, 'state.json')
    if not os.path.exists(state_path):
        state = {
            "Latest_IP": "",
            "Users": {}
        }
        state = json.dumps(state, indent=4)
        with open(os.path.join(home_dir, 'state.json'), 'w') as f:
            f.write(state)
            
    with open(os.path.join(home_dir, 'state.json'),'r') as file:
            state = json.load(file)
    return state
        
def read_wg_preamble():
    # Read wg0.txt
    with subprocess.Popen(['sudo', 'head', '-n', '6', 'wg0.txt'], stdout=subprocess.PIPE) as p:
        preamble = p.stdout.read().decode()
    
    # Store Private Key 
    with subprocess.Popen(["sudo", "cat", "wg0.txt"], stdout=subprocess.PIPE) as p:
        output = p.stdout.read().decode()
    data = output.splitlines()
    robot_private_key = data[2].split(' ')[-1].strip()
    
    return preamble, robot_private_key


def write_wg(preamble, state):
    formatted_entries = ""
    
    # Iterate over the users in the state file and add entries to wg0.txt
    for user, devices in state['Users'].items():
        for device, device_data in devices.items():
            formatted_entry = f"\n[Peer]\n" \
                          f"{user} | {device}\n" \
                          f"PublicKey = {device_data['PublicKey']}\n" \
                          f"PreSharedKey = {device_data['PreSharedKey']}\n" \
                          f"AllowedIPs = {device_data['AllowedIPs']}\n" \
                          f"PersistentKeepAlive = 25"
            formatted_entries += "\n" + formatted_entry
    formatted_entries = formatted_entries[:-1]
    preamble += formatted_entries
    
    with subprocess.Popen(["sudo", "tee", "wg0.txt"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL) as p:
        p.communicate(preamble.encode())
        
        
def assign_IP(state):    
    # Assigning IPs if first entry default to 10.77.0.2 else increment latest IP by 1
    if state["Latest_IP"] == "":
        state["Latest_IP"] = "10.77.0.2"
        user_ip = "10.77.0.2"
    else:
        latest_IP_int = ipaddress.IPv4Address(state["Latest_IP"])
        latest_IP_int +=1
        state["Latest_IP"] = str(ipaddress.IPv4Address(latest_IP_int))
        user_ip = str(ipaddress.IPv4Address(latest_IP_int))
    return user_ip


def add_user_to_state(username, device, user_public, state, robot_private_key):
    # Decode and assign wg_private as a Private Key object
    wg_private = base64.b64decode(robot_private_key)
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

    # Assign IP:
    user_ip = assign_IP(state)
    
    # New User to be added    
    entry = {
        f"{device}": {
            "PublicKey" : user_public.decode(),
            "PreSharedKey" : str(user_psk.decode()),
            "AllowedIPs" : user_ip,
        }
    }
    
    # If user does not have a preexisting username, create one. 
    # If so, add new device to the list of devices asssociated with the username
    if f"{username}" not in state["Users"]:
        state["Users"][f"{username}"] = entry
    else:
        if f"{device}" in state["Users"][f"{username}"]:
            print("Error: Device Already Added")
            sys.exit(1)
        else:
            state["Users"][f"{username}"] |= entry
    
    # Output newly updated state.json file
    state = json.dumps(state, indent=4)
    with open(os.path.join(home_dir, 'state.json'), 'w') as f:
        f.write(state)
    
    # Update wg0.txt with new state.json file
    state = read_state()
    write_wg(preamble, state)
            

    # User side:
    # Combine both values into a string
    message = f"USER_IP = {user_ip} | PSK = {user_psk.decode()}"
    
    # Encrypt IP and PSK and return
    encrypted_config = base64.b64encode(wg_box.encrypt(message.encode()))
    return state, encrypted_config




# Command Line Arguments
if len(sys.argv) == 1:
    print("Usage")
    print("init: Robot.py \"init\"", file=sys.stderr)
    print("Encrypt: Robot.py <User> <Device> <Device_Public>", file=sys.stderr)
    exit(0)

executable = sys.argv.pop(0)
command = sys.argv.pop(0)

# Needed for real robot
if command == "configure":
    exit(0)

preamble,robot_private_key = read_wg_preamble()

# Robot: CheckoutDatum
state = read_state()

if command != "init":
    username = sys.argv.pop(0).lower()
    device = sys.argv.pop(0).lower()
    user_public = sys.argv.pop(0)
    state, encrypted_config = add_user_to_state(username, device, user_public, state, robot_private_key)
    # add_user_to_state generates an error message if needed and returns False, ""
    # otherwise returns True, "<base64 encoded encrypted config string>"
    print(f"\nEncrypted config: {encrypted_config}\n")


# write_wg(preamble, state)

# if reload:
#   print("(reloading wireguard)")