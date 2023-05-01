#!/usr/bin/python3
import ipaddress
import sys
import os
import json
import base64
import subprocess
import urllib.request
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from gopherbot_v2 import Robot

bot = Robot()

WG_CONF = '/etc/wireguard/wg0.conf'
username = os.getenv("GOPHER_USER")

def read_state():
    state = bot.CheckoutDatum("wg", True)
    if not state.exists:
        state.datum = {
            "Latest_IP": "",
            "Users": {}
        }
    return state


def delete_user(username, state):
    # If the user exists in state.datum['Users'], remove it
    if username in state.datum['Users']:
        del state.datum['Users'][username]
        bot.UpdateDatum(state)
        return True
    else:
        return False


def delete_device(username, device, state):
    if username in state.datum['Users'] and device in state.datum['Users'][username]:
        del state.datum['Users'][username][device]
        bot.UpdateDatum(state)
        return True
    else:
        return False


def read_wg_preamble():
    # read wg0.txt and store robot's private key
    with subprocess.Popen(['sudo', 'head', '-n', '6', WG_CONF], stdout=subprocess.PIPE) as p:
        preamble = p.stdout.read().decode()
        data = preamble.splitlines()
        base_IP = data[1].split(' ')[-1].strip()
        robot_private_key = data[2].split(' ')[-1].strip()
        robot_port = data[3].split(' ')[-1].strip()

    return preamble, base_IP, robot_private_key, robot_port


def write_wg(preamble, state):
    formatted_entries = ""
    # iterate over the users in the state file and add entries to wg0.txt
    for user, devices in state.datum['Users'].items():
        for device, device_data in devices.items():
            formatted_entry = f"\n[Peer]\n" \
                          f"# {user} | {device}\n" \
                          f"PublicKey = {device_data['PublicKey']}\n" \
                          f"PreSharedKey = {device_data['PreSharedKey']}\n" \
                          f"AllowedIPs = {device_data['AllowedIPs']}"
            formatted_entries += "\n" + formatted_entry
    # remove trailing whitespace
    formatted_entries = formatted_entries[:-1]
    preamble += formatted_entries
    
    # output updated wg0.txt
    with subprocess.Popen(["sudo", "tee", WG_CONF], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL) as p:
        p.communicate(preamble.encode())


def get_robot_IP():
    # retrieve robot IP
    url = 'https://cloudflare.com/cdn-cgi/trace'
    with urllib.request.urlopen(url) as response:
        data = response.read().decode('utf-8')
    # get only the ip line
    ip_line = [line for line in data.split('\n') if 'ip=' in line][0]
    robot_IP = ip_line.split('=')[-1]
    # combine
    return robot_IP

def encrypt(user_public, robot_private_key, robot_IP, user_IP):
    # decode and assign wg_private as a private Key object
    wg_private = base64.b64decode(robot_private_key)
    wg_private = nacl.public.PrivateKey(wg_private)
    
    # decode user and assign user_public as a public key object
    user_public_binkey = base64.b64decode(user_public)
    user_public_binkey = nacl.public.PublicKey(user_public_binkey)
    
    # create a wireguard box
    wg_box = Box(wg_private, user_public_binkey)
    user_psk = wg_box.shared_key()
    user_psk_str = base64.b64encode(user_psk)
    
    # encode the public key in base64
    user_public_str = base64.b64encode(user_public_binkey.encode())

    # combine both values into a string
    message = f"Robot_IP = {robot_IP} | USER_IP = {user_IP} | PSK = {user_psk_str.decode()}"
    
    # encrypt IP and PSK and return
    encrypted_config = base64.b64encode(wg_box.encrypt(message.encode())).decode()

    return encrypted_config, user_public_str, user_psk_str


def add_user_to_state(bot, device, user_public, state, base_IP, robot_private_key, robot_port):
    # Assigning IPs: if first entry, default to base_IP +1; else, increment latest IP by 1
    if state.datum["Latest_IP"] == "":
        base_interface = ipaddress.IPv4Interface(base_IP)
        base_network = base_interface.network.prefixlen
        user_IP = str(base_interface.ip + 1) + '/32'
        state.datum["Latest_IP"] = user_IP
    else:
        # Convert to IPv4Address for correct incrementing
        latest_interface = ipaddress.IPv4Interface(state.datum["Latest_IP"])
        latest_network = latest_interface.network.prefixlen
        user_IP = str(latest_interface.ip + 1) + '/32'
        state.datum["Latest_IP"] = user_IP

    # get robot port
    robot_IP = get_robot_IP()
    robot_IP = robot_IP + ":" + robot_port

    # encrypt
    encrypted_config, user_public_str, user_psk_str = encrypt(user_public, robot_private_key,robot_IP, user_IP)

    # new user to be added    
    entry = {
        "PublicKey" : user_public_str.decode(),
        "PreSharedKey" : user_psk_str.decode(),
        "AllowedIPs" : user_IP,
    }
    
    # if user does not have a preexisting username, create one. 
    # if so, add new device to the list of devices asssociated with the username
    if f"{username}" in state.datum["Users"]:
        if f"{device}" in state.datum["Users"][f"{username}"]:
            bot.CheckinDatum(state)
            bot.Say("Error: Device Already Added.")
            exit(0)
    else:
        state.datum["Users"][f"{username}"] = {}

    state.datum["Users"][f"{username}"][f"{device}"] = entry
    bot.UpdateDatum(state)

    return state, encrypted_config


def get_user_device_config(bot, device, user_public, state, robot_private_key, robot_port):
    # get user_IP
    if username in state.datum['Users'] and device in state.datum['Users'][username]:
            user_IP = state.datum['Users'][username][device]["AllowedIPs"]
    else:
        bot.Say(f"Error: User '{username}' or device '{device}' not found")
        exit(1)

    # get robot port
    robot_IP = get_robot_IP()
    robot_IP = robot_IP + ":" + robot_port

    # encrypt
    encrypted_config, user_public_str, user_psk_str = encrypt(user_public, robot_private_key,robot_IP, user_IP)

    return encrypted_config


# Command Line Arguments

executable = sys.argv.pop(0)
command = sys.argv.pop(0)

# needed for real robot
if command == "configure":
    exit(0)

preamble, base_IP, robot_private_key, robot_port = read_wg_preamble()

# robot: CheckoutDatum
state = read_state()

if command == "admin-list-vpn-users":
    # dictionary of vpn devices grouped by user
    user_devices = {}
    for username, devices in state.datum['Users'].items():
        user_devices[username] = [device for device in devices.keys()]
    
    # list of strings containing user and devices
    user_list = []
    for username, devices in user_devices.items():
        devices_string = ', '.join(devices)
        user_list.append(f"{username}: {devices_string}")
    user_list_string = '\n'.join(user_list)

    if user_list_string:
        bot.Say(f"\n{user_list_string}")
    else:
        bot.Say("No Users Found.")
    exit(0)

if command == "admin-delete-vpn-user":
    username = sys.argv.pop(0).lower()
    if delete_user(username, state):
        bot.Say(f"User '{username}' deleted successfully.")
    else:
        bot.Say(f"User '{username}' not found.")
    exit(0)


if command == "add-device":
    device = sys.argv.pop(0).lower()
    user_public = sys.argv.pop(0)
    state, encrypted_config = add_user_to_state(bot, device, user_public, state, base_IP, robot_private_key, robot_port)
    bot.Say(f"\nPaste in Terminal:\n./WgSetup.py {bot.GetBotAttribute('name')} {device} {encrypted_config}")
    exit(0)

if command == "list-vpn-devices":
    if username in state.datum['Users']:
        devices = state.datum['Users'][username]
        device_list = ', '.join(devices.keys())
        devices_message = f"Device(s) for user '{username}': {device_list}\n"
    else:
        devices_message = f"No devices found for user '{username}'\n"
    bot.Say(devices_message)
    exit(0)


if command == "delete-device":
    device = sys.argv.pop(0).lower()
    if delete_device(username, device, state):
        bot.Say(f"Device '{device}' deleted successfully.")
    else:
        bot.Say(f"Device '{device}' not found for user '{username}'.")
    exit(0)

if command == "get-vpn":
    device = sys.argv.pop(0).lower()
    if username in state.datum['Users']:
        devices = state.datum['Users'][username]
        if device in devices:
            user_public = devices[device]["PublicKey"]
            encrypted_config = get_user_device_config(bot, device, user_public, state, robot_private_key, robot_port)
            bot.Say(f"\nPaste in Terminal:\n./WgSetup.py {bot.GetBotAttribute('name')} {device} {encrypted_config}")
        else:
            bot.Say(f"Device '{device}' not found for user '{username}'")
    else:
        bot.Say(f"No devices found for user '{username}'")
    exit(0)


write_wg(preamble, state)

if os.getenv("GOPHER_PROTOCOL") != "terminal":
    os.system("sudo systemctl reload wg-quick@wg0")
