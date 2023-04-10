#!/usr/bin/python3
import sys
import os
import nacl.utils
import base64
import subprocess
from nacl.public import PrivateKey,PublicKey, Box

home_dir = os.path.expanduser('~')

# format: 'robot' : ["public_key"],
robot_table = {
        'ram': 'PyCIhvAiBFNxP8Ka5MOhvqq9Q3LkBAddWBjlbb5HDUA=',
        'tron': 'Public Key2',
        'flynn': 'Public Key3'
        }

def find_robot(robot):
    robot_lower = robot.lower()
    if robot_lower not in robot_table:
        print(f"{robot} not found. \n")
        print("Available Robots: ")
        for r in robot_table:
            print(f"{r}".capitalize())
        sys.exit(1)
            
            
def wg_data(device):    
    wg_data_dir = os.path.join(home_dir, '.wireguard_data')
    
    # check if .wireguard_data exists
    if not os.path.exists(wg_data_dir):
        os.mkdir(wg_data_dir)
        os.chmod(wg_data_dir, 0o700)
    
    # create robot directory if it doesn't exist
    robot_dir = os.path.join(wg_data_dir, robot.lower())
    if not os.path.exists(robot_dir):
        os.mkdir(robot_dir)
        os.chmod(robot_dir, 0o700)
    
    # create device directory if it doesn't exist
    device_dir = os.path.join(robot_dir, device.lower())
    if not os.path.exists(device_dir):
        os.mkdir(device_dir)
        os.chmod(device_dir, 0o700)
        
    return device_dir    
       

def generate_keys(robot, device):
    # check if robot exists
    find_robot(robot)
    
    # create key pairs
    user_private_key = PrivateKey.generate()
    user_public_key = user_private_key.public_key
    
    user_private_key = base64.b64encode(user_private_key.encode())
    user_public_key = base64.b64encode(user_public_key.encode())
    
    print(f"\nHere is your Public Key: {user_public_key.decode()}")
    print(f"Public Key and Private Key stored at {device_dir}\n")
    
    # write the private and public keys as strings to the home directory
    with open(os.path.join(device_dir, f'{device}_private.txt'), 'wb') as f:
        f.write(user_private_key)
        
    with open(os.path.join(device_dir, f'{device}_public.txt'), 'wb') as f:
        f.write(user_public_key)
    
    
def decrypt_config(robot, device, encrpyted_config):
    # check if robot exists
    find_robot(robot)  
     
    # find private key
    private_dir = f'{device_dir}/{device}_private.txt'
    # run the command with sudo privileges and capture the output
    proc = subprocess.Popen(['sudo', 'cat', private_dir], stdout=subprocess.PIPE)
    user_private_key = proc.communicate()[0]
        
    # decode all base64 variables
    encrypted_config = base64.b64decode(encrpyted_config)
    robot = base64.b64decode(robot_table[robot.lower()])
    user_private_key = base64.b64decode(user_private_key)
    
    # convert into key objects
    robot = nacl.public.PublicKey(robot)
    user_private_key = nacl.public.PrivateKey(user_private_key)
        
        
    # create user box
    user_box = Box(user_private_key, robot)
    
    # decrypt encrypted config
    decoded_config = user_box.decrypt(encrypted_config)
    
    print(f"\nHere is your Decoded Config: {decoded_config.decode()}")
    # export to text file
    with open(os.path.join(device_dir, f'{device}_decrypted_config.txt'), 'w') as fp:
        fp.write(decoded_config.decode())
    
    print(f"Decoded Config stored at {device_dir}\n")


# Command Line Arguments    
if len(sys.argv) == 3:
    print("Generating Keys...")
    # create private and public Keys
    sys.argv.pop(0)
    robot = sys.argv.pop(0)
    device = sys.argv.pop(0)
    device = device.lower()
    
    # assign where to store device info
    device_dir = wg_data(device)
    generate_keys(robot, device)
    print("Done")
    
elif len(sys.argv) == 4:
    print("Decrypting...")
    # assign variables
    sys.argv.pop(0)
    robot = sys.argv.pop(0)
    device = sys.argv.pop(0)
    device = device.lower()
    encrypted_config = sys.argv.pop(0)
    device_dir = wg_data(device)
    
    # run decrypter    
    decrypt_config(robot, device, encrypted_config)
    
    print("Done")
    
else:
    # invalid command
    print("Invalid argument(s)\n")
    print("Usage:")
    print("Generate Keys: WgSetup.py, <Robot>, <Device>", file=sys.stderr)
    print("Decrypt: WgSetup.py <Robot>, <Device>, <Ecrypted>", file=sys.stderr)
    exit(0)