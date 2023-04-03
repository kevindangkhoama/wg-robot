#!/usr/bin/python3
import sys
import os
import nacl.utils
import base64
import subprocess
from nacl.public import PrivateKey,PublicKey, Box

home_dir = os.path.expanduser('~')

def wgdata(device, robot):
    home_dir = os.path.expanduser('~')
    wg_data_dir = os.path.join(home_dir, 'wireguard_data')
    
    # Check if .wireguard_data exists
    if not os.path.exists(wg_data_dir):
        os.mkdir(wg_data_dir)
        os.chmod(wg_data_dir, 0o700)
    
    # Create robot directory if it doesn't exist
    robot_dir = os.path.join(wg_data_dir, robot)
    if not os.path.exists(robot_dir):
        os.mkdir(robot_dir)
        os.chmod(robot_dir, 0o700)
    
    # Create device directory if it doesn't exist
    device_dir = os.path.join(robot_dir, device)
    if not os.path.exists(device_dir):
        os.mkdir(device_dir)
        os.chmod(device_dir, 0o700)
        
    return device_dir    
       

def Generate(device):
    # Create Key Pairs
    userprivate = PrivateKey.generate()
    userpublic = userprivate.public_key
    
    userprivate = base64.b64encode(userprivate.encode())
    userpublic = base64.b64encode(userpublic.encode())
    
    print(f"Here is your private key: {userprivate.decode()}")
    print(f"Here is your public key: {userpublic.decode()}")
    
    # Write the private and public keys as strings to the home directory
    with open(os.path.join(device_dir, f'{device}_Private.txt'), 'wb') as fp:
        fp.write(userprivate)
        
    with open(os.path.join(device_dir, f'{device}_Public.txt'), 'wb') as fp:
        fp.write(userpublic)
        
    print(f"Keys stored at {device_dir}")
    
def Decrypter(robot, device, encrpyted):
    # Format: 'Robot' : ["Public Key"],
    robot_table = {
        'Ram': 'PyCIhvAiBFNxP8Ka5MOhvqq9Q3LkBAddWBjlbb5HDUA=',
        'Tron': 'Public Key2',
        'Flynn': 'Public Key3'
        }
    
    # Find private key
    private_dir = f'{device_dir}/{device}_Private.txt'
    # run the command with sudo privileges and capture the output
    proc = subprocess.Popen(['sudo', 'cat', private_dir], stdout=subprocess.PIPE)
    user_private = proc.communicate()[0]
        
    # Decode all base64 variables
    encrypted = base64.b64decode(encrpyted)
    robot = base64.b64decode(robot_table[robot])
    user_private = base64.b64decode(user_private)
    
    # Convert into Key objects
    robot = nacl.public.PublicKey(robot)
    user_private = nacl.public.PrivateKey(user_private)
    
    # Create User Box
    user_box = Box(user_private, robot)
    
    # Decrypt encrypted config
    decoded = user_box.decrypt(encrypted)
    
    print(f"Here is your Decoded Config: {decoded.decode()}")
    # Export to text file
    with open(os.path.join(device_dir, f'{device}_Decrypted_Config.txt'), 'w') as fp:
        fp.write(decoded.decode())
    
    print(f"Decoded Config stored at {device_dir}")

# Command Line Arguments    
if len(sys.argv) == 3:
    print("Generating Keys...")
    # Create Private and Public Keys
    sys.argv.pop(0)
    robot = sys.argv.pop(0)
    device = sys.argv.pop(0)
    
    # assign where to store device info
    device_dir = wgdata(device, robot)
    Generate(device)
    print("Done")
    
elif len(sys.argv) == 4:
    print("Decrypting...")
    # Assign variables
    sys.argv.pop(0)
    robot = sys.argv.pop(0)
    device = sys.argv.pop(0)
    encrypted = sys.argv.pop(0)
    device_dir = wgdata(device, robot)
    
    # Run decrypter    
    Decrypter(robot, device, encrypted)
    
    print("Done")
    
else:
    # Invalid Command
    print("Invalid argument(s)")
    print("Usage:")
    print("Generate Keys: WgSetup.py, <Robot>, <Device>", file=sys.stderr)
    print("Decrypt: WgSetup.py <Robot>, <Device>, <Ecrypted>", file=sys.stderr)
    sys.exit(1)