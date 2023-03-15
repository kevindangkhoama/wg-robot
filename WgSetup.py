#!/usr/bin/python3
import sys
import os
import nacl.utils
import base64
from nacl.public import PrivateKey,PublicKey, Box

home_dir = os.path.expanduser('~')

def Generate(device):
    # Create Key Pairs
    userprivate = PrivateKey.generate()
    userpublic = userprivate.public_key
    
    userprivate = base64.b64encode(userprivate.encode())
    userpublic = base64.b64encode(userpublic.encode())
    
    print(f"Here is your private key: {userprivate.decode()}")
    print(f"Here is your public key: {userpublic.decode()}")
    
    # Write the private and public keys as strings to the home directory
    with open(os.path.join(home_dir, f'{device}_Private.txt'), 'wb') as fp:
        fp.write(userprivate)
        
    with open(os.path.join(home_dir, f'{device}_Public.txt'), 'wb') as fp:
        fp.write(userpublic)

    
def Decrypter(robot, user_private, encrpyted):
    # Format: 'Robot' : ["Public Key"],
    robot_table = {
        'Ram': 'PyCIhvAiBFNxP8Ka5MOhvqq9Q3LkBAddWBjlbb5HDUA=',
        'Tron': 'Public Key2',
        'Flynn': 'Public Key3'
        }
    
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
    
    print(f"Here is your decoded config: {decoded.decode()}")
    # Export to text file
    with open(os.path.join(home_dir, f'{device}_Decrypted_Config.txt'), 'w') as fp:
        fp.write(decoded)
    

# Command Line Arguments    
if len(sys.argv) == 2:
    print("Generating Keys...")
    # Create Private and Public Keys
    sys.argv.pop(0)
    device = sys.argv.pop(0)
    Generate(device)
    print("Done")
    
elif len(sys.argv) == 4:
    print("Decrypting...")
    sys.argv.pop(0)
    robot = sys.argv.pop(0)
    user_private = sys.argv.pop(0)
    encrypted = sys.argv.pop(0)
    # Store txt file name as a variable
    device = os.path.splitext(user_private)[0].replace('_Public', '')
    # Open text files and store as a variable
    with open(f'{device}_Encrypted_Config.txt', 'r') as fp:
        encrypted = fp.read()
    with open(f'{device}_Private.txt', 'r') as fp:
        user_private = fp.read()
    
    # Run decrypter    
    Decrypter(robot, user_private, encrypted)
    
    print("Done")
    
else:
    # Invalid Command
    print("Invalid argument(s)")
    print("Usage:")
    print("Generate Keys: WgSetup.py, <Device>", file=sys.stderr)
    print("Decrypt: WgSetup.py <Robot>, <User_Private>, <Ecrypted>", file=sys.stderr)
    sys.exit(1)