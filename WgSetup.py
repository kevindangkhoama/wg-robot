#!/usr/bin/python3
import sys
import os
import nacl.utils
import base64
from nacl.public import PrivateKey,PublicKey, Box

def Generate():
    # Create Key Pairs
    userprivate = PrivateKey.generate()
    userpublic = userprivate.public_key
    
    userprivate = base64.b64encode(userprivate.encode())
    userpublic = base64.b64encode(userpublic.encode())
    
    print(f"Here is your private key: {userprivate.decode()}")
    print(f"Here is your public key: {userpublic.decode()}")
    
    # # Get the absolute path of the home directory
    # home_dir = os.path.expanduser('~')
    
    # # Write the private and public keys as strings to the home directory
    # with open(os.path.join(home_dir, 'User_Private.txt'), 'wb') as fp:
    #     fp.write(userprivate)
        
    # with open(os.path.join(home_dir, 'User_Public.txt'), 'wb') as fp:
    #     fp.write(userpublic)

    
def Decrypter(robot, user_private, encrpyted):
    # Format: 'Robot' : ["Public Key"],
    robot_table = {
        'Ram': 'W6zJkCbIPNJLhtlUdDemzwNbNLk7MRvsxMICLB1Z5Ck=',
        'Tron': 'Public Key2',
        'Flynn': 'Public Key3'
        }
    
    # Decode all base64 variables
    encrypted = base64.b64decode(encrpyted)
    robot = base64.b64decode(robot_table[robot])
    user_private = base64.b64decode(user_private)
    
    # Convert into Key objectss
    robot = nacl.public.PublicKey(robot)
    user_private = nacl.public.PrivateKey(user_private)
    
    # Create User Box
    user_box = Box(user_private, robot)
    
    # Decrypt encrypted config
    decoded = user_box.decrypt(encrypted)
    
    print(f"Here is your decoded config: {decoded.decode()}")
    # # Export to text file
    # home_dir = os.path.expanduser('~')
    # with open(os.path.join(home_dir, 'Decrypted_Config.txt'), 'w') as fp:
    #     fp.write(decoded)
    

# Command Line Arguments    
if len(sys.argv) == 1:
    print("Generating Keys...")
    # Create Private and Public Keys
    Generate()
    print("Done")
    
elif len(sys.argv) == 4:
    print("Decrypting...")
    sys.argv.pop(0)
    robot = sys.argv.pop(0)
    encrypted = sys.argv.pop(0)
    user_private = sys.argv.pop(0)
    
    # # Open text files and store as a variable
    # with open('Encrypted_Config.txt', 'r') as fp:
    #     encrypted = fp.read()
    # with open('User_Private.txt', 'r') as fp:
    #     user_private = fp.read()
    
    # Run decrypter    
    Decrypter(robot, user_private, encrypted)
    
    print("Done")
    
else:
    # Invalid Command
    print("Invalid argument(s)")
    print("Usage:")
    print("Generate Keys: WgSetup.py", file=sys.stderr)
    print("Decrypt: WgSetup.py <Robot>, <Ecrypted> <User_Private>", file=sys.stderr)
    sys.exit(1)