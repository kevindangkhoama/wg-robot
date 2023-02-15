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
    # Get the absolute path of the home directory
    home_dir = os.path.expanduser('~')
    
    userprivate = base64.b64encode(userprivate.encode())
    userpublic = base64.b64encode(userpublic.encode())
    
    # Write the private and public keys as strings to the home directory
    with open(os.path.join(home_dir, 'User_Private.txt'), 'wb') as fp:
        fp.write(userprivate)
    with open(os.path.join(home_dir, 'User_Public.txt'), 'wb') as fp:
        fp.write(userpublic)

    
def Decrypter(robot_public, user_private, encrpyted):
    # Decode all base64 variables
    encrypted = base64.b64decode(encrpyted)
    robot_public = base64.b64decode(robot_public)
    user_private = base64.b64decode(user_private)
    
    # Convert into Key objects
    robot_public = nacl.public.PublicKey(robot_public)
    user_private = nacl.public.PrivateKey(user_private)
    
    # Create User Box
    user_box = Box(user_private, robot_public)
    
    # Decrypt encrypted config
    decoded = user_box.decrypt(encrypted)
    decoded = decoded.decode('utf-8')
    
    # Export to text file
    home_dir = os.path.expanduser('~')
    with open(os.path.join(home_dir, 'Decrypted_Config.txt'), 'w') as fp:
        fp.write(decoded)
    

# Command Line Arguments    
if len(sys.argv) == 1:
    print("Generating Keys...")
    # Create Private and Public Keys
    Generate()
    print("Done")
    
elif len(sys.argv) == 3:
    print("Decrypting...")

    robot_public = "dnBijRHCphJpBoNxFuflGQqpWS8pWbnOBlPLQHNn3H0="
    
    # Open text files and store as a variable
    with open('Encrypted_Config.txt', 'r') as fp:
        encrypted = fp.read()
    with open('User_Private.txt', 'r') as fp:
        user_private = fp.read()
    
    # Run decrypter    
    Decrypter(robot_public, user_private, encrypted)
    
    print("Done")
    
else:
    # Invalid Command
    print("Invalid argument(s)")
    print("Usage:")
    print("Generate Keys: WgSetup.py", file=sys.stderr)
    print("Decrypt: WgSetup.py <Ecrypted> <User_Private>", file=sys.stderr)
    sys.exit(1)
