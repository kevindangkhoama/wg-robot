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
    
    # Write the private and public keys as strings to the home directory
    with open(os.path.join(home_dir, 'User_Private.txt'), 'w') as fp:
        fp.write(str(userprivate))
    with open(os.path.join(home_dir, 'User_Public.txt'), 'w') as fp:
        fp.write(str(userpublic))

    
def Decrypter(robot_public, user_private, encrpyted):
    # Create User Box
    user_box = Box(user_private, robot_public)
    
    # Decrypt base64 encrypted config and return
    decoded = user_box.decrypt(base64.b64decode(encrpyted))
    print(decoded.decode('utf-8'))
    
    
# Command Line Arguments    
if len(sys.argv) == 1:
    print("Generating Keys...")
    Generate()
    print("Done")
elif len(sys.argv) == 3:
    print("Decrypting...")
    sys.argv.pop(0)
    encrpyted_config = sys.argv.pop(0)
    robot_public = ""
    user_private = sys.argv.pop(0)
    Decrypter(robot_public, user_private, encrpyted_config)
    print("Done")
else:
    # Invalid Command
    print("Invalid argument(s)")
    print("Usage:")
    print("Generate Keys: WgSetup.py", file=sys.stderr)
    print("Decrypt: WgSetup.py <Ecrypted> <User_Private>", file=sys.stderr)
    sys.exit(1)