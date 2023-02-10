import nacl.utils
import base64
from nacl.public import PrivateKey,PublicKey, Box

def WgSetupGenerate(user_public, wg_private):
    # WireGuard private key
    # wg_private = ""
    
    # Create a WireGuard Box
    wg_box = Box(wg_private, user_public)
    
    # Generate IP and preshared key
    user_ip = "10.77.0.7"
    user_psk = wg_box.shared_key()
    
    # Combine both values into a string
    message = f"USER_IP={user_ip} | PSK={user_psk}"
    print(message)
    
    # Encrypt IP and PSK and return
    encrypted = base64.b64encode(wg_box.encrypt(message.encode()))
    return encrypted

def WgSetupConfigure(robot_public, user_private, encrpyted):
    # Create User Box
    user_box = Box(user_private, robot_public)
    
    # Decode encrypted config and return
    decoded = user_box.decrypt(base64.b64decode(encrpyted))
    print(decoded.decode('utf-8'))


# Testing    
if __name__ == "__main__":
    # Test User
    testuserprivate = PrivateKey.generate()
    testuserpublic = testuserprivate.public_key
    
    # Random WireGuard key pair 
    testwgprivate = PrivateKey.generate()
    testwgpublic = testwgprivate.public_key

    # Test Functions
    encrpyted_config = WgSetupGenerate(testuserpublic, testwgprivate)
    print("\n")
    print(encrpyted_config)
    print("\n")
    WgSetupConfigure(testwgpublic, testuserprivate, encrpyted_config)