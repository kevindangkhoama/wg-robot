# WireGuard Robot
Final product located in Gopherbot file.

WgSetup.py: Python script that allows users to generate private and public key pairs for their devices. Additionally allows the user to decrypt configs generated by Robot.py by providing the specified robot they wish to configure WireGuard with, their private key, and the encrypted file.

Robot.py: Python script that will take a user's public key and the robot's private key to create a preshared key. An IP will then be assigned and both the IP and the preshared key will be encrypted in base64 and sent to the user.

> Both scripts have functionality for printing the encrpyted keys and config or saving said files as a .txt in the home directory.
