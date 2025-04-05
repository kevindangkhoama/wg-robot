# 🛡️ VPN Provisioning Plugin for Slack-Based Infrastructure Automation

## Overview
This project is a custom plugin built for **GopherBot**, an open-source ChatOps automation tool. It enables secure and automated **VPN provisioning** for internal users via **Slack commands**, integrating with **WireGuard**, **PyNaCl**, and system-level networking scripts.

Originally developed during my internship at **Welld Health**, this plugin empowers IT and DevOps teams to provision VPN access in seconds using simple, CLI-style chat interactions.

---

## 🔧 Key Features
- 🔐 **Asymmetric encryption** for secure key management using `PyNaCl`
- 🧰 **WireGuard VPN configuration** automation with private/public key pairing
- 💬 **Slack command integration** via GopherBot using `wireguard.yaml` definitions
- ⚙️ **System-level VPN setup** triggered via WireGuard config + Bash NAT scripts
- 🧑‍💻 Real-time VPN provisioning for new devices and users

---

## 📂 Project Structure

| File                      | Description                                                       |
|---------------------------|-------------------------------------------------------------------|
| `robot_plugin.py`         | Main backend logic handling Slack-triggered VPN commands          |
| `wireguard.yaml`          | Defines GopherBot command patterns (e.g. `add-device`, `get-vpn`) |
| `WgSetup.py`              | Generates WireGuard configuration files for new devices           |
| `Robot.py`                | Handles encryption/decryption of keys using PyNaCl                |
| `Robot_Private.txt`       | Private key used for VPN configuration                            |
| `Robot_Public.txt`        | Public key used for VPN configuration                             |
| `wg0.txt`                 | Base WireGuard config template, includes Bash script hooks        |

---

## ⚙️ Tech Stack
- **Python**
- **GopherBot** (Slack ChatOps engine)
- **PyNaCl** for encryption
- **WireGuard** for VPN tunnels
- **Bash scripts** for NAT + post-connection config
- **YAML** for bot command definitions

---

## 🧪 Example Slack Commands

```text
(bot), add-device kevins-laptop <public_key>
(bot), list-vpn-devices
(bot), get-vpn kevins-laptop
(bot), delete-device kevins-laptop
(bot), list-vpn-users
(bot), delete-vpn-user kevin
