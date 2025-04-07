# VPN Provisioning Plugin for Slack-Based Infrastructure Automation

This project is a custom VPN provisioning plugin built for **GopherBot**, an open-source ChatOps automation framework. It enables internal team members to request and configure secure VPN connections in real-time via Slack commands.

Developed during my internship at **Welld Health**, this tool empowers IT and DevOps teams to streamline VPN access using **WireGuard**, **PyNaCl**, and Linux networking.

---

## Key Features

- 🔑 **Asymmetric Encryption** for secure key exchange and device authentication using `PyNaCl`
- 📡 **Real-Time VPN Provisioning** via Slack commands through GopherBot integrations
- 🔧 **WireGuard Configuration Automation** with dynamic key generation, IP assignment, and routing setup
- 🧩 **System-Level Networking** via Bash NAT scripts (`PostUp`, `PostDown`) for seamless device routing
- 🛠️ **Slack CLI-Like Commands** defined in YAML for admin/user-level access and lifecycle control

---

## Project Structure

| File | Description |
|------|-------------|
| `robot_plugin.py` | Main GopherBot plugin logic handling Slack-triggered VPN commands (e.g. `add-device`, `get-vpn`) |
| `wireguard.yaml` | Defines Slack command matchers for VPN provisioning and admin tasks |
| `Robot.py` | Handles encryption/decryption using `PyNaCl`; manages secure device provisioning |
| `WgSetup.py` | CLI script for generating and decrypting WireGuard keys on local user devices |
| `wg0.txt` | WireGuard configuration template used for backend provisioning |
| `Robot_Private.txt` / `Robot_Public.txt` | Public/private keys used for the provisioning server |
| `requirements.txt` | Python dependencies (`PyNaCl`, `cffi`, `rpdb`) |

---

## Example Slack Commands

```bash
(bot), add-device kevins-laptop <public_key>
(bot), get-vpn kevins-laptop
(bot), list-vpn-devices
(bot), delete-device kevins-laptop
(bot), list-vpn-users          # admin
(bot), delete-vpn-user kevin   # admin
```
---

## Notes
This system handles VPN setup through Slack but requires users to finalize configuration via WgSetup.py.

All device credentials are encrypted and provisioned securely, with automated WireGuard config updates.
