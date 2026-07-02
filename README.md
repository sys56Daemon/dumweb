# airIsLeaking — Educational WiFi Packet-Sniffing Demo

An educational demonstration server designed for cybersecurity classes to showcase how unencrypted network traffic (HTTP) leaves sensitive credentials vulnerable to packet sniffing using tools like Wireshark.

This repository hosts a simulated portal featuring multiple realistic, simplified login portals (SecurePortal, Instagram clone, Google clone) and a local LAN chatroom.

> [!WARNING]
> This application is strictly for educational, testing, and classroom demonstration purposes. Only run this server on networks you own or have explicit authorization to audit.

---

## 📋 Features
- **Clean Center-Card SecurePortal:** Center-card login portal with dynamic animations and input validation.
- **Realistic Instagram Login Page:** Replica of the official mobile login web page.
- **Realistic Google Login Page:** Outlined Google Accounts layout with floating active label.
- **LAN Chatroom:** A shared local-network chat room that auto-fills usernames passed from logins.
- **Plaintext Transmission:** Submissions travel over unencrypted HTTP POST requests, rendering them fully visible to packet capture tools.
- **Admin Dashboard:** A dashboard at `/admin` (auth-gated) summarizing all captured credentials.

---

## 🛠️ Prerequisites & Installation

### 🐧 Linux (Ubuntu/Debian)

#### 1. Install Git
```bash
sudo apt update
sudo apt install -y git
```

#### 2. Install Node.js & npm
We recommend using the NodeSource LTS repository for a modern Node.js version:
```bash
# Download and install NodeSource setup script
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -

# Install Node.js
sudo apt install -y nodejs
```

---

### 🪟 Windows

#### 1. Install Git
Download and run the official Git for Windows installer: [Git for Windows](https://git-scm.com/download/win).

#### 2. Install Node.js
Download and run the official Node.js installer: [Node.js Official Website](https://nodejs.org/). Make sure you select the option to **"Add to PATH"** during setup.

Once installed, open a fresh command prompt (CMD or PowerShell) and check the versions:
```cmd
node -v
npm -v
git --version
```

---

## 🚀 Running the Web App

1. Clone the repository and navigate into the project directory:
   ```bash
   git clone https://github.com/sys56daemon/dumweb.git
   cd dumweb
   ```
2. Install the required Node packages:
   ```bash
   npm install
   ```
3. Launch the server:
   ```bash
   node server.js
   ```

The application will start, printing your server's local network (LAN) IP. Tell your attendees to open that link (e.g., `http://192.168.1.100:8080`) on their devices.

---

## 🕵️ How to Sniff Credentials with Wireshark

To demonstrate packet capture:
1. Ensure the attacker machine running Wireshark and the victim client device are on the **same Wi-Fi network**.
2. Open Wireshark on the attacker machine and double-click your active network interface (e.g., `Wi-Fi` or `Ethernet`).
3. Set the display filter bar to target the demo app's port:
   ```text
   http && tcp.port == 8080
   ```
4. Have the victim log in via any of the portals (SecurePortal, Instagram, or Google).
5. In Wireshark, look for the `POST /submit`, `POST /instagram-submit`, or `POST /google-submit` packet.
6. Right-click the packet, select **Follow** ➜ **TCP Stream** to inspect the plaintext `username` and `password` payload.

---

## ⚡ The Quick One-Liner

When you are on a fresh Linux or Windows machine (with Git and Node already installed), copy-paste this single command line to set up and start the application instantly:

```bash
git clone https://github.com/sys56daemon/dumweb.git && cd dumweb && npm install && node server.js
```
