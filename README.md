# Burp Suite Tor Proxy Manager Extension

This extension allows you to start, stop, and manage the [Tor](https://www.torproject.org/) proxy directly from the Burp Suite user interface. This makes it easy to toggle your anonymity layer with a single click during penetration tests or web analysis.

 ## ✨ Features

  - **One-Click Control:** Start and stop the Tor proxy without leaving the Burp UI.
  - **Auto-Path Detection:** Automatically detects the default executable `tor` file on Windows, macOS (Homebrew), and Linux systems.
  - **Instant Validation & Feedback:**
      - The path input field turns **green** when a valid `tor` executable path is provided.
      - The input field turns **pink/red** for an invalid path.
      - The "ON" button is enabled only when a valid and executable path is specified.
  - **Non-Blocking UI:** Start/stop operations run in the background, preventing the Burp Suite UI from freezing.
  - **Cross-Platform:** Works on Windows, macOS, and Linux.

## ⚙️ Requirements

To run this extension, you must have the following installed and configured:

1.  **Burp Suite:** Community or Professional Edition.
2.  **Jython Standalone JAR:** Burp Suite requires Jython to run Python-based extensions. The recommended version is the `2.7.x` series.
      - **Required File:** `jython-standalone-2.7.4.jar` (or a compatible version like `2.7.3`).
      - **Download Link:** [Jython Official Website](https://www.jython.org/download)
3.  **Tor:** The Tor client must be installed on your system.
      - **For Windows:** Download the [Tor Expert Bundle](https://www.torproject.org/download/tor/) and extract it to a folder.
      - **For macOS:** You can install it via Homebrew using the command `brew install tor`.
      - **For Linux:** You can install it using `sudo apt-get install tor` or the appropriate package manager for your distribution.

## 🚀 Installation

1.  **Configure Jython in Burp Suite:**

      - Open Burp Suite and navigate to the **Extender -\> Options** tab.
      - In the "Python Environment" section, under the "Location of Jython standalone JAR file" heading, click the **"Select file..."** button.
      - Locate and select the `jython-standalone-2.7.4.jar` file you downloaded.

2.  **Add the Extension:**

      - Go to the **Extender -\> Extensions** tab.
      - Click the **"Add"** button.
      - In the "Extension Details" window, set the "Extension type" to **"Python"**.
      - Click the **"Select file..."** button and choose the `main.py` file from this project.
      - Click **"Next"**. If no errors appear in the "Errors" tab, the extension has been loaded successfully.

## 👨‍💻 Usage

1.  After successful installation, a new tab named **"Tor Proxy Manager"** will appear in Burp Suite's main tab bar.
2.  The extension will attempt to automatically detect the `tor` executable on your system. If found, the input field will turn green, and the "ON" button will be enabled.
3.  If the path is not found automatically, click the **"Browse"** button to manually locate and select your `tor` (or `tor.exe`) file.
4.  Once a valid path is set, click the **"ON"** button to start the Tor proxy. The status label will indicate that the proxy is running.
5.  To stop the proxy, click the **"OFF"** button.

> **IMPORTANT: Configure SOCKS Proxy**
>
> This extension only starts and stops the Tor process. To actually route Burp Suite's traffic through Tor, you **must** configure the SOCKS proxy settings.
>
> 1.  Go to the **User options -\> Connections** tab.
> 2.  In the **SOCKS Proxy** section, enter the following details:
>       - **SOCKS proxy host:** `127.0.0.1`
>       - **SOCKS proxy port:** `9050`
> 3.  Check the box "Use SOCKS proxy".

## 🔧 Troubleshooting

  - **The "ON" Button is Not Enabled:**

      - Ensure the path in the input field points directly to the `tor` executable file, not a folder.
      - A pink/red background in the input field means the path is invalid or the file is not executable.
      - On macOS/Linux, make sure you have given the file execute permissions using `chmod +x /path/to/tor`.

  - **I Get an Error "Tor could not be started":**

      - Check if your antivirus or firewall software is blocking `tor.exe` from running.
      - Try running Tor manually from your command line to ensure the executable is not corrupted.
      - Check for any specific error messages in the **Extender -\> Extensions -\> Tor Proxy Manager -\> Errors** tab.

## Disclaimer

This tool has been developed for educational and professional security research purposes only. The software is provided "AS IS", without any warranty of any kind. All risks and responsibilities related to the use of this software belong to the user. The developer shall not be held liable for any direct or indirect damages that may arise from the use, misuse, or inability to use the software. All actions and their consequences resulting from the use of this tool are the sole responsibility of the user.

## 📄 License
This project is licensed under the MIT License.
