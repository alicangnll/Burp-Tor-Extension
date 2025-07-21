try:
    from burp import IBurpExtender, ITab
    from javax.swing import (JPanel, JButton, JTextField, JLabel, JFileChooser,
                             BoxLayout, SwingConstants, BorderFactory,
                             SwingUtilities)
    from javax.swing.event import DocumentListener
    from java.awt import (BorderLayout, FlowLayout, Color, Font, Dimension)
    from java.net import Socket, ConnectException
    import sys
    import subprocess
    import os
    import time
    import threading

except ImportError as e:
    print("Error: Required modules could not be loaded. {}".format(e))

# --- Constants and Strings ---
TOR_HOST = "127.0.0.1"
TOR_PORT = 9050
IS_WINDOWS = sys.platform == "win32"
MSG_DEFAULT_PATH_TEXT = "Enter the path to the Tor executable"
MSG_TAB_CAPTION = "Tor Proxy Manager"
MSG_EXTENSION_NAME = "Tor Proxy Manager"
MSG_AUTHOR_LBL = "Created by: Ali Can GONULLU"
MSG_STATUS_RUNNING = "Tor proxy is running. Enjoy your anonymity!"
MSG_STATUS_STOPPED = "Tor proxy is stopped. You are now being watched :)"
MSG_STATUS_ALREADY_RUNNING = "Tor proxy is already running."
MSG_STATUS_ALREADY_STOPPED = "Tor proxy is already stopped."
MSG_STATUS_STARTING = "Starting Tor..."
MSG_STATUS_STOPPING = "Stopping Tor..."
MSG_STATUS_START_ERROR = "Error: Tor could not be started. Check the path and permissions."
MSG_STATUS_STOP_ERROR = "Error: Tor could not be stopped properly."
MSG_STATUS_INVALID_PATH = "Error: Tor path is not set or is invalid."
MSG_HINT_SOCKS_ON = "Hint: Enable Burp's 'User options -> SOCKS Proxy' settings. Host: {}, Port: {}"
MSG_HINT_SOCKS_OFF = "Hint: Disable Burp's 'User options -> SOCKS Proxy' settings."

class BurpExtender(IBurpExtender, ITab, DocumentListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._tor_process = None
        self._callbacks.setExtensionName(MSG_EXTENSION_NAME)
        SwingUtilities.invokeLater(self._initialize_ui)
        print("{} extension loaded.".format(MSG_EXTENSION_NAME))

    def _initialize_ui(self):
        self.main_panel = JPanel()
        self.main_panel.setLayout(BoxLayout(self.main_panel, BoxLayout.Y_AXIS))
        path_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.path_input = JTextField(45)
        self.path_input.setText(MSG_DEFAULT_PATH_TEXT)
        self.path_input.setForeground(Color.GRAY)
        self.path_input.getDocument().addDocumentListener(self)

        # --- NEW: Set the default EXECUTABLE Tor path based on the operating system ---
        path_found = False
        if sys.platform == "darwin": # macOS
            # Checking your specified path and other common paths
            macos_paths = [
                "/System/Volumes/Data/opt/homebrew/bin/tor", # Your desired path first
                "/opt/homebrew/bin/tor",                     # Apple Silicon Homebrew
                "/usr/local/bin/tor"                         # Intel Homebrew
            ]
            for path in macos_paths:
                # Check not only for file existence but also if it's executable
                if os.path.isfile(path) and os.access(path, os.X_OK):
                    self.path_input.setText(path)
                    self.path_input.setForeground(Color.BLACK)
                    print("DEBUG: Executable macOS Tor path found: {}".format(path))
                    path_found = True
                    break # Stop at the first valid path found
        elif sys.platform.startswith("linux"): # Linux
            linux_path = "/usr/bin/tor"
            # Also perform the executability check for Linux
            if os.path.isfile(linux_path) and os.access(linux_path, os.X_OK):
                self.path_input.setText(linux_path)
                self.path_input.setForeground(Color.BLACK)
                print("DEBUG: Executable Linux Tor path found: {}".format(linux_path))
                path_found = True
        
        if path_found:
             print("DEBUG: Default path was successfully written to the text field.")
        else:
             print("DEBUG: No default, executable Tor path was found on the system.")
        # -------------------------------------------------------------------------

        browse_button = JButton("Browse", actionPerformed=self._browse_for_tor_path)
        self.on_button = JButton("ON", actionPerformed=self._start_tor)
        self.off_button = JButton("OFF", actionPerformed=self._stop_tor)
        path_panel.add(self.path_input)
        path_panel.add(browse_button)
        path_panel.add(self.on_button)
        path_panel.add(self.off_button)
        status_panel = JPanel(BorderLayout())
        status_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        self.status_label = JLabel("Status: Not Started", SwingConstants.CENTER)
        self.status_label.setFont(Font("SansSerif", Font.BOLD, 16))
        self.hint_label = JLabel(" ", SwingConstants.CENTER)
        self.hint_label.setFont(Font("SansSerif", Font.ITALIC, 12))
        status_panel.add(self.status_label, BorderLayout.CENTER)
        status_panel.add(self.hint_label, BorderLayout.SOUTH)
        author_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        author_label = JLabel(MSG_AUTHOR_LBL)
        author_label.setFont(Font("SansSerif", Font.PLAIN, 10))
        author_label.setForeground(Color.GRAY)
        author_panel.add(author_label)
        self.main_panel.add(path_panel)
        self.main_panel.add(status_panel)
        self.main_panel.add(author_panel)
        self._update_button_colors()
        self._validate_on_button_state()
        self._callbacks.addSuiteTab(self)

    def insertUpdate(self, e):
        self._validate_on_button_state()
    def removeUpdate(self, e):
        self._validate_on_button_state()
    def changedUpdate(self, e):
        self._validate_on_button_state()

    def _validate_on_button_state(self):
        path = self.path_input.getText().strip()
        is_valid_file = os.path.isfile(path) and os.access(path, os.X_OK)
        self.on_button.setEnabled(is_valid_file)
        def update_color_task():
            if not path or path == MSG_DEFAULT_PATH_TEXT:
                self.path_input.setBackground(Color.WHITE)
            elif is_valid_file:
                self.path_input.setBackground(Color.decode("#90EE90")) # Light Green
            else:
                self.path_input.setBackground(Color.decode("#FFB6C1")) # Light Pink/Red
        SwingUtilities.invokeLater(update_color_task)

    def getTabCaption(self):
        return MSG_TAB_CAPTION

    def getUiComponent(self):
        return self.main_panel

    def _start_tor(self, event):
        self._set_ui_busy(True, MSG_STATUS_STARTING)
        threading.Thread(target=self._perform_start_sequence).start()

    def _stop_tor(self, event):
        self._set_ui_busy(True, MSG_STATUS_STOPPING)
        threading.Thread(target=self._perform_stop_sequence).start()

    def _perform_start_sequence(self):
        tor_path = self.path_input.getText().strip()
        if not (os.path.isfile(tor_path) and os.access(tor_path, os.X_OK)):
             self._update_status(MSG_STATUS_INVALID_PATH, is_error=True)
             self._set_ui_busy(False)
             return
        if self._is_tor_running():
            self._update_status(MSG_STATUS_ALREADY_RUNNING, MSG_HINT_SOCKS_ON.format(TOR_HOST, TOR_PORT))
            self._set_ui_busy(False)
            return
        try:
            tor_dir = os.path.dirname(tor_path)
            self._tor_process = subprocess.Popen([tor_path], cwd=tor_dir)
            time.sleep(4)
            if self._is_tor_running():
                self._update_status(MSG_STATUS_RUNNING, MSG_HINT_SOCKS_ON.format(TOR_HOST, TOR_PORT))
            else:
                if self._tor_process: self._tor_process.terminate()
                self._tor_process = None
                self._update_status(MSG_STATUS_START_ERROR, is_error=True)
        except Exception as e:
            print("Error starting Tor: {}".format(e))
            self._tor_process = None
            self._update_status(MSG_STATUS_START_ERROR, is_error=True)
        finally:
            self._set_ui_busy(False)

    def _perform_stop_sequence(self):
        try:
            if not self._is_tor_running() and self._tor_process is None:
                self._kill_tor_by_name()
                self._update_status(MSG_STATUS_ALREADY_STOPPED, MSG_HINT_SOCKS_OFF)
                return
            if self._tor_process and self._tor_process.poll() is None:
                self._tor_process.terminate()
                self._tor_process.wait()
                self._tor_process = None
            else:
                self._kill_tor_by_name()
            time.sleep(2)
            if not self._is_tor_running():
                self._update_status(MSG_STATUS_STOPPED, MSG_HINT_SOCKS_OFF)
            else:
                self._update_status(MSG_STATUS_STOP_ERROR, is_error=True)
        except Exception as e:
            print("Error stopping Tor: {}".format(e))
            self._update_status(MSG_STATUS_STOP_ERROR, is_error=True)
        finally:
            self._set_ui_busy(False)
    
    def _browse_for_tor_path(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        result = chooser.showDialog(self.main_panel, "Select Tor Executable")
        if result == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            self.path_input.setText(file.getAbsolutePath())

    def _kill_tor_by_name(self):
        try:
            command = "taskkill /F /IM tor.exe" if IS_WINDOWS else "pkill tor"
            subprocess.check_call(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print("Tor process terminated by name.")
        except (subprocess.CalledProcessError, OSError):
            pass

    def _is_tor_running(self):
        s = None
        try:
            s = Socket(TOR_HOST, TOR_PORT)
            return True
        except ConnectException:
            return False
        except Exception as e:
            print("Unexpected error during port check: {}".format(e))
            return False
        finally:
            if s: s.close()
    
    def _set_ui_busy(self, busy, message=None):
        def task():
            if busy:
                self.on_button.setEnabled(False)
            else:
                self._validate_on_button_state()
            self.off_button.setEnabled(not busy)
            if message:
                self.status_label.setText(message)
                self.hint_label.setText(" ")
            if not busy:
                self._update_button_colors()
        SwingUtilities.invokeLater(task)
            
    def _update_status(self, status, hint="", is_error=False):
        def task():
            self.status_label.setText(status)
            self.status_label.setForeground(Color.RED if is_error else Color.DARK_GRAY)
            self.hint_label.setText(hint)
        SwingUtilities.invokeLater(task)

    def _update_button_colors(self):
        def task():
            if self._is_tor_running():
                self.on_button.setBackground(Color.GREEN)
                self.off_button.setBackground(None)
            else:
                self.on_button.setBackground(None)
                self.off_button.setBackground(Color.ORANGE)
        SwingUtilities.invokeLater(task)