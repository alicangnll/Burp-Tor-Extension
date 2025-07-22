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
    import json

except ImportError as e:
    print("Error: Required modules could not be loaded. {}".format(e))

# --- Sabitler ve Metinler ---
TOR_HOST = "127.0.0.1"
TOR_PORT = 9050
IS_WINDOWS = sys.platform == "win32"
MSG_DEFAULT_PATH_TEXT = "Enter the path to the Tor executable"
MSG_TAB_CAPTION = "Tor Proxy Manager"
MSG_EXTENSION_NAME = "Tor Proxy Manager"
MSG_AUTHOR_LBL = "Created by: Ali Can GONULLU"
MSG_STATUS_RUNNING = "Tor proxy is running"
MSG_HINT_RUNNING = "SOCKS Proxy was automatically enabled."
MSG_STATUS_STOPPED = "Tor proxy is stopped"
MSG_HINT_STOPPED = "SOCKS Proxy was automatically disabled."
MSG_STATUS_SCANNING = "Scanning for Tor executable..."
MSG_STATUS_NOT_FOUND = "Tor not found. Please select the path manually."
MSG_STATUS_STARTING = "Starting Tor & enabling SOCKS proxy..."
MSG_STATUS_STOPPING = "Stopping Tor & disabling SOCKS proxy..."
MSG_STATUS_START_ERROR = "Error: Tor could not be started."
MSG_HINT_START_ERROR = "Check the path and permissions."
MSG_STATUS_STOP_ERROR = "Error: Tor could not be stopped properly."
MSG_STATUS_CONFIG_ERROR = "Error: Could not modify Burp's SOCKS config."
MSG_HINT_CONFIG_ERROR = "Please check the Extender error logs for details."
MSG_STATUS_INVALID_PATH = "Error: Tor path is not set or is invalid."

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
        browse_button = JButton("Browse", actionPerformed=self._browse_for_tor_path)
        self.on_button = JButton("ON", actionPerformed=self._start_tor)
        self.off_button = JButton("OFF", actionPerformed=self._stop_tor)
        path_panel.add(self.path_input)
        path_panel.add(browse_button)
        path_panel.add(self.on_button)
        path_panel.add(self.off_button)
        status_panel = JPanel(BorderLayout())
        status_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        self.status_label = JLabel("Status: Initializing...", SwingConstants.CENTER)
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
        
        self._update_status(MSG_STATUS_SCANNING)
        threading.Thread(target=self._scan_for_tor).start()
        
        self._validate_on_button_state()
        self._callbacks.addSuiteTab(self)

    def _scan_for_tor(self):
        search_roots = []
        filename_to_find = "tor"
        if IS_WINDOWS:
            filename_to_find = "tor.exe"
            common_paths = [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.environ.get("UserProfile")]
            search_roots = [p for p in common_paths if p]
        else:
            search_roots = ["/usr/bin", "/usr/local/bin", "/opt", os.path.expanduser("~")]
        print("DEBUG: Tor taramasi baslatildi. Aranacak kok dizinler: {}".format(search_roots))
        found_path = None
        for root_dir in search_roots:
            if found_path: break
            try:
                for root, _, files in os.walk(root_dir):
                    if found_path: break
                    if filename_to_find in files:
                        candidate_path = os.path.join(root, filename_to_find)
                        if os.access(candidate_path, os.X_OK):
                            found_path = candidate_path
                            print("DEBUG: Calistirilabilir Tor bulundu: {}".format(found_path))
                            break
            except OSError as e:
                print("DEBUG: Dizin taranirken hata olustu (izinler?): {} - {}".format(root_dir, e))
                continue

        def update_ui_task():
            if found_path:
                self.path_input.setText(found_path)
                self.path_input.setForeground(Color.BLACK)
                self._update_status(MSG_STATUS_STOPPED, MSG_HINT_STOPPED)
            else:
                self._update_status(MSG_STATUS_NOT_FOUND)
            self._validate_on_button_state()
        SwingUtilities.invokeLater(update_ui_task)

    def _set_socks_proxy_state(self, enable):
        try:
            print("DEBUG: SOCKS Proxy ayari degistiriliyor. Istenen durum: {}".format("Etkin" if enable else "Pasif"))
            config_json_str = self._callbacks.saveConfigAsJson("user_options.connections.socks_proxy")
            config = json.loads(config_json_str)
            proxy_settings = config.setdefault("user_options", {}).setdefault("connections", {}).setdefault("socks_proxy", {})
            print("DEBUG: SOCKS ayarlarinin mevcut durumu: {}".format(proxy_settings))
            proxy_settings["socks_proxy_enabled"] = enable
            if enable:
                proxy_settings["socks_proxy_host"] = TOR_HOST
                proxy_settings["socks_proxy_port"] = TOR_PORT
            print("DEBUG: SOCKS ayarlarinin yeni durumu: {}".format(proxy_settings))
            updated_config_json_str = json.dumps(config)
            self._callbacks.loadConfigFromJson(updated_config_json_str)
            print("DEBUG: SOCKS Proxy ayari basariyla yuklendi.")
            return True
        except Exception as e:
            print("ERROR: SOCKS ayari degistirilirken hata olustu: {}".format(e))
            self._update_status(MSG_STATUS_CONFIG_ERROR, MSG_HINT_CONFIG_ERROR, is_error=True)
            return False

    def _perform_start_sequence(self):
        tor_path = self.path_input.getText().strip()
        if not (os.path.isfile(tor_path) and os.access(tor_path, os.X_OK)):
             self._update_status(MSG_STATUS_INVALID_PATH, is_error=True)
             self._set_ui_busy(False)
             return
        if self._is_tor_running():
            if self._set_socks_proxy_state(True):
                self._update_status(MSG_STATUS_RUNNING, MSG_HINT_RUNNING)
            self._set_ui_busy(False)
            return
        
        try:
            tor_dir = os.path.dirname(tor_path)
            self._tor_process = subprocess.Popen([tor_path], cwd=tor_dir)
            time.sleep(4)
            if self._is_tor_running():
                if self._set_socks_proxy_state(True):
                    self._update_status(MSG_STATUS_RUNNING, MSG_HINT_RUNNING)
            else:
                if self._tor_process: self._tor_process.terminate()
                self._tor_process = None
                self._update_status(MSG_STATUS_START_ERROR, MSG_HINT_START_ERROR, is_error=True)
        except Exception as e:
            print("Error starting Tor: {}".format(e))
            self._tor_process = None
            self._update_status(MSG_STATUS_START_ERROR, MSG_HINT_START_ERROR, is_error=True)
        finally:
            self._set_ui_busy(False)

    def _perform_stop_sequence(self):
        try:
            if not self._is_tor_running() and self._tor_process is None:
                self._kill_tor_by_name()
                if self._set_socks_proxy_state(False):
                    self._update_status(MSG_STATUS_STOPPED, MSG_HINT_STOPPED)
                return
            if self._tor_process and self._tor_process.poll() is None:
                self._tor_process.terminate()
                self._tor_process.wait()
            else:
                self._kill_tor_by_name()
            self._tor_process = None
            time.sleep(1)
            if not self._is_tor_running():
                if self._set_socks_proxy_state(False):
                    self._update_status(MSG_STATUS_STOPPED, MSG_HINT_STOPPED)
            else:
                self._update_status(MSG_STATUS_STOP_ERROR, is_error=True)
        except Exception as e:
            print("Error stopping Tor: {}".format(e))
            self._update_status(MSG_STATUS_STOP_ERROR, is_error=True)
        finally:
            self._set_ui_busy(False)
    
    def insertUpdate(self, e): self._validate_on_button_state()
    def removeUpdate(self, e): self._validate_on_button_state()
    def changedUpdate(self, e): self._validate_on_button_state()

    def _validate_on_button_state(self):
        path = self.path_input.getText().strip()
        is_valid_file = os.path.isfile(path) and os.access(path, os.X_OK)
        self.on_button.setEnabled(is_valid_file)
        def update_color_task():
            if not path or path == MSG_DEFAULT_PATH_TEXT:
                self.path_input.setBackground(Color.WHITE)
            elif is_valid_file:
                self.path_input.setBackground(Color.decode("#90EE90"))
            else:
                self.path_input.setBackground(Color.decode("#FFB6C1"))
        SwingUtilities.invokeLater(update_color_task)

    def getTabCaption(self): return MSG_TAB_CAPTION
    def getUiComponent(self): return self.main_panel
    
    def _start_tor(self, event):
        self._set_ui_busy(True, MSG_STATUS_STARTING)
        threading.Thread(target=self._perform_start_sequence).start()
    
    # DUZELTME: 'def' anahtar kelimesi hatali bir sekilde ayrilmisti, simdi birlestirildi.
    def _stop_tor(self, event):
        self._set_ui_busy(True, MSG_STATUS_STOPPING)
        threading.Thread(target=self._perform_stop_sequence).start()
    
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
        except (subprocess.CalledProcessError, OSError): pass
    
    def _is_tor_running(self):
        s = None
        try:
            s = Socket(TOR_HOST, TOR_PORT)
            return True
        except ConnectException: return False
        except Exception as e:
            print("Unexpected error during port check: {}".format(e))
            return False
        finally:
            if s: s.close()
    
    def _set_ui_busy(self, busy, message=None):
        def task():
            if busy: self.on_button.setEnabled(False)
            else: self._validate_on_button_state()
            self.off_button.setEnabled(not busy)
            # Guncelleme: Mesaj artik _update_status tarafindan yonetiliyor.
            if message: self._update_status(message) 
            if not busy: self._update_button_colors()
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
