# coding: utf-8
# chrome.py
# Use "Google Chrome Dev Protocol" to automate Chrome
# https://chromedevtools.github.io/devtools-protocol/

import os
import platform
import re
import time
import socket
import base64
import pprint
import subprocess
import psutil
import tempfile
import shutil
from signal import SIGTERM
from contextlib import closing
from http.cookiejar import Cookie, LWPCookieJar
from . import cdp


IS_LINUX = platform.system() == 'Linux'

def find_free_port():
    """pick a free port number
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]
    
def check_socket(host, port):
    """Check if a port is open
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex((host, port)) == 0:
            print("[Debug]Port {}:{} is open".format(host, port))
            return True
        else:
            print("[Debug]Port {}:{} is not open".format(host, port))
            return False

class TimeoutError(Exception):
    """Raised when a request times out
    """
    pass

class Chrome:
    def __init__(self, proxy=None, 
                 download_images=True,
                 user_agent=None, 
                 display=True,
                 chrome_path=None,
                 chrome_user_data_dir=None,
                 chrome_profile=None,
                 extra_cmd_args=None,
                 remote_url=None,
                 before_request_sent_callback=None,
                 after_response_reveiced_callback=None,
                 execution_context_created_callback=None,
                 start_position=(0, 0),
                 window_size=(1024, 768),
                 debug=False):
        """Startup a chrome instance
        proxy: Proxy to use.
        download_images: Whether to download images.
        load_timeout: Page load timeout(seconds).
        user_agent: Specify user-agent.
        display: A boolean that tells ghost to displays UI. Headless model. Chrome version >= 59.
        chrome_path: Path of chrome binary file, if value is None will use default path.
        chrome_user_data_dir: To specify the user data directory(Storage location for custom configuration files, extensions, caches, and other data), will add the "--user-data-dir=..." parameter in chrome command line.
        chrome_profile: To specify the profile directoy, will add the "--profile-directory=..." parameter in chrome command line.
        extra_cmd_args: Extra arguments to be added into the chrome command line.
        before_request_sent_callback: Fired when page is about to send HTTP request.
        after_response_reveiced_callback: Fired when HTTP response is available.
        execution_context_created_callback: Fired when new execution context is created.
        start_position: The start window position.
        window_size: The start window size.
        debug: Print debug info if value is True. 
        """
        self.proxy_url = None
        self.proxy_scheme = None
        self.proxy_host = None
        self.proxy_port = None
        self.proxy_username = None
        self.proxy_password = None
        self.proxy_extension_dir = None
        self.remote_url = remote_url
        self.user_agent = user_agent
        self.display = display
        self.chrome_path = chrome_path
        self.chrome_user_data_dir = chrome_user_data_dir
        self.chrome_profile = chrome_profile
        self.extra_cmd_args = extra_cmd_args
        self.before_request_sent_callback = before_request_sent_callback
        self.after_response_reveiced_callback = after_response_reveiced_callback
        self.execution_context_created_callback = execution_context_created_callback
        self.download_images = download_images
        self.start_position = start_position
        self.window_size = window_size
        self.debug = debug
        self.browser = None
        self.chrome_process = None
        self.vdisplay = None
        self.temp_chrome_user_data_dir = None
        self.requests = {}
        if proxy:
            m = re.compile(r'^([a-z\d]+)\://', re.IGNORECASE).search(proxy)
            if m:
                self.proxy_scheme = m.group(1).lower()
                if self.proxy_scheme == 'https':
                    self.proxy_scheme = 'http'
                proxy = re.compile(r'^[a-z\d]+\://', re.IGNORECASE).sub('', proxy)
            else:
                self.proxy_scheme = 'http'
            if self.proxy_scheme not in ['http', 'socks5']:
                raise Exception('Unsupported proxy type: {}'.format(self.proxy_scheme))
            match = re.match(r'((?P<username>\w+):(?P<password>\w+)@)?(?P<host>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})(:(?P<port>\d+))?', proxy)
            if not match:
                match = re.compile(r'((?P<username>\w+):(?P<password>\w+)@)?(?P<host>[a-z\d\.\-]+)(:(?P<port>\d+))?', re.IGNORECASE).match(proxy)
            if match:
                groups = match.groupdict()
                self.proxy_username = groups.get('username')
                self.proxy_password = groups.get('password')
                self.proxy_host = groups.get('host') 
                self.proxy_port = int(groups.get('port'))
                self.proxy_url = '{}://{}:{}'.format(self.proxy_scheme, self.proxy_host, self.proxy_port)
            if self.debug:
                print('[Debug]proxy_url:', self.proxy_url)
                if self.proxy_username and self.proxy_password:
                    print('[Debug]proxy_username:', self.proxy_username)
                    print('[Debug]proxy_password:', self.proxy_password)
        
        if not self.remote_url:
            # Not specify remoge_url, will start a chrome instance
            # Chrome path
            self.chrome_path = self.chrome_path or self.get_default_chrome_path()
            if not self.chrome_path:
                raise Exception('Can not find chrome binary file.')
            else:
                if self.debug:
                    print('[Debug]Use chrome binary file: "{}"'.format(self.chrome_path))
            
            # "Google Chrome Dev Protocol" listen port
            self.dev_protocol_port = find_free_port()
            
            self.remote_url = 'http://127.0.0.1:{}'.format(self.dev_protocol_port)
            
            # Some default arguments for chrome command line
            chrome_args = [
                    '--remote-allow-origins=*',
                    '--no-first-run',
                    '--no-service-autorun',
                    '--disable-auto-reload',
                    '--no-default-browser-check',
                    '--homepage=about:blank',
                    '--no-pings',
                    '--wm-window-animations-disabled',
                    '--animation-duration-scale=0',
                    '--enable-privacy-sandbox-ads-apis',
                    '--safebrowsing-disable-download-protection',
                    '--simulate-outdated-no-au="Tue, 31 Dec 2099 23:59:59 GMT"',
                    '--password-store=basic',
                    '--deny-permission-prompts',
                    '--disable-infobars',
                    '--disable-breakpad',
                    '--disable-prompt-on-repost',
                    '--disable-password-generation',
                    '--disable-ipc-flooding-protection',
                    '--disable-background-timer-throttling',
                    '--disable-search-engine-choice-screen',
                    '--disable-backgrounding-occluded-windows',
                    '--disable-client-side-phishing-detection',
                    '--disable-top-sites',
                    '--disable-translate',
                    '--disable-renderer-backgrounding',
                    '--disable-background-networking',
                    '--disable-dev-shm-usage',
                    '--disable-features=IsolateOrigins,site-per-process,Translate,InsecureDownloadWarnings,DownloadBubble,DownloadBubbleV2,OptimizationTargetPrediction,OptimizationGuideModelDownloading,SidePanelPinning,UserAgentClientHint,PrivacySandboxSettings4,DisableLoadExtensionCommandLineSwitch',
                    '--disable-features=IsolateOrigins,site-per-process',
                    '--disable-session-crashed-bubble',
                    '--remote-debugging-host=127.0.0.1']
            if self.debug:
                print('[Debug]Default chrome command line arguments: {}'.format(chrome_args))
            if self.extra_cmd_args:
                if self.debug:
                    print('[Debug]Add extra command line arguments: {}'.format(self.extra_cmd_args))
                chrome_args.extend(self.extra_cmd_args)
            #chrome_args.extend(['--remote-allow-origins=*', '--disable-web-security', '--disable-features=IsolateOrigins,site-per-process', '--disable-site-isolation-trials'])
            chrome_args.append('--remote-debugging-port={}'.format(self.dev_protocol_port))
            # Set proxy
            if self.proxy_url:
                if not self.proxy_username:
                    if self.debug:
                        print('[Debug]Set proxy into {}'.format(self.proxy_url))
                    chrome_args.append('--proxy-server="{}"'.format(self.proxy_url))
                else:
                    # Create a proxy extension for proxy with authentication
                    self.proxy_extension_dir = self.create_proxy_extension(scheme=self.proxy_scheme, host=self.proxy_host, port=self.proxy_port, username=self.proxy_username, password=self.proxy_password)
                    if self.debug:
                        print('[Debug]Create proxy extension directory: "{}"'.format(self.proxy_extension_dir))
                    chrome_args.append('--load-extension={}'.format(os.path.abspath(self.proxy_extension_dir)))
            # User-agent
            if self.user_agent:
                if self.debug:
                    print('[Debug]Set User-agent into "{}"'.format(self.user_agent))
                chrome_args.append('--user-agent="{}"'.format(self.user_agent))
            # # Chrome user data directory
            if self.chrome_user_data_dir:
                if self.debug:
                    print('[Debug]Set --user-data-dir into "{}"'.format(self.chrome_user_data_dir))
                chrome_args.append('--user-data-dir="{}"'.format(self.chrome_user_data_dir))
            else:
                self.temp_chrome_user_data_dir = os.path.normpath(tempfile.mkdtemp())
                if self.debug:
                    print('[Debug]Create a temporary user data directory: "{}"'.format(self.temp_chrome_user_data_dir))
                chrome_args.append('--user-data-dir="{}"'.format(self.temp_chrome_user_data_dir))

            # Chrome profile
            if self.chrome_profile:
                # Chrome default user profile directory: C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default
                if self.debug:
                    print('[Debug]Set --profile-directory into "{}"'.format(self.chrome_profile))
                chrome_args.append('--profile-directory="{}"'.format(self.chrome_profile))
            # Headless model
            if not self.display:
                if self.debug:
                    print('[Debug]Use headless model: --headless --no-sandbox --disable-gpu')
                chrome_args.append('--headless --no-sandbox --disable-gpu')
            # Start position
            if self.start_position:
                if self.debug:
                    print('[Debug]Set --window-position={},{}'.format(self.start_position[0], self.start_position[1]))
                chrome_args.append('--window-position={},{}'.format(self.start_position[0], self.start_position[1]))
            # Start window size
            if self.window_size:
                if self.debug:
                    print('[Debug]Set --window-size={},{}'.format(self.window_size[0], self.window_size[1]))
                chrome_args.append('--window-size={},{}'.format(self.window_size[0], self.window_size[1]))

            # Start chrome
            cmd = self.chrome_path + ' ' + ' '.join(chrome_args)
            if self.debug:
                print('[Debug]Full cmd for start chrome:', cmd)
            if IS_LINUX:
                from xvfbwrapper import Xvfb
                if not self.vdisplay:
                    if self.debug:
                        print('[Debug]Start Xvfb...')
                    self.vdisplay = Xvfb(width=1920, height=1080, colordepth=24)
                    self.vdisplay.start()
            self.chrome_process = subprocess.Popen(cmd, env=os.environ.copy(), shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)         
        else:
            if not proxy:
                print('[Debug]Since the chrome has started, the proxy parameter will be ignored.')
            m = re.compile(r'\:(\d+)').search(self.remote_url)
            if m:
                self.dev_protocol_port = int(m.groups()[0])

        # Waitting for Chrome being ready
        num = 0
        while True:
            if check_socket(host='127.0.0.1', port=self.dev_protocol_port):
                break
            else:
                num += 1
                if num >= 20:
                    self.quit()
                    raise Exception('Can not connect to chrome during 20 seconds.')
                else:
                    time.sleep(1)

        # create a browser instance
        self.browser = cdp.Browser(url=self.remote_url)
        self.tab = None
        
    def get_default_chrome_path(self):
        """Get the realpath of chrome binary file
        """
        # Chrome installed in the default location for each system:
        # https://github.com/SeleniumHQ/selenium/wiki/ChromeDriver#requirements
        candidates = set()
        
        if not IS_LINUX:
            # Windows
            for item in map(os.environ.get, ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA", "PROGRAMW6432")):
                if item is not None:
                    for subitem in ("Google/Chrome/Application",):
                        candidates.add(os.sep.join((item, subitem, "chrome.exe")))
        else:
            # Linux
            for item in os.environ.get("PATH").split(os.pathsep):
                for subitem in (
                    "google-chrome",
                    "chromium",
                    "chromium-browser",
                    "chrome",
                    "google-chrome-stable",
                ):
                    candidates.add(os.sep.join((item, subitem)))
        for candidate in candidates:
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return os.path.normpath(candidate)
            
    def create_proxy_extension(self, scheme, host, port, username, password):
        """ Create a proxy extension file.
        """
        manifest_json = """
        {
        "version": "1.0.0",
        "manifest_version": 3,
        "name": "Chrome Proxy",
        "permissions": [
            "proxy",
            "tabs",
            "unlimitedStorage",
            "storage",
            "webRequest",
            "webRequestAuthProvider"
        ],
        "host_permissions": [
            "<all_urls>"
        ],
        "background": {
            "service_worker": "background.js"
        },
        "minimum_chrome_version":"88.0.0"
        }
        """

        background_js = """
        var config = {
            mode: "fixed_servers",
            rules: {
                singleProxy: {
                    scheme: "%s",
                    host: "%s",
                    port: %d
                },
                bypassList: ["localhost"]
            }
        };

        chrome.proxy.settings.set({value: config, scope: "regular"}, function() {});

        function callbackFn(details) {
            return {
                authCredentials: {
                    username: "%s",
                    password: "%s"
                }
            };
        }

        chrome.webRequest.onAuthRequired.addListener(
            callbackFn,
            { urls: ["<all_urls>"] },
            ['blocking']
        );
        """ % (
            scheme,
            host,
            port,
            username,
            password
        )

        proxy_extension_dir = tempfile.mkdtemp()
        with open(os.path.join(proxy_extension_dir, "manifest.json"), "w") as f:
            f.write(manifest_json)
        with open(os.path.join(proxy_extension_dir, "background.js"), "w") as f:
            f.write(background_js)
        return proxy_extension_dir
            
        
    def __request_will_be_sent(self, request, **kwargs):
        """Network.requestWillBeSent Callback
        """
        requestId = kwargs.get('requestId')
        if self.debug:
            print("Will send request {}, requestId = {}".format(request.get('url'), requestId))
        self.requests[requestId] = {'request': request, 'response': None}
        if self.before_request_sent_callback:
            self.before_request_sent_callback(request)
            
    def __response_received(self, requestId, response, **kwargs):
        """Network.responseReceived Callback
        """      
        if self.debug:
            print("Received response for {}, type = {}, requestId = {}".format(response.get('url'), kwargs.get('type'), requestId))
        if self.after_response_reveiced_callback and kwargs.get('type') in ['Document', 'Script', 'XHR', 'Fetch']:
            if requestId in self.requests:
                self.requests[requestId]['response'] = response
           
            
    def __loading__finished(self, requestId, **kwargs):
        """Network.loadingFinished
        """
        if self.debug:
            print("Loading finished for {}".format(requestId))
        
        if self.after_response_reveiced_callback:
            if requestId in self.requests:
                request, response = self.requests[requestId]['request'], self.requests[requestId]['response']
                try:
                    body_obj = self.tab.Network.getResponseBody(requestId=requestId)
                    body_text = body_obj['body']
                    if body_obj['base64Encoded']:
                        body_text = base64.decodestring(body_text)
                except Exception as e:
                    if self.debug:
                        print('[Debug]Failed to get response body for "{}": {}'.format(request.get('url'), str(e)))
                    body_text = ''
                self.after_response_reveiced_callback(request, response, body_text)
            else:
                if self.debug:
                    print('[Debug]Does not find related reponse data for requestId: {}'.format(requestId))
             

    def get_tab(self):
        """Get firxt tab
        """
        if not self.tab:
            # https://chromedevtools.github.io/devtools-protocol/tot/Network
            need_network_enabled = False
            tabs = self.browser.list_tab()
            if tabs:
                self.tab = tabs[0]
            else:
                self.tab = self.browser.new_tab()
            self.tab.start()
            self.tab.Page.stopLoading()
            self.tab.Extensions.loadUnpacked(path="F:/scrapers/test/tmp0unxbivn")
            if self.user_agent:
                # Set User-Agent header
                self.tab.Network.setExtraHTTPHeaders(headers={'User-Agent': self.user_agent})
                need_network_enabled = True
            if not self.download_images:
                # Disable images
                self.tab.Network.setBlockedURLs(urls=['*.jpg', '*.png', '*.gif', '*.woff'])
                need_network_enabled = True
            if self.before_request_sent_callback or self.after_response_reveiced_callback:
                if self.debug:
                    print('[Debug]Add Network.requestWillBeSent callback')
                self.tab.Network.requestWillBeSent = self.__request_will_be_sent
                need_network_enabled = True
            if self.after_response_reveiced_callback:
                if self.debug:
                    print('[Debug]Add Network.responseReceived callback')
                self.tab.Network.responseReceived = self.__response_received
                self.tab.Network.loadingFinished = self.__loading__finished
                need_network_enabled = True
            if need_network_enabled:
                self.tab.Network.enable()
            if self.execution_context_created_callback:
                self.tab.Runtime.executionContextCreated = self.execution_context_created_callback
                # Enables reporting of execution contexts creation by means of executionContextCreated event. When the reporting gets enabled the event will be sent immediately for each existing execution context.
                # https://chromedevtools.github.io/devtools-protocol/tot/Runtime/#method-enable
                self.tab.Runtime.enable()
            self.tab.Page.enable()            
        return self.tab

    def open(self, url, timeout=30):
        """Load url
        url: URL to load;
        """
        print('[Debug]Loading {} ...'.format(url))
        if not self.tab:
            self.get_tab()
        self.tab.Page.navigate(url=url, _timeout=timeout)
    
    def sleep(self, seconds):
        time.sleep(seconds)
        
    def wait_for_text(self, text, timeout=60):
        """Waits until given text appear on main frame.
        text: The text to wait for.
        timeout: An optional timeout.
        """
        start_time = time.time()
        while time.time() - start_time <= timeout:
            if text in self.content:
                return True
            else:
                time.sleep(1)
        raise TimeoutError
    
    def wait_for_any_text(self, texts, timeout=60):
        """Waits if any given text appear on main frame.
        texts: Any text to wait for.
        timeout: An optional timeout.
        """
        start_time = time.time()
        while time.time() - start_time <= timeout:
            for _text in texts:
                if _text in self.content:
                    return True
            time.sleep(1)
        raise TimeoutError
    
    def wait_for_all_text(self, texts, timeout=60):
        """Waits if all given text appear on main frame.
        texts: All texts to wait for.
        timeout: An optional timeout.
        """
        start_time = time.time()
        while time.time() - start_time <= timeout:
            all_existed = True
            for _text in texts:
                if _text not in self.content:
                    all_existed = False
            if all_existed:
                return True
            else:
                time.sleep(1)
        raise TimeoutError
    
    def capture_to(self, save_path):
        """Save screenshot
        """
        data = self.tab.Page.captureScreenshot()
        with open(save_path, "wb") as fd:
            fd.write(base64.b64decode(data['data']))     
        
    def evaluate(self, script, timeout=10):
        """Evaluates script in page frame.
        script: The script to evaluate.
        """
        if not self.tab:
            self.get_tab()
        js_result = self.tab.Runtime.evaluate(expression=script, _timeout=timeout)
        if u'exceptionDetails' not in js_result and u'result' in js_result and u'value' in js_result[u'result']:
            return js_result[u'result'][u'value']

    
    def load_cookies(self, cookie_storage):
        """load from Set-Cookie3 format text file.

        cookie_storage: file location string on disk.
        """
        cj = LWPCookieJar(cookie_storage)
        cj.load()
        for cookie in cj:
            self.tab.Network.setCookie(name=cookie.name, 
                                     value=cookie.value, 
                                     path=cookie.path, 
                                     secure=cookie.secure, 
                                     domain=cookie.domain,
                                     expires=cookie.expires)

        
    def save_cookies(self, cookie_storage):
        """Save to Set-Cookie3 format text file.

        cookie_storage: file location string.
        """
        
        def to_cookiejar_cookie(chrome_cookie):
            port = None
            port_specified = False
            secure = chrome_cookie['secure']
            name = chrome_cookie['name']
            value = chrome_cookie['value']
            v = chrome_cookie['path']
            path_specified = bool(v != "")
            path = v if path_specified else None
            v = chrome_cookie['domain']
            domain_specified = bool(v != "")
            domain = v
            if domain_specified:
                domain_initial_dot = v.startswith('.')
            else:
                domain_initial_dot = None
            v = int(chrome_cookie.get('expires') or 2147483647)
            # Long type boundary on 32bit platfroms; avoid ValueError
            expires = 2147483647 if v > 2147483647 or v == -1 else v
            rest = {}
            discard = False
            return Cookie(
                0,
                name,
                value,
                port,
                port_specified,
                domain,
                domain_specified,
                domain_initial_dot,
                path,
                path_specified,
                secure,
                expires,
                discard,
                None,
                None,
                rest,
            )

        cj = LWPCookieJar(cookie_storage)
        for cookie in self.cookies:
            cj.set_cookie(to_cookiejar_cookie(cookie))
        cj.save()
        
    def get_page_html(self, expression=None, timeout=10):
        """Get current page HTML
        """
        html = ''
        if not self.tab:
            self.get_tab()
        js_result = self.tab.Runtime.evaluate(expression=(expression or "document.documentElement.outerHTML"), _timeout=timeout)
        if u'exceptionDetails' not in js_result and u'result' in js_result and js_result[u'result'][u'type'] == u'string':
            html = js_result[u'result'][u'value']
        return html    
    
    @property
    def content(self):
        """Get current page HTML
        """
        return self.get_page_html(expression="document.documentElement.outerHTML")
    
    @property
    def title(self):
        """Get current page title
        """
        return self.evaluate(script="document.title")
    
    @property
    def cookies(self):
        """Returns all cookies.
        """
        if not self.tab:
            self.get_tab()
        return self.tab.Network.getCookies().get('cookies') or []

    def delete_cookies(self, alldomains=False):
        """Deletes all cookies.
        """
        if not self.tab:
            self.get_tab()
        if alldomains:
            # 删除所有域名的cookies
            self.tab.Network.clearBrowserCookies()
        else:
            for cookie in self.cookies:
                name = cookie['name']
                domain = cookie['domain']
                self.tab.Network.deleteCookies(name=name, domain=domain)
        
        
    def close_all_tabs(self):
        """Close all tabs, exit the chrome
        """
        if self.browser:
            for tab in self.browser.list_tab():
                self.browser.close_tab(tab)
            time.sleep(1)
        self.requests.clear()

    def get_chrome_subpids(self):
        """获取chrome子进程ID
        """
        chrome_pids = []
        if self.chrome_process:
            try:
                p = psutil.Process(self.chrome_process.pid)
            except psutil.NoSuchProcess:
                print('[Debug]Process({}) does not exit.'.format(self.chrome_process.pid))
            else:
                for sub_p in p.children(recursive=True):
                    chrome_pids.append(sub_p.pid)
        return chrome_pids


    def quit(self):
        """Close all tabs, exit the chrome
        """
        if self.chrome_process:
            # Get all subprocesses of chrome
            chrome_pids = self.get_chrome_subpids()
    
            # Terminate the main chrome process
            try:
                self.close_all_tabs()
            except Exception as e:
                print(e)
            self.chrome_process.terminate()
            self.chrome_process.wait()
            
            if chrome_pids:
                # Kill all chrome subprocesses
                for pid in chrome_pids:
                    try:
                        p = psutil.Process(pid)
                        if self.debug:
                            print('[Debug]Killing process({}) {}.'.format(p.pid, p.name()))
                        p.send_signal(SIGTERM)                 
                    except psutil.NoSuchProcess:
                        if self.debug:
                            print('[Debug]Chrome process({}) exited indeed.'.format(pid))
            self.chrome_process = None
            if self.vdisplay:
                self.vdisplay.stop()
            # Remove temporary user data directory
            if self.temp_chrome_user_data_dir and os.path.exists(self.temp_chrome_user_data_dir):
                shutil.rmtree(self.temp_chrome_user_data_dir)
            # Remove temporary proxy extension directory
            if self.proxy_extension_dir and os.path.exists(self.proxy_extension_dir):
                shutil.rmtree(self.proxy_extension_dir)
        
    def exit(self):
        self.quit()

    def close(self):
        self.exit()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.exit()


def test():
    # 测试环境：Win7 + Chrome V69 和 Ubuntu + Chrome V73 均测试通过
    
    def before_request_sent(request):
        """HTTP请求发出前 - 回调函数
        """
        print('[Debug]#' * 20 + ' REQUEST DATA FOR "{}" '.format(request.get('url')) + '#' * 20)
        pprint.pprint(request)
        print('[Debug]#' * 80)
        
        
    def after_response_received(request, response, body):
        """HTTP应答接收到了 - 回调函数
        """
        url = request.get('url')
        print('[Debug]#' * 20 + ' RESPONSE DATA FOR "{}" '.format(url) + '#' * 20)
        pprint.pprint(response)
        print('[Debug]RESPONSE BODY:')
        print(body)
        print('[Debug]#' * 80)    
        
    
    browser = Chrome(user_agent='KUNZHIPENG UA',
                     proxy=None,
                     download_images=True,
                     display=True,
                     chrome_profile='debug',
                    #  before_request_sent_callback=before_request_sent,
                    #  after_response_reveiced_callback=after_response_received,
                     debug=True)
    # 查看当前IP
    print('[Debug]查看当前IP')
    browser.open('http://httpbin.org/ip')
    # 等待页面加载就绪
    browser.wait_for_text(text='"origin"', timeout=10)
    # 获取当前页面HTML
    #print(browser.content)
    browser.capture_to('chrome-ip.png')
    input('Press ENTER to continue.')

    # 查看UA
    print('[Debug]查看UA')
    browser.open('http://proxies.site-digger.com/headers-view/')
    browser.wait_for_text(text='HTTP_USER_AGENT', timeout=10)
    browser.capture_to('chrome-ua.png')
    # 获取当前页面HTML
    #print(browser.content)
    input('Press ENTER to continue.')

    # 查看Cookies
    print('[Debug]查看Cookies')
    browser.open('http://httpbin.org/cookies/set?name=redice&sex=male')
    # 等待页面加载就绪
    browser.wait_for_text(text='"cookies"', timeout=10)
    # 获取当前页面HTML
    #print(browser.content)  
    # 打印当前Cookies
    pprint.pprint(browser.cookies)
    # 保存Cookies
    browser.save_cookies('chrome_cookies.txt')
    input('Press ENTER to continue.')

    # 删除所有Cookies
    print('[Debug]删除所有Cookies，然后查看当前Cookies')
    browser.delete_cookies(alldomains=True)
    browser.open('http://httpbin.org/cookies')
    browser.wait_for_text(text='"cookies"', timeout=10)
    # 打印当前Cookies
    pprint.pprint(browser.cookies)
    input('Press ENTER to continue.')

    print('[Debug]导入Cookies，然后查看当前Cookies')
    # 导入Cookies
    browser.load_cookies('chrome_cookies.txt')
    browser.open('http://httpbin.org/cookies')
    browser.wait_for_text(text='"cookies"', timeout=10)
    # 打印当前Cookies
    pprint.pprint(browser.cookies)   

    # 关闭浏览器
    browser.quit()
    
if __name__ == '__main__':
    test()