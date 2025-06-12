# coding: utf-8
# chrome.py
# Chrome automate with "Google Chrome Dev Protocol"(https://chromedevtools.github.io/devtools-protocol/)

import sys
import os
import platform
import re
import time
import socket
import base64
import subprocess
import psutil
import tempfile
import shutil
import json
from urllib.parse import urlparse
from signal import SIGTERM
from contextlib import closing
from . import cdp

IS_LINUX = platform.system() == 'Linux'
if IS_LINUX:
    from xvfbwrapper import Xvfb

# Default chrome command line arguments
DEFAULT_CHROME_CMD_ARGS = [
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
        self.debug = debug or '--chromepy-debug' in sys.argv
        self.cdpcli = None
        self.chrome_process = None
        self.vdisplay = None
        self.temp_chrome_user_data_dir = None
        self.dev_protocol_port = None
        self.requests_cache = {}
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
            if self.proxy_username and self.proxy_password:
                if self.debug:
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
            self.dev_protocol_port = self.pick_free_port()
            
            self.remote_url = 'http://127.0.0.1:{}'.format(self.dev_protocol_port)
            
            # Some default arguments for chrome command line
            chrome_args = DEFAULT_CHROME_CMD_ARGS.copy()
            if self.debug:
                print('[Debug]Default chrome command line arguments: {}'.format(chrome_args))
            if self.extra_cmd_args:
                for arg in self.extra_cmd_args:
                    if arg not in chrome_args:
                        chrome_args.append(arg)
                        if self.debug:
                            print('[Debug]Add extra chrome command line argument: {}'.format(arg))
            #chrome_args.extend(['--remote-allow-origins=*', '--disable-web-security', '--disable-features=IsolateOrigins,site-per-process', '--disable-site-isolation-trials'])
            chrome_args.append('--remote-debugging-port={}'.format(self.dev_protocol_port))
            # Set proxy
            if self.proxy_url:
                if self.debug:
                    print('[Debug]Set proxy into {}'.format(self.proxy_url))
                chrome_args.append('--proxy-server="{}"'.format(self.proxy_url))
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
            cmd = '"{}"'.format(self.chrome_path) + ' ' + ' '.join(chrome_args)
            if self.debug:
                print('[Debug]Full cmd for start chrome:', cmd)
            if IS_LINUX:
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
        print('[Info]Waitting for Chrome CDP being ready...')
        while True:
            if self.check_socket(host='127.0.0.1', port=self.dev_protocol_port):
                break
            else:
                num += 1
                if num >= 20:
                    self.quit()
                    raise Exception('Can not connect to chrome during 20 seconds.')
                else:
                    time.sleep(1)

        # create a cdp browser instance
        self.cdpcli = cdp.Browser(url=self.remote_url)
        self.tab = None

    def pick_free_port(self):
        """pick a free port number
        """
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(('', 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]
    
    def check_socket(self, host, port):
        """Check if a port is open
        """
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            if sock.connect_ex((host, port)) == 0:
                if self.debug:
                    print("[Debug]Port {}:{} is open".format(host, port))
                return True
            else:
                if self.debug:
                    print("[Debug]Port {}:{} is not open".format(host, port))
                return False
        
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
            
    def __request_intercepted(self, interceptionId, request, **kwargs):
        """Network.requestIntercepted Callback
        """
        if self.debug:
            print("[Debug]Intercepted request {}".format(request.get('url')))
        headers = request.get('headers', {})
        if self.user_agent:
            # Change UA
            headers['User-Agent'] = self.user_agent
        auth_challenge = kwargs.get('authChallenge')
        if auth_challenge:
            try:
                # 30x redirect with http proxy auth
                self.tab.Network.continueInterceptedRequest(
                    interceptionId=interceptionId,
                    headers=headers,
                    authChallengeResponse={'response': 'ProvideCredentials', 
                                           'username': self.proxy_username,
                                           'password': self.proxy_password}
                )
            except Exception as e:
                if self.debug:
                    print('[Debug]Exception when call Network.continueInterceptedRequest: {}'.format(str(e)))
        else:
            try:
                self.tab.Network.continueInterceptedRequest(
                    interceptionId=interceptionId,
                    headers=headers
                )
            except Exception as e:
                if self.debug:
                    print('[Debug]Exception when call Network.continueInterceptedRequest: {}'.format(str(e)))
            
        
    def __request_will_be_sent(self, request, **kwargs):
        """Network.requestWillBeSent Callback
        """
        requestId = kwargs.get('requestId')
        if self.debug:
            print("[Debug]Will send request {}, requestId = {}".format(request.get('url'), requestId))
        self.requests_cache[requestId] = {'request': request, 'response': None}
        if self.before_request_sent_callback:
            self.before_request_sent_callback(request)
            
    def __response_received(self, requestId, response, **kwargs):
        """Network.responseReceived Callback
        """      
        if self.debug:
            print("[Debug]Received response for {}, type = {}, requestId = {}".format(response.get('url'), kwargs.get('type'), requestId))
        if self.after_response_reveiced_callback and kwargs.get('type') in ['Document', 'Script', 'XHR', 'Fetch']:
            if requestId in self.requests_cache:
                self.requests_cache[requestId]['response'] = response
           
            
    def __loading__finished(self, requestId, **kwargs):
        """Network.loadingFinished
        """
        if self.debug:
            print("[Debug]Loading finished for {}".format(requestId))
        
        if self.after_response_reveiced_callback:
            if requestId in self.requests_cache:
                request, response = self.requests_cache[requestId]['request'], self.requests_cache[requestId]['response']
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
        """Get a tab. All operations are done on this tab.
        """
        if not self.tab:
            # https://chromedevtools.github.io/devtools-protocol/tot/Network
            need_network_enabled = False
            tabs = self.cdpcli.list_tab()
            if tabs:
                self.tab = tabs[0]
            else:
                self.tab = self.cdpcli.new_tab()
            self.tab.start()
            self.tab.Page.stopLoading()
            if self.proxy_username:
                if self.debug:
                    print('[Debug]Add Network.requestIntercepted callback')
                # Need to add Proxy-Authorization credentials
                self.tab.Network.requestIntercepted = self.__request_intercepted
                # setRequestInterceptionEnabled has been removed, should use setRequestInterception now
                self.tab.Network.setRequestInterception(patterns=[{"RequestPattern": '*'}])
                need_network_enabled = True
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
        print('[Info]Loading {} ...'.format(url))
        if not self.tab:
            self.get_tab()
        self.tab.Page.navigate(url=url, _timeout=timeout)
    
    def sleep(self, seconds):
        time.sleep(seconds)
        
    def wait_for_text(self, text, timeout=30):
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
    
    def wait_for_any_text(self, texts, timeout=30):
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
    
    def wait_for_all_text(self, texts, timeout=30):
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
    
    def capture_to(self, save_path, timeout=10):
        """Save screenshot
        """
        data = self.tab.Page.captureScreenshot(_timeout=timeout)
        with open(save_path, "wb") as fd:
            fd.write(base64.b64decode(data['data']))     
        
    def evaluate(self, script, timeout=10):
        """Evaluates script in page frame.
        script: The script to evaluate.
        """
        if not self.tab:
            self.get_tab()
        js_result = self.tab.Runtime.evaluate(expression=script, _timeout=timeout)
        if 'exceptionDetails' not in js_result and 'result' in js_result and 'value' in js_result['result']:
            return js_result['result']['value']

    
    def load_cookies(self, cookie_storage="cookies.json"):
        """load cookies from json file
        """
        if os.path.exists(cookie_storage):
            with open(cookie_storage, 'r', encoding='utf-8') as f:
                json_text = f.read()
                if json_text:
                    for cookie in json.loads(json_text):
                        self.add_cookie(cookie)
                        
    def add_cookie(self, cookie, timeout=10):
        """Add a cookie.
        """
        if not cookie.get('domain'):
            current_domain = urlparse(self.get_current_url()).netloc
            if current_domain:
                cookie['domain'] = current_domain
        args = cookie
        args['_timeout'] = timeout
        self.tab.Network.setCookie(**args)

    def add_cookies(self, cookies):
        """Add cookies.
        """
        for cookie in cookies:
            self.add_cookie(cookie)
        
    def save_cookies(self, cookie_storage="cookies.json"):
        """Save cookies into json file.
        """
        with open(cookie_storage, 'w', encoding='utf-8') as f:
            f.write(json.dumps(self.cookies, ensure_ascii=False))

    def refresh(self, ignore_cache=False, timeout=10):
        """Refresh the current page.
        ignore_cache: If true, browser cache is ignored (as if the user pressed Shift+refresh).
        """
        if not self.tab:
            self.get_tab()
        self.tab.Page.reload(ignoreCache=ignore_cache, _timeout=timeout)

    def refresh_page(self, ignore_cache=False, timeout=10):
        """Duplicate of refresh()
        """
        self.refresh(ignore_cache=ignore_cache, timeout=timeout)
        
    def get_page_html(self, expression=None, timeout=10):
        """Get current page HTML
        """
        html = ''
        if not self.tab:
            self.get_tab()
        js_result = self.tab.Runtime.evaluate(expression=(expression or "document.documentElement.outerHTML"), _timeout=timeout)
        if 'exceptionDetails' not in js_result and 'result' in js_result and js_result['result']['type'] == 'string':
            html = js_result['result']['value']
        return html    
    
    @property
    def content(self):
        """Duplicate of get_page_html()
        """
        return self.get_page_html(expression="document.documentElement.outerHTML")
    
    def get_page_source(self):
        """Duplicate of get_page_html()
        """
        return self.content
    
    def get_current_url(self, timeout=10):
        """Get current page url 
        """
        return self.evaluate('document.location.href', timeout=timeout)
    
    @property
    def title(self):
        """Get current page title
        """
        return self.evaluate(script="document.title")
    
    @property
    def cookies(self, timeout=10):
        """Returns all cookies.
        """
        if not self.tab:
            self.get_tab()
        return self.tab.Network.getCookies(_timeout=timeout).get('cookies') or []
    
    def get_cookies(self):
        """Duplicate of cookies()
        """
        return self.cookies

    def delete_cookies(self, timeout=10):
        """Deletes all cookies.
        """
        if not self.tab:
            self.get_tab()
        # 删除所有的cookies
        self.tab.Network.clearBrowserCookies(_timeout=timeout)

    def delete_all_cookies(self):
        """Duplicate of delete_cookies()
        """
        self.delete_cookies()

        
    def close_all_tabs(self):
        """Close all tabs, exit the chrome
        """
        if self.cdpcli:
            for tab in self.cdpcli.list_tab():
                self.cdpcli.close_tab(tab)
            time.sleep(1)
        self.requests_cache.clear()

    def get_chrome_subpids(self):
        """获取chrome子进程ID
        """
        if self.chrome_process:
            try:
                p = psutil.Process(self.chrome_process.pid)
            except psutil.NoSuchProcess:
                if self.debug:
                    print('[Debug]Process({}) does not exit.'.format(self.chrome_process.pid))
            else:
                chrome_pids = []
                for sub_p in p.children(recursive=True):
                    chrome_pids.append(sub_p.pid)
                return chrome_pids

    def quit(self):
        """Close all tabs, exit the chrome
        """
        if self.chrome_process:
            # Get all subprocesses of chrome
            chrome_pids = self.get_chrome_subpids()

            try:
                self.close_all_tabs()
                time.sleep(1)
            except Exception as e:
                if self.debug:
                    print('[Debug]Exception in close_all_tabs: {}'.format(str(e)))
            # Terminate the main chrome process
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
                try:
                    shutil.rmtree(self.temp_chrome_user_data_dir)
                except Exception as e:
                    print(e)
        else:
            try:
                self.close_all_tabs()
                time.sleep(1)
            except Exception as e:
                if self.debug:
                    print('[Debug]Exception in close_all_tabs: {}'.format(str(e)))
        
    def exit(self):
        self.quit()

    def close(self):
        self.exit()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.exit()
