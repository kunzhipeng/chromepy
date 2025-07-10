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
import logging
from urllib.parse import urlparse
from signal import SIGTERM
from contextlib import closing
from . import cdp

formatter = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)

IS_LINUX = platform.system() == 'Linux'
if IS_LINUX:
    from xvfbwrapper import Xvfb

def is_running_in_docker():
    """Check if the script is running in a Docker container
    """
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup", "rt") as f:
            return "docker" in f.read() or "containerd" in f.read()
    except Exception:
        return False


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
                 download_css=True,
                 user_agent=None,
                 accept_language=None,
                 display=True,
                 chrome_path=None,
                 incognito=False,
                 chrome_user_data_dir=None,
                 chrome_profile=None,
                 extra_cmd_args=None,
                 remote_url=None,
                 before_request_sent_callback=None,
                 after_response_reveiced_callback=None,
                 execution_context_created_callback=None,
                 start_position=None,
                 window_size=None,
                 save_iframe_execution_context=False,
                 debug=False):
        """Startup a chrome instance
        proxy: Proxy to use.
        download_images: Whether to download images.
        download_css: Whether to download css files.
        load_timeout: Page load timeout(seconds).
        user_agent: Specify User-Agent.
        accept_language: Specify Accept-Language.
        display: A boolean that tells ghost to displays UI. Headless model. Chrome version >= 59.
        chrome_path: Path of chrome binary file, if value is None will use default path.
        incognito: Whether to use incognito mode.
        chrome_user_data_dir: To specify the user data directory(Storage location for custom configuration files, extensions, caches, and other data), will add the "--user-data-dir=..." parameter in chrome command line.
        chrome_profile: To specify the profile directoy, will add the "--profile-directory=..." parameter in chrome command line.
        extra_cmd_args: Extra arguments to be added into the chrome command line.
        before_request_sent_callback: Fired when page is about to send HTTP request.
        after_response_reveiced_callback: Fired when HTTP response is available.
        execution_context_created_callback: Fired when new execution context is created.
        start_position: The start window position.
        window_size: The start window size.
        save_iframe_execution_context: Whether to save iframe execution context.
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
        self.accept_language = accept_language
        self.display = display
        self.chrome_path = chrome_path
        self.incognito = incognito
        self.chrome_user_data_dir = chrome_user_data_dir
        self.chrome_profile = chrome_profile
        self.extra_cmd_args = extra_cmd_args
        self.before_request_sent_callback = before_request_sent_callback
        self.after_response_reveiced_callback = after_response_reveiced_callback
        self.execution_context_created_callback = execution_context_created_callback
        self.download_images = download_images
        self.download_css = download_css
        self.start_position = start_position
        self.window_size = window_size
        self.save_iframe_execution_context = save_iframe_execution_context
        self.debug = debug or '--chromepy-debug' in sys.argv or os.environ.get('CHROMEPY_DEBUG') == '1'
        self.cdpcli = None
        self.chrome_process = None
        self.vdisplay = None
        self.temp_chrome_user_data_dir = None
        self.dev_protocol_port = None
        self.requests_cache = {}
        # To save "frameId -> ExecutionContextId"
        self.iframe_execution_contexts = {}
        if self.debug:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
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
                logger.debug('proxy_username:', self.proxy_username)
                logger.debug('proxy_password:', self.proxy_password)
        
        if not self.remote_url:
            # Not specify remoge_url, will start a chrome instance
            # Chrome path
            self.chrome_path = self.chrome_path or self.get_default_chrome_path()
            if not self.chrome_path:
                raise Exception('Can not find chrome binary file.')
            else:
                logger.debug('Use chrome binary file: "{}"'.format(self.chrome_path))
            
            # "Google Chrome Dev Protocol" listen port
            self.dev_protocol_port = self.pick_free_port()
            logger.debug('"CDP" listen port: {}'.format(self.dev_protocol_port))
            
            self.remote_url = 'http://127.0.0.1:{}'.format(self.dev_protocol_port)
            
            # Some default arguments for chrome command line
            chrome_args = DEFAULT_CHROME_CMD_ARGS.copy()
            logger.debug('Default chrome command line arguments: {}'.format(chrome_args))
            if self.extra_cmd_args:
                for arg in self.extra_cmd_args:
                    if arg not in chrome_args:
                        chrome_args.append(arg)
                        logger.debug('Add extra chrome command line argument: {}'.format(arg))
            if self.incognito:
                chrome_args.append('--incognito')
                logger.debug('Add "--incognito" into chrome command line arguments')
            if is_running_in_docker() and '--no-sandbox' not in chrome_args:
                chrome_args.append('--no-sandbox')
                logger.debug('Running in docker, Add "--no-sandbox" into chrome command line arguments')
            chrome_args.append('--remote-debugging-port={}'.format(self.dev_protocol_port))
            # Set proxy
            if self.proxy_url:
                logger.debug('Set proxy into {}'.format(self.proxy_url))
                chrome_args.append('--proxy-server="{}"'.format(self.proxy_url))
            # User-agent
            if self.user_agent:
                logger.debug('Set User-agent into "{}"'.format(self.user_agent))
                chrome_args.append('--user-agent="{}"'.format(self.user_agent))
            # # Chrome user data directory
            if self.chrome_user_data_dir:
                logger.debug('Set --user-data-dir into "{}"'.format(self.chrome_user_data_dir))
                chrome_args.append('--user-data-dir="{}"'.format(self.chrome_user_data_dir))
            else:
                self.temp_chrome_user_data_dir = os.path.normpath(tempfile.mkdtemp())
                logger.debug('Create a temporary user data directory: "{}"'.format(self.temp_chrome_user_data_dir))
                chrome_args.append('--user-data-dir="{}"'.format(self.temp_chrome_user_data_dir))

            # Chrome profile
            if self.chrome_profile:
                logger.debug('Set --profile-directory into "{}"'.format(self.chrome_profile))
                chrome_args.append('--profile-directory="{}"'.format(self.chrome_profile))
            # Headless model
            if not self.display:
                logger.debug('Use headless model: --headless --no-sandbox --disable-gpu')
                chrome_args.append('--headless --no-sandbox --disable-gpu')
            # Start position
            if self.start_position:
                logger.debug('Set --window-position={},{}'.format(self.start_position[0], self.start_position[1]))
                chrome_args.append('--window-position={},{}'.format(self.start_position[0], self.start_position[1]))
            # Start window size
            if self.window_size:
                logger.debug('Set --window-size={},{}'.format(self.window_size[0], self.window_size[1]))
                chrome_args.append('--window-size={},{}'.format(self.window_size[0], self.window_size[1]))

            # Start chrome
            cmd = '"{}"'.format(self.chrome_path) + ' ' + ' '.join(chrome_args)
            logger.debug('Full cmd for start chrome: {}'.format(cmd))
            if IS_LINUX:
                if not self.vdisplay:
                    logger.debug('Start Xvfb...')
                    self.vdisplay = Xvfb(width=1920, height=1080, colordepth=24)
                    self.vdisplay.start()   
            self.chrome_process = subprocess.Popen(cmd, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)     
        else:
            if not proxy:
                logger.debug('Since the chrome has started, the proxy parameter will be ignored.')
            m = re.compile(r'\:(\d+)').search(self.remote_url)
            if m:
                self.dev_protocol_port = int(m.groups()[0])

        # Waitting for Chrome being ready
        num = 0
        logger.info('Waitting for Chrome CDP being ready...')
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
        self.cdpcli = cdp.Browser(url=self.remote_url, debug=self.debug)
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
                logger.debug("Port {}:{} is open".format(host, port))
                return True
            else:
                logger.debug("Port {}:{} is not open".format(host, port))
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
        logger.debug("Intercepted request {}".format(request.get('url')))
        headers = request.get('headers', {})
        # if self.user_agent:
        #     # Change UA
        #     headers['User-Agent'] = self.user_agent
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
                logger.debug('Exception when call Network.continueInterceptedRequest: {}'.format(str(e)))
        else:
            try:
                self.tab.Network.continueInterceptedRequest(
                    interceptionId=interceptionId,
                    headers=headers
                )
            except Exception as e:
               logger.debug('Exception when call Network.continueInterceptedRequest: {}'.format(str(e)))
            
        
    def __request_will_be_sent(self, request, **kwargs):
        """Network.requestWillBeSent Callback
        """
        requestId = kwargs.get('requestId')
        logger.debug("Will send request {}, requestId = {}".format(request.get('url'), requestId))
        self.requests_cache[requestId] = {'request': request, 'response': None}
        if self.before_request_sent_callback:
            self.before_request_sent_callback(request)
            
    def __response_received(self, requestId, response, **kwargs):
        """Network.responseReceived Callback
        """      
        logger.debug("Received response for {}, type = {}, requestId = {}".format(response.get('url'), kwargs.get('type'), requestId))
        if self.after_response_reveiced_callback and kwargs.get('type') in ['Document', 'Script', 'XHR', 'Fetch']:
            if requestId in self.requests_cache:
                self.requests_cache[requestId]['response'] = response
           
            
    def __loading__finished(self, requestId, **kwargs):
        """Network.loadingFinished Callback
        """
        logger.debug("Loading finished for {}".format(requestId))
        
        if self.after_response_reveiced_callback:
            if requestId in self.requests_cache:
                request, response = self.requests_cache[requestId]['request'], self.requests_cache[requestId]['response']
                try:
                    body_obj = self.tab.Network.getResponseBody(requestId=requestId)
                    body_text = body_obj['body']
                    if body_obj['base64Encoded']:
                        body_text = base64.decodestring(body_text)
                except Exception as e:
                    logger.debug('Failed to get response body for "{}": {}'.format(request.get('url'), str(e)))
                    body_text = ''
                self.after_response_reveiced_callback(request, response, body_text)
            else:
                logger.debug('Does not find related reponse data for requestId: {}'.format(requestId))

    def __execution_context_created_callback(self, context):
        """Runtime.executionContextCreated Callback
        """
        logger.debug('Runtime.executionContextCreated: {}'.format(context))
        context_id = context['id']
        aux_data = context.get('auxData', {})
        if aux_data.get('frameId'):
            self.iframe_execution_contexts[aux_data['frameId']] = context
        if self.execution_context_created_callback:
            self.execution_context_created_callback(context)


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
                logger.debug('Add Network.requestIntercepted callback')
                # Need to add Proxy-Authorization credentials
                self.tab.Network.requestIntercepted = self.__request_intercepted
                # setRequestInterceptionEnabled has been removed, should use setRequestInterception now
                self.tab.Network.setRequestInterception(patterns=[{"RequestPattern": '*'}])
                need_network_enabled = True
            if self.user_agent or self.accept_language:
                # Set User-Agent header
                args = {}
                if self.user_agent:
                    logger.debug('Set user-agent: {}'.format(self.user_agent))
                    args['userAgent'] = self.user_agent
                else:
                    # When call Emulation.setUserAgentOverride, "userAgent" parameter can not be empty, so use the default User-Agent value here
                    self.tab.Runtime.enable()
                    args['userAgent'] = self.tab.Runtime.evaluate(expression='navigator.userAgent')['result']['value']
                if self.accept_language:
                    logger.debug('Set accept-language: {}'.format(self.accept_language))
                    args['acceptLanguage'] = self.accept_language
                if args:
                    # https://chromedevtools.github.io/devtools-protocol/tot/Emulation/#method-setUserAgentOverride
                    self.tab.Emulation.setUserAgentOverride(**args)
                    need_network_enabled = True
            urls_to_block = []
            if not self.download_images:
                # Do not download images
                urls_to_block.extend(['*.jpg', '*.png', '*.gif', '*.woff'])
            if not self.download_css:
                # Do not download css files
                urls_to_block.extend(['*.css'])
            if urls_to_block:
                logger.debug('Set blocked urls: {}'.format(urls_to_block))
                self.tab.Network.setBlockedURLs(urls=urls_to_block)
                need_network_enabled = True
            if self.before_request_sent_callback or self.after_response_reveiced_callback:
                logger.debug('Add Network.requestWillBeSent callback')
                self.tab.Network.requestWillBeSent = self.__request_will_be_sent
                need_network_enabled = True
            if self.after_response_reveiced_callback:
                logger.debug('Add Network.responseReceived callback')
                self.tab.Network.responseReceived = self.__response_received
                self.tab.Network.loadingFinished = self.__loading__finished
                need_network_enabled = True
            if need_network_enabled:
                self.tab.Network.enable()
            if self.execution_context_created_callback or self.save_iframe_execution_context:
                self.tab.Runtime.executionContextCreated = self.__execution_context_created_callback
                # Enables reporting of execution contexts creation by means of executionContextCreated event. When the reporting gets enabled the event will be sent immediately for each existing execution context.
                # https://chromedevtools.github.io/devtools-protocol/tot/Runtime/#method-enable
                self.tab.Runtime.enable()
            self.tab.Page.enable()
        return self.tab
    
    def add_init_script(self, script, timeout=10):
        """Evaluates given script in every frame upon creation (before loading frame's scripts).
        """
        logger.debug('Add init script: {}'.format(script))
        self.get_tab().Page.addScriptToEvaluateOnNewDocument(source=script, _timeout=timeout)


    def open(self, url, headers=None, slient=False, timeout=30):
        """Load url
        url: URL to load;
        slient: Whether to print log;
        timeout: An optional timeout.
        """
        self.iframe_execution_contexts.clear()
        if not slient:
            logger.info('Opening "{}"...'.format(url))
        if headers:
            # Add extra headers
            self.set_extra_http_headers(headers=headers)
        try:
            self.get_tab().Page.navigate(url=url, _timeout=timeout)
        except cdp.TimeoutException:
            raise TimeoutError('Timeout after loading page "{}" for more than {}s!'.format(url, timeout))
        
    def set_extra_http_headers(self, headers={}):
        """Set extra HTTP headers.
        """
        if headers:
            logger.debug('Set extra HTTP headers: {}'.format(headers))
            self.get_tab().Network.enable()
            self.get_tab().Network.setExtraHTTPHeaders(headers=headers)
    
    def sleep(self, seconds):
        time.sleep(seconds)

    def _text_in_html(self, text):
        """Check if given text is in page html.
        text: The text to check, support re.Pattern.
        """
        if isinstance(text, re.Pattern):
            if text.search(self.content):
                return True
            return False
        else:
            return text in self.content
        
    def wait_for_text(self, text, timeout=30):
        """Waits until given text appear on main frame.
        text: The text to wait for, support re.Pattern.
        timeout: An optional timeout.
        """
        start_time = time.time()
        while time.time() - start_time <= timeout:
            if self._text_in_html(text):
                return True
            else:
                time.sleep(1)
        raise TimeoutError
    
    def wait_for_any_text(self, texts, timeout=30):
        """Waits if any given text appear on main frame.
        texts: Any text to wait for, support re.Pattern.
        timeout: An optional timeout.
        """
        start_time = time.time()
        while time.time() - start_time <= timeout:
            for _text in texts:
                if self._text_in_html(_text):
                    return True
            time.sleep(1)
        raise TimeoutError
    
    def wait_for_all_text(self, texts, timeout=30):
        """Waits if all given text appear on main frame.
        texts: All texts to wait for, support re.Pattern.
        timeout: An optional timeout.
        """
        start_time = time.time()
        while time.time() - start_time <= timeout:
            all_existed = True
            for _text in texts:
                if not self._text_in_html(_text):
                    all_existed = False
            if all_existed:
                return True
            else:
                time.sleep(1)
        raise TimeoutError
    
    def capture_to(self, save_path, timeout=10):
        """Save screenshot
        """
        data = self.get_tab().Page.captureScreenshot(_timeout=timeout)
        with open(save_path, "wb") as fd:
            fd.write(base64.b64decode(data['data']))     
        
    def evaluate(self, script, context_id=None, timeout=10):
        """Evaluates script in page frame.
        script: The script to evaluate.
        """
        args = {}
        if context_id is not None:
            args['contextId'] = context_id
        args['expression'] = script
        args['_timeout'] = timeout
        js_result = self.get_tab().Runtime.evaluate(**args)
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
        self.get_tab().Network.setCookie(**args)

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
        self.get_tab().Page.reload(ignoreCache=ignore_cache, _timeout=timeout)

    def refresh_page(self, ignore_cache=False, timeout=10):
        """Duplicate of refresh()
        """
        self.refresh(ignore_cache=ignore_cache, timeout=timeout)

    def stop_loading(self, timeout=10):
        """Force the page stop all navigations and pending resource fetches.
        """
        self.get_tab().Page.stopLoading(_timeout=timeout)

    def get_page_html(self, expression=None, timeout=10):
        """Get current page HTML
        """
        html = ''
        js_result = self.get_tab().Runtime.evaluate(expression=(expression or "document.documentElement.outerHTML"), _timeout=timeout)
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
        return self.get_tab().Network.getCookies(_timeout=timeout).get('cookies') or []
    
    def get_cookies(self):
        """Duplicate of cookies()
        """
        return self.cookies
    
    def get_cookie_string(self):
        """Returns all cookies as a string.
        """
        return self.evaluate(script="document.cookie")

    def delete_cookies(self, timeout=10):
        """Deletes all cookies.
        """
        # 删除所有的cookies
        self.get_tab().Network.clearBrowserCookies(_timeout=timeout)

    def delete_all_cookies(self):
        """Duplicate of delete_cookies()
        """
        self.delete_cookies()

    def scroll_down(self, distance=300):
        """Scroll page down, return the current scroll height.
        """
        self.get_tab().Input.synthesizeScrollGesture(
            x=10, 
            y=10, 
            yDistance=-distance,  
            yOverscroll=0,
            xOverscroll=0,
            speed=3000)
        return self.evaluate('window.scrollY')
    
    
    def click_xy(self, x, y, timeout=10):
        """Click the point with x, y coordinates of the browser viewport.
        x: X coordinate of the browser viewport.
        y: Y coordinate of the browser viewport.
        """
        self.get_tab().Input.dispatchMouseEvent(type='mouseMoved', x=x, y=y, _timeout=timeout)
        self.get_tab().Input.dispatchMouseEvent(type='mousePressed', x=x, y=y, button='left', clickCount=1, _timeout=timeout)
        self.get_tab().Input.dispatchMouseEvent(type='mouseReleased', x=x, y=y, button='left', clickCount=1, _timeout=timeout)

    
    def click(self, css_selector, scroll=True, timeout=10):
        """Click the item postioned by css selector
        scroll: If True, scroll the element into the visible area first.
        """
        if scroll:
            # Scroll the element into the visible area
            js = f'''document.querySelector('{css_selector}').scrollIntoView();'''
            self.evaluate(js, timeout=timeout)
            time.sleep(0.3)
        # Get the position of an element in the view
        js = f'''JSON.stringify(document.querySelector('{css_selector}').getBoundingClientRect())'''
        bounding_jsontext = self.evaluate(js, timeout=timeout)
        if bounding_jsontext:
            bounding_rect = json.loads(bounding_jsontext)
            # Get the center position of the element
            x = bounding_rect['x'] + bounding_rect['width'] / 2
            y = bounding_rect['y'] + bounding_rect['height'] / 2
            # Click the element
            self.click_xy(x, y, timeout=timeout)
        else:
            logger.error(f'Element not found by selector: {css_selector}')
    
    def get_window_info(self, timeout=10):
        """Get windowId and bounds information of the window.
        https://chromedevtools.github.io/devtools-protocol/tot/Browser/#method-getWindowForTarget
        """
        return self.get_tab().Browser.getWindowForTarget(_timeout=timeout)

    def set_window_bounds(self, bounds, window_id=None, timeout=10):
        """Set window bounds
        https://chromedevtools.github.io/devtools-protocol/tot/Browser/#method-setWindowBounds
        """
        if not window_id:
            window_id = self.get_window_info(timeout=timeout)['windowId']
        self.get_tab().Browser.setWindowBounds(windowId=window_id, bounds=bounds, _timeout=timeout)

    def max(self):
        """Maximize the window.
        """
        info = self.get_window_info()
        if info['bounds']['windowState'] in ('fullscreen', 'minimized'):
            self.set_window_bounds(bounds={'windowState': 'normal'}, window_id=info['windowId'])
        self.set_window_bounds(bounds={'windowState': 'maximized'}, window_id=info['windowId'])

    def mini(self):
        """Minimize the window.
        """
        info = self.get_window_info()
        if info['bounds']['windowState'] == 'fullscreen':
            self.set_window_bounds(bounds={'windowState': 'normal'}, window_id=info['windowId'])
        self.set_window_bounds(bounds={'windowState': 'minimized'}, window_id=info['windowId'])

    def full(self):
        """Fullscreen the window.
        """
        info = self.get_window_info()
        if info['bounds']['windowState'] == 'minimized':
            self.set_window_bounds(bounds={'windowState': 'normal'}, window_id=info['windowId'])
        self.set_window_bounds(bounds={'windowState': 'fullscreen'}, window_id=info['windowId'])

    def normal(self):
        """Normal the window.
        """
        info = self.get_window_info()
        if info['bounds']['windowState'] == 'fullscreen':
            self.set_window_bounds(bounds={'windowState': 'normal'}, window_id=info['windowId'])
        self.set_window_bounds(bounds={'windowState': 'normal'}, window_id=info['windowId'])

    def size(self, width=None, height=None):
        """Set window size.
        """
        if width or height:
            info = self.get_window_info()
            if info['bounds']['windowState'] != 'normal':
                self.set_window_bounds(bounds={'windowState': 'normal'}, window_id=info['windowId'])
            width = width + 16 if width else info['bounds']['width']
            height = height + 8 if height else info['bounds']['height']
            self.set_window_bounds(bounds={'width': width, 'height': height}, window_id=info['windowId'])

    def location(self, x=None, y=None):
        """Set window location.
        """
        if x is not None or y is not None:
            info = self.get_window_info()
            if info['bounds']['windowState'] != 'normal':
                self.set_window_bounds(bounds={'windowState': 'normal'}, window_id=info['windowId'])
            x = x if x is not None else info['bounds']['left']
            y = y if y is not None else info['bounds']['top']
            self.set_window_bounds(bounds={'left': x - 8, 'top': y}, window_id=info['windowId'])


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
                logger.debug('Process({}) does not exit.'.format(self.chrome_process.pid))
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
                logger.debug('Exception in close_all_tabs: {}'.format(str(e)))
            # Terminate the main chrome process
            self.chrome_process.terminate()
            self.chrome_process.wait()
            
            if chrome_pids:
                # Kill all chrome subprocesses
                for pid in chrome_pids:
                    try:
                        p = psutil.Process(pid)
                        logger.debug('Killing process({}) {}.'.format(p.pid, p.name()))
                        p.send_signal(SIGTERM)                 
                    except psutil.NoSuchProcess:
                        logger.debug('Chrome process({}) exited indeed.'.format(pid))
            self.chrome_process = None
            if self.vdisplay:
                self.vdisplay.stop()
            # Remove temporary user data directory
            if self.temp_chrome_user_data_dir and os.path.exists(self.temp_chrome_user_data_dir):
                try:
                    shutil.rmtree(self.temp_chrome_user_data_dir)
                except Exception as e:
                    logger.error(e)
        else:
            try:
                self.close_all_tabs()
                time.sleep(1)
            except Exception as e:
                logger.debug('Exception in close_all_tabs: {}'.format(str(e)))
        
    def exit(self):
        self.quit()

    def close(self):
        self.exit()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.exit()