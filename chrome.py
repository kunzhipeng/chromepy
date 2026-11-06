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
import math
import logging
import random
import ctypes
from ctypes import wintypes
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

def has_desktop():
    # 方式一：DISPLAY 环境变量（X11）
    if os.environ.get("DISPLAY"):
        return True
    # 方式二：Wayland
    if os.environ.get("WAYLAND_DISPLAY"):
        return True
    return False


# Default chrome command line arguments
DEFAULT_CHROME_CMD_ARGS = [
    '--remote-allow-origins=*',
    '--no-first-run',
    '--no-startup-window',
    '--disable-default-apps',
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
    '--disable-hang-monitor',
    '--disable-top-sites',
    '--disable-translate',
    '--disable-renderer-backgrounding',
    '--disable-background-networking',
    '--disable-dev-shm-usage',
    '--use-mock-keychain',
    '--disable-back-forward-cache',
    '--disable-popup-blocking',
    '--disable-features=IsolateOrigins,site-per-process,Translate,InsecureDownloadWarnings,DownloadBubble,DownloadBubbleV2,OptimizationTargetPrediction,OptimizationGuideModelDownloading,SidePanelPinning,UserAgentClientHint,PrivacySandboxSettings4,DisableLoadExtensionCommandLineSwitch',
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
                 urls_to_block=None,
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
        self.urls_to_block = urls_to_block or []
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
                logger.debug('proxy_username: {}'.format(self.proxy_username))
                logger.debug('proxy_password: {}'.format(self.proxy_password))
        
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
                chrome_args.append('--proxy-server={}'.format(self.proxy_url))
            # User-agent
            if self.user_agent:
                logger.debug('Set User-agent into "{}"'.format(self.user_agent))
                chrome_args.append('--user-agent={}'.format(self.user_agent))
            # # Chrome user data directory
            if self.chrome_user_data_dir:
                logger.debug('Set --user-data-dir into "{}"'.format(self.chrome_user_data_dir))
                chrome_args.append('--user-data-dir={}'.format(self.chrome_user_data_dir))
            else:
                self.temp_chrome_user_data_dir = os.path.normpath(tempfile.mkdtemp())
                logger.debug('Create a temporary user data directory: "{}"'.format(self.temp_chrome_user_data_dir))
                chrome_args.append('--user-data-dir={}'.format(self.temp_chrome_user_data_dir))

            # Chrome profile
            if self.chrome_profile:
                logger.debug('Set --profile-directory into "{}"'.format(self.chrome_profile))
                chrome_args.append('--profile-directory={}'.format(self.chrome_profile))
            # Headless model
            if not self.display:
                logger.debug('Use headless model: --headless --no-sandbox --disable-gpu')
                if '--headless' not in chrome_args:
                    chrome_args.append('--headless')
                if '--no-sandbox' not in chrome_args:
                    chrome_args.append('--no-sandbox')
                if '--disable-gpu' not in chrome_args:
                    chrome_args.append('--disable-gpu')
            # Start position
            if self.start_position:
                logger.debug('Set --window-position={},{}'.format(self.start_position[0], self.start_position[1]))
                chrome_args.append('--window-position={},{}'.format(self.start_position[0], self.start_position[1]))
            # Start window size
            if self.window_size:
                logger.debug('Set --window-size={},{}'.format(self.window_size[0], self.window_size[1]))
                chrome_args.append('--window-size={},{}'.format(self.window_size[0], self.window_size[1]))

            # Start chrome
            # On Linux, start Xvfb if no desktop environment
            if IS_LINUX and not has_desktop():
                if not self.vdisplay:
                    logger.debug('Start Xvfb...')
                    self.vdisplay = Xvfb(width=1920, height=1080, colordepth=24)
                    self.vdisplay.start()
            full_args = [self.chrome_path] + chrome_args
            logger.debug('Full args for start chrome: {}'.format(full_args))
            self.chrome_process = subprocess.Popen(full_args, shell=False, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            # Windows: 将chrome挂入本进程持有的Job Object
            # python进程无论以何种方式退出(正常结束/异常/Ctrl+C/关闭窗口/taskkill /F)，
            # 系统都会关闭Job句柄并自动杀掉chrome，彻底杜绝孤儿进程
            self._hjob = self._assign_to_job(self.chrome_process.pid)
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
                    # quit自身可能抛异常（如主进程已死时terminate报错），不能让它顶掉超时异常
                    try:
                        self.quit()
                    except Exception as e:
                        logger.error('Exception when quit chrome after CDP timeout: {}'.format(str(e)))
                    raise Exception('Can not connect to chrome during 20 seconds.')
                else:
                    time.sleep(1)

        # create a cdp browser instance
        try:
            self.cdpcli = cdp.Browser(url=self.remote_url, debug=self.debug)
        except Exception:
            # cdp连接失败时chrome进程已经启动，必须先清理再抛异常，否则进程泄漏
            try:
                self.quit()
            except Exception as e:
                logger.error('Exception when quit chrome after cdp.Browser failure: {}'.format(str(e)))
            raise
        self.tab = None
        # 上一次的鼠标位置(视口坐标),None 表示未知
        self._mouse_pos = None

    def _assign_to_job(self, pid):
        """将指定进程挂入Windows Job Object(KILL_ON_JOB_CLOSE)
        返回job句柄；句柄由本python进程持有，进程退出(含强杀)时系统自动杀掉job内全部进程。
        非Windows平台或失败时返回None（不影响正常流程）。
        """
        if platform.system() != 'Windows':
            return None
        hjob = None
        try:
            kernel32 = ctypes.windll.kernel32

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in (
                    'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                    'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ('PerProcessUserTimeLimit', ctypes.c_int64),
                    ('PerJobUserTimeLimit', ctypes.c_int64),
                    ('LimitFlags', wintypes.DWORD),
                    ('MinimumWorkingSetSize', ctypes.c_size_t),
                    ('MaximumWorkingSetSize', ctypes.c_size_t),
                    ('ActiveProcessLimit', wintypes.DWORD),
                    ('Affinity', ctypes.c_size_t),
                    ('PriorityClass', wintypes.DWORD),
                    ('SchedulingClass', wintypes.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ('IoInfo', IO_COUNTERS),
                    ('ProcessMemoryLimit', ctypes.c_size_t),
                    ('JobMemoryLimit', ctypes.c_size_t),
                    ('PeakProcessMemoryUsed', ctypes.c_size_t),
                    ('PeakJobMemoryUsed', ctypes.c_size_t),
                ]

            JobObjectExtendedLimitInformation = 9
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
            PROCESS_SET_QUOTA = 0x0100
            PROCESS_TERMINATE = 0x0001

            hjob = kernel32.CreateJobObjectW(None, None)
            if not hjob:
                raise OSError('CreateJobObjectW failed')
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(
                    hjob, JobObjectExtendedLimitInformation,
                    ctypes.byref(info), ctypes.sizeof(info)):
                raise OSError('SetInformationJobObject failed')
            hproc = kernel32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
            if not hproc:
                raise OSError('OpenProcess({}) failed'.format(pid))
            if not kernel32.AssignProcessToJobObject(hjob, hproc):
                raise OSError('AssignProcessToJobObject failed')
            kernel32.CloseHandle(hproc)
            logger.debug('Process({}) assigned to job object.'.format(pid))
        except Exception as e:
            logger.debug('Assign to job object failed: {}'.format(str(e)))
            if hjob:
                kernel32 = ctypes.windll.kernel32
                kernel32.CloseHandle(hjob)
                hjob = None
        return hjob

    def _kill_by_job(self):
        """主动终止job内所有进程并关闭句柄
        """
        hjob = getattr(self, '_hjob', None)
        if not hjob:
            return
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.TerminateJobObject(hjob, 0)
            kernel32.CloseHandle(hjob)
        except Exception as e:
            logger.debug('Exception in _kill_by_job: {}'.format(str(e)))
        self._hjob = None

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
            
    def __fetch_auth_required(self, requestId, request, authChallenge, **kwargs):
        """Fetch.authRequired Callback

        Chrome delegates authentication challenges to this callback when
        Fetch.enable(handleAuthRequests=True) is used. Only proxy challenges
        are answered with credentials; server (401) challenges are cancelled
        so that proxy credentials never leak to a website.
        """
        logger.debug("Auth required for {}, source = {}".format(request.get('url'), authChallenge.get('source')))
        try:
            if authChallenge.get('source') == 'Proxy' and self.proxy_username and self.proxy_password:
                self.tab.Fetch.continueWithAuth(
                    requestId=requestId,
                    authChallengeResponse={'response': 'ProvideCredentials',
                                           'username': self.proxy_username,
                                           'password': self.proxy_password}
                )
            else:
                self.tab.Fetch.continueWithAuth(
                    requestId=requestId,
                    authChallengeResponse={'response': 'CancelAuth'}
                )
        except Exception as e:
            logger.debug('Exception when call Fetch.continueWithAuth: {}'.format(str(e)))

    def __fetch_request_paused(self, requestId, request, **kwargs):
        """Fetch.requestPaused Callback

        Every request intercepted by Fetch domain must be continued (or
        failed/fulfilled), otherwise Chrome will never send it.
        """
        logger.debug("Intercepted request {}".format(request.get('url')))
        try:
            self.tab.Fetch.continueRequest(requestId=requestId)
        except Exception as e:
            logger.debug('Exception when call Fetch.continueRequest: {}'.format(str(e)))
            
        
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
                # Network.setRequestInterception/continueInterceptedRequest have been
                # removed from CDP. Proxy authentication is now handled by the Fetch domain:
                # Fetch.authRequired gives us the 407 challenge, and Fetch.requestPaused
                # must be continued for every intercepted request.
                logger.debug('Enable Fetch domain to handle proxy authentication')
                self.tab.Fetch.authRequired = self.__fetch_auth_required
                self.tab.Fetch.requestPaused = self.__fetch_request_paused
                self.tab.Fetch.enable(patterns=[{'urlPattern': '*'}], handleAuthRequests=True)
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
            if not self.download_images:
                # Do not download images
                for url_pattern in ['*.jpg', '*.png', '*.gif', '*.woff']:
                    if url_pattern not in self.urls_to_block:
                        self.urls_to_block.append(url_pattern)
            if not self.download_css:
                # Do not download css files
                for url_pattern in ['*.css']:
                    if url_pattern not in self.urls_to_block:
                        self.urls_to_block.append(url_pattern)
            if self.urls_to_block:
                logger.debug('Set blocked urls: {}'.format(self.urls_to_block))
                self.tab.Network.setBlockedURLs(urls=self.urls_to_block)
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

    def save_screenshot(self, save_path, timeout=10):
        """Duplicate of capture_to()
        """
        self.capture_to(save_path, timeout=timeout)

        
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
        try:
            js_result = self.get_tab().Runtime.evaluate(expression=(expression or "document.documentElement.outerHTML"), _timeout=timeout)
        except cdp.TimeoutException:
            logger.error('Timeout to get page HTML')
        else:
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
    
    def get_user_agent(self, timeout=10):
        """Get current user-agent
        """
        return self.evaluate('navigator.userAgent', timeout=timeout)
    
    @property
    def title(self):
        """Get current page title
        """
        return self.evaluate(script="document.title")
    
    @property
    def cookies(self, timeout=10):
        """Returns all cookies as a List
        """
        return self.get_tab().Network.getCookies(_timeout=timeout).get('cookies') or []
    
    def get_cookies(self):
        """Duplicate of cookies()
        """
        return self.cookies
    
    def get_cookies_dict(self):
        """Returns all cookies as a Dict
        """
        cookies = {}
        for cookie in self.cookies:
            cookies[cookie['name']] = cookie['value']
        return cookies
    
    def get_cookies_string(self):
        """Returns all cookies as a String
        """
        return '; '.join([f'{cookie["name"]}={cookie["value"]}' for cookie in self.cookies])
    
    def get_requests_cookiejar(self):
        """Returns all cookies as a RequestsCookieJar
        """
        from requests.cookies import RequestsCookieJar
        jar = RequestsCookieJar()
        for cookie in self.cookies:
            jar.set(cookie['name'], cookie['value'], domain=cookie['domain'], path=cookie['path'])
        return jar
    
    def get_js_cookie(self):
        """Returns JS `document.cookie`
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
    
    def dispatch_key(self, key, code, key_code, modifiers=0, timeout=10):
        """Dispatch key event. https://chromedevtools.github.io/devtools-protocol/tot/Input/#method-dispatchKeyEvent
        key: Key to dispatch.
        code: Code of the key.
        key_code: Windows virtual key code of the key.
        modifiers: Modifier keys.
        timeout: Timeout in seconds.
        """
        text = ''
        if key == 'Enter':
            text = '\r'
        for _type in ['keyDown', 'keyUp']:
            self.get_tab().Input.dispatchKeyEvent(type=_type,
                key=key,
                code=code,
                windowsVirtualKeyCode=key_code,
                nativeVirtualKeyCode=key_code,
                modifiers=modifiers,
                text=text,
                _timeout=timeout
            )
     
    def insert_text(self, text, timeout=10):
        """Insert text into the current input element.
        text: Text to insert.
        """
        self.get_tab().Input.insertText(text=text, _timeout=timeout)
        
    
    def click_xy(self, x, y, timeout=10):
        """Click the point with x, y coordinates of the browser viewport.
        x: X coordinate of the browser viewport.
        y: Y coordinate of the browser viewport.
        """
        self.get_tab().Input.dispatchMouseEvent(type='mouseMoved', x=x, y=y, _timeout=timeout)
        self.get_tab().Input.dispatchMouseEvent(type='mousePressed', x=x, y=y, button='left', clickCount=1, _timeout=timeout)
        self.get_tab().Input.dispatchMouseEvent(type='mouseReleased', x=x, y=y, button='left', clickCount=1, _timeout=timeout)
        # 同步鼠标位置,保证后续 move_to/random_move 从正确的位置起算轨迹
        self._mouse_pos = (int(round(x)), int(round(y)))

    # ------------------------------------------------------------------
    # 拟人化鼠标移动
    # ------------------------------------------------------------------
    # 真实鼠标回报率一般 125Hz,浏览器侧按 60~90Hz 采样,这里取中间值
    _MOUSE_HZ = 85

    @staticmethod
    def _min_jerk(t):
        """最小抖动(minimum-jerk)归一化位移曲线。
        真人手部运动的速度是钟形的:先加速、中段最快、收尾减速,而非常速直线。
        """
        t = 0.0 if t < 0.0 else (1.0 if t > 1.0 else t)
        return t * t * t * (10.0 - 15.0 * t + 6.0 * t * t)

    @staticmethod
    def _fitts_duration(distance, tolerance=24.0):
        """按 Fitts 定律估算移动耗时(秒):距离越远越慢,但增长是对数的而非线性。
        """
        distance = max(float(distance), 1.0)
        base = 0.085 + 0.13 * math.log2(1.0 + distance / tolerance)
        return min(max(base * random.uniform(0.85, 1.2), 0.08), 1.6)

    def _viewport_size(self, timeout=10):
        """获取视口尺寸。
        注意不能用 get_window_info() 的 bounds:那是窗口外框尺寸,包含了地址栏、
        标签栏、书签栏等浏览器自身的 UI,落在这些区域里的坐标不会产生页面内的
        鼠标事件(等于白动一次)。
        """
        try:
            info = self.evaluate(
                'JSON.stringify({w: window.innerWidth, h: window.innerHeight})',
                timeout=timeout)
            size = json.loads(info) if info else None
            if size and size.get('w') and size.get('h'):
                return int(size['w']), int(size['h'])
        except Exception as e:
            logger.debug('Get viewport size by JS failed: {}'.format(str(e)))
        try:
            bounds = self.get_window_info(timeout=timeout)['bounds']
            # 拿不到视口时退回窗口外框,粗略扣掉边框和浏览器 UI
            return max(int(bounds['width']) - 16, 100), max(int(bounds['height']) - 88, 100)
        except Exception as e:
            logger.debug('Get viewport size by window bounds failed: {}'.format(str(e)))
        return 1280, 720

    def _guess_mouse_pos(self, width, height):
        """鼠标位置未知时,以视口中部偏下的区域作为起点(最常见的停留位置)
        """
        return (int(width * random.uniform(0.35, 0.65)),
                int(height * random.uniform(0.35, 0.70)))

    def _plan_move(self, start, end, tremor=1.0, duration_scale=1.0, bounds=None):
        """规划一条拟人轨迹,返回 [(x, y, delay), ...],delay 是距上一个点的等待秒数。

        轨迹由三部分叠加而成:
        1. 三次贝塞尔曲线 —— 人手走的是带弧度的曲线,终点越远弯得越明显;
        2. 最小抖动速度剖面 —— 钟形速度,带轻微不对称(加速段比减速段短);
        3. 手抖 —— 低频正弦 + 高斯噪声,且越接近落点幅度越小(瞄准末段更稳)。
        """
        x0, y0 = float(start[0]), float(start[1])
        x1, y1 = float(end[0]), float(end[1])
        dx, dy = x1 - x0, y1 - y0
        distance = math.hypot(dx, dy)
        if distance < 0.5:
            return [(x1, y1, 0.0)]

        duration = max(self._fitts_duration(distance) * duration_scale, 0.05)
        steps = int(min(max(duration * self._MOUSE_HZ, 6), 90))
        dt = duration / steps
        # 单位法向量,弧度和手抖都加在这个方向上
        ux, uy = -dy / distance, dx / distance
        # 贝塞尔控制点:沿弦方向取随机比例,再沿法向偏移,曲率随距离增长但有上限
        bend = random.uniform(-1.0, 1.0) * min(distance * 0.18, 70.0)
        c1, c2 = random.uniform(0.15, 0.35), random.uniform(0.65, 0.85)
        p1x = x0 + dx * c1 + ux * bend * random.uniform(0.7, 1.0)
        p1y = y0 + dy * c1 + uy * bend * random.uniform(0.7, 1.0)
        p2x = x0 + dx * c2 + ux * bend * random.uniform(0.2, 0.5)
        p2y = y0 + dy * c2 + uy * bend * random.uniform(0.2, 0.5)
        # 手抖参数
        freq = random.uniform(1.1, 2.6)
        phase = random.uniform(0.0, 2.0 * math.pi)
        amplitude = min(1.6, 0.3 + distance * 0.0025) * tremor
        # 加速段比减速段短 —— 真人收尾更慢
        skew = random.uniform(0.80, 0.95)
        # 偶尔中途卡顿一下(人是会走神的)
        stall_at = 0
        stall_extra = 0.0
        if steps > 8 and random.random() < 0.15:
            stall_at = random.randint(max(int(steps * 0.3), 1), max(int(steps * 0.7), 2))
            stall_extra = random.uniform(0.02, 0.07)

        points = []
        for i in range(1, steps + 1):
            t = (i / float(steps)) ** skew
            s = self._min_jerk(t)
            b = 1.0 - s
            px = (b ** 3) * x0 + 3 * (b ** 2) * s * p1x + 3 * b * (s ** 2) * p2x + (s ** 3) * x1
            py = (b ** 3) * y0 + 3 * (b ** 2) * s * p1y + 3 * b * (s ** 2) * p2y + (s ** 3) * y1
            damp = 1.0 - s
            offset = (amplitude * damp * math.sin(2.0 * math.pi * freq * s + phase)
                      + random.gauss(0.0, 0.35 * damp + 0.05))
            px += ux * offset
            py += uy * offset
            if bounds:
                px = min(max(px, 0.0), bounds[0] - 1.0)
                py = min(max(py, 0.0), bounds[1] - 1.0)
            delay = dt * random.uniform(0.85, 1.15)
            if stall_at and i == stall_at:
                delay += stall_extra
            points.append((px, py, delay))

        # 归一化等待时间,避免随机抖动把总耗时拉偏
        total = sum(p[2] for p in points)
        if total > 0:
            weight = duration / total
            points = [(p[0], p[1], p[2] * weight) for p in points]
        return points

    def _emit_move(self, plan, timeout=10):
        """按规划轨迹逐点派发 mouseMoved 事件,返回最后一个落点的整数坐标
        """
        last = None
        for x, y, delay in plan:
            if delay > 0:
                time.sleep(delay)
            x, y = int(round(x)), int(round(y))
            if last is not None and (x, y) == last and len(plan) > 1:
                # 位置没变化,真实鼠标不会产生新的移动事件(低速段很常见)
                continue
            self.get_tab().Input.dispatchMouseEvent(
                type='mouseMoved',
                x=x,
                y=y,
                button='none',
                buttons=0,
                timestamp=time.time(),
                _timeout=timeout)
            last = (x, y)
        if last is None:
            last = (int(round(plan[-1][0])), int(round(plan[-1][1])))
        return last

    def move_to(self, x, y, timeout=10, overshoot=None):
        """沿拟人轨迹把鼠标移动到视口坐标 (x, y)。
        overshoot: 是否做"冲过头再修正",None 表示按距离和概率随机决定 ——
                   真实的长距离甩动经常稍微冲过目标,再靠一次短促修正拉回来。
        """
        width, height = self._viewport_size(timeout=timeout)
        target = (min(max(float(x), 0.0), width - 1.0),
                  min(max(float(y), 0.0), height - 1.0))
        start = self._mouse_pos or self._guess_mouse_pos(width, height)
        distance = math.hypot(target[0] - start[0], target[1] - start[1])
        if overshoot is None:
            overshoot = distance > 220 and random.random() < 0.55
        if overshoot and distance > 220:
            ratio = random.uniform(1.004, 1.03)
            over = (start[0] + (target[0] - start[0]) * ratio,
                    start[1] + (target[1] - start[1]) * ratio)
            plan = self._plan_move(start, over, duration_scale=0.82,
                                   bounds=(width, height))
            last = self._emit_move(plan, timeout=timeout)
            time.sleep(random.uniform(0.03, 0.09))
            # 修正动作短、抖、直
            plan = self._plan_move(last, target, tremor=0.4, duration_scale=0.35,
                                   bounds=(width, height))
        else:
            plan = self._plan_move(start, target, bounds=(width, height))
        self._mouse_pos = self._emit_move(plan, timeout=timeout)
        # 到位后偶尔来一两下 1px 以内的微调,像人在确认落点
        if random.random() < 0.35:
            for _ in range(random.randint(1, 2)):
                time.sleep(random.uniform(0.02, 0.06))
                # 位移至少 1px,否则等于没动
                jx = self._mouse_pos[0] + random.choice((-1, 1))
                jy = self._mouse_pos[1] + random.choice((-1, 0, 1))
                self._mouse_pos = self._emit_move([(jx, jy, 0.0)], timeout=timeout)
        return self._mouse_pos

    def random_move(self, times=1, interval=0.1, timeout=10, area=None):
        """在浏览器视口内随机移动鼠标若干次,轨迹与节奏模仿真人。

        times: 移动次数。
        interval: 两次移动之间的停顿(秒),实际会在此基础上随机浮动;传 0 表示不额外停顿。
        area: 可选,限定活动区域 (left, top, right, bottom),默认全视口(四边各留 4% 边距,
              真人很少把光标顶到最边上)。
        """
        width, height = self._viewport_size(timeout=timeout)
        margin_x, margin_y = int(width * 0.04), int(height * 0.04)
        left, top, right, bottom = area or (margin_x, margin_y,
                                            width - margin_x, height - margin_y)
        left, right = max(int(left), 0), min(int(right), width - 1)
        top, bottom = max(int(top), 0), min(int(bottom), height - 1)
        if right <= left or bottom <= top:
            raise ValueError('Invalid area: {}'.format(area))

        for i in range(times):
            if i > 0 and interval:
                # 真人不会按固定节拍移动,停顿时间本身也是抖动的
                time.sleep(max(interval * random.uniform(0.6, 1.6), 0.0))
            # 近一半的移动是"就近活动":人不会每次都横跨整屏
            if self._mouse_pos and random.random() < 0.45:
                span_x = random.randint(80, 320)
                span_y = random.randint(60, 220)
                x = self._mouse_pos[0] + random.randint(-span_x, span_x)
                y = self._mouse_pos[1] + random.randint(-span_y, span_y)
                x = min(max(x, left), right)
                y = min(max(y, top), bottom)
            else:
                x = random.randint(left, right)
                y = random.randint(top, bottom)
            logger.info('Human-like move to ({}, {})'.format(x, y))
            self.move_to(x, y, timeout=timeout)
        return self._mouse_pos

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
                chrome_pids = []
                for sub_p in p.children(recursive=True):
                    chrome_pids.append(sub_p.pid)
                return chrome_pids
            except (psutil.NoSuchProcess, ValueError):
                # 进程已死或pid无效，不算错误
                logger.debug('Process({}) does not exit.'.format(self.chrome_process.pid))
            except Exception as e:
                logger.debug('Exception in get_chrome_subpids: {}'.format(str(e)))
        return None

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
            # terminate/wait失败（如进程已死）不应中断后续的子进程清理和临时目录删除
            try:
                self.chrome_process.terminate()
                self.chrome_process.wait()
            except Exception as e:
                logger.debug('Exception when terminate chrome main process: {}'.format(str(e)))
            # 冗余兜底：直接终止整个Job，确保组内所有进程（含子进程树）全部退出
            self._kill_by_job()
            
            if chrome_pids:
                # Kill all chrome subprocesses
                for pid in chrome_pids:
                    try:
                        p = psutil.Process(pid)
                        logger.debug('Killing process({}) {}.'.format(p.pid, p.name()))
                        try:
                            p.send_signal(SIGTERM)
                        except psutil.AccessDenied:
                            pass             
                    except psutil.NoSuchProcess:
                        logger.debug('Chrome process({}) exited indeed.'.format(pid))
            self.chrome_process = None
            if self.vdisplay:
                try:
                    self.vdisplay.stop()
                except Exception as e:
                    logger.debug('Exception when stop vdisplay: {}'.format(str(e)))
            # Remove temporary user data directory
            temp_dir = self.temp_chrome_user_data_dir
            if temp_dir and os.path.exists(temp_dir):
                for i in range(5):
                    try:
                        shutil.rmtree(temp_dir)
                        logger.info(f"Successfully removed temp dir \"{temp_dir}\"")
                        break
                    except Exception as e:
                        logger.warning(f"Attempt {i+1} failed to delete \"{temp_dir}\": {e}")
                        time.sleep(2)
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