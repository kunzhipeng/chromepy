# coding: utf-8
# chrome.py
# 使用Google Chrome Dev Protocol控制Chrome浏览器
# https://chromedevtools.github.io/devtools-protocol/

import sys
import os
import platform
import re
import time
import socket
import threading
import base64
import pprint
# https://github.com/fate0/pychrome
import pychrome
import subprocess
import psutil
from signal import SIGTERM
from contextlib import closing
from base64 import b64encode
from http.cookiejar import Cookie, LWPCookieJar

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
            print("Port {}:{} is open".format(host, port))
            return True
        else:
            print("Port {}:{} is not open".format(host, port))
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
                 remote_url=None,
                 before_request_sent_callback=None,
                 after_response_reveiced_callback=None,
                 execution_context_created_callback=None,
                 chrome_profile=None,
                 start_position=(0, 0),
                 window_size=(1024, 768),
                 disable_cache=False,
                 debug=False):
        """Startup a chrome instance
        proxy: Proxy to use.
        download_images: Whether to download images.
        load_timeout: Page load timeout(seconds).
        user_agent: Specify user-agent.
        display: A boolean that tells ghost to displays UI. Headless model. Chrome version >= 59.
        chrome_path: Path of chrome binary file, if value is None will use default path.
        before_request_sent_callback: Fired when page is about to send HTTP request.
        after_response_reveiced_callback: Fired when HTTP response is available.
        execution_context_created_callback: Fired when new execution context is created.
        chrome_profile: Use specify profile directoy.
        start_position: The start window position.
        window_size: The start window size.
        disable_cache: Do not use chache.
        debug: Print debug info if value is True. 
        """
        self.proxy = None
        self.proxy_credentials = None
        self.proxy_username = None
        self.proxy_password = None
        self.remote_url = remote_url
        self.user_agent = user_agent
        self.display = display
        self.before_request_sent_callback = before_request_sent_callback
        self.after_response_reveiced_callback = after_response_reveiced_callback
        self.execution_context_created_callback = execution_context_created_callback
        self.download_images = download_images
        self.start_position = start_position
        self.window_size = window_size
        self.disable_cache = disable_cache
        self.chrome_profile = chrome_profile
        self.debug = debug
        self.requests = {}
        if proxy:
            match = re.match(r'((?P<username>\w+):(?P<password>\w+)@)?(?P<host>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})(:(?P<port>\d+))?', proxy)
            if not match:
                match = re.compile(r'((?P<username>\w+):(?P<password>\w+)@)?(?P<host>[a-z\d\.\-]+)(:(?P<port>\d+))?', re.IGNORECASE).match(proxy)
            if match:
                groups = match.groupdict()
                proxy_username = groups.get('username')
                proxy_password = groups.get('password')
                proxy_host = groups.get('host') 
                proxy_port = int(groups.get('port'))
                if proxy_username and proxy_password:
                    # Proxy-Authorization credentials
                    credentials = '{}:{}'.format(proxy_username, proxy_password)
                    self.proxy_credentials = b64encode(credentials.encode('UTF-8'))
                self.proxy = '{}:{}'.format(proxy_host, proxy_port)
                self.proxy_username = proxy_username
                self.proxy_password = proxy_password
            if self.debug:
                print('proxy:', self.proxy)
                print('proxy_username:', self.proxy_username)
                print('proxy_password:', self.proxy_password)
        
        if not self.remote_url:
            # Not specify remoge_url, will start a chrome instance
            # Chrome path
            self.chrome_path = chrome_path or self.get_default_chrome_path()
            print(self.chrome_path)
            
            # "Google Chrome Dev Protocol" listen port
            self.dev_protocol_port = find_free_port()
            
            self.remote_url = 'http://127.0.0.1:{}'.format(self.dev_protocol_port)
            
            # Ignore certificate errors
            # '--ignore-certificate-errors'
            chrome_args = ['--remote-allow-origins=*', '--disable-web-security', '--disable-features=IsolateOrigins,site-per-process', '--disable-site-isolation-trials']
            chrome_args.append('--remote-debugging-port={}'.format(self.dev_protocol_port))
            # Add proxy
            if self.proxy:
                if self.debug:
                    print('Set proxy into {}'.format(proxy))
                chrome_args.append('--proxy-server="https={};http={}"'.format(self.proxy, self.proxy))
            # User-agent
            if self.user_agent:
                if self.debug:
                    print('Set User-agent into "{}"'.format(self.user_agent))
                chrome_args.append('--user-agent="{}"'.format(self.user_agent))
            # Chrome profile
            if self.chrome_profile:
                # Chrome "User Data" default directory: C:\Users\Administrator\AppData\Local\Google\Chrome\User Data
                if self.debug:
                    print('Set --profile-directory into "{}"'.format(self.chrome_profile))
                chrome_args.append('--profile-directory="{}"'.format(self.chrome_profile))
            # Headless model
            if not self.display:
                if self.debug:
                    print('Use headless model: --headless --no-sandbox --disable-gpu')
                chrome_args.append('--headless --no-sandbox --disable-gpu')
            # Start position
            if self.start_position:
                if self.debug:
                    print('Set --window-position={},{}'.format(self.start_position[0], self.start_position[1]))
                chrome_args.append('--window-position={},{}'.format(self.start_position[0], self.start_position[1]))
            # Start window size
            if self.window_size:
                if self.debug:
                    print('Set --window-size={},{}'.format(self.window_size[0], self.window_size[1]))
                chrome_args.append('--window-size={},{}'.format(self.window_size[0], self.window_size[1]))
            if self.disable_cache:
                if self.debug:
                    print('Set --disable-application-cache --media-cache-size=1 --disk-cache-size=1')
                chrome_args.append('--disable-application-cache --media-cache-size=1 --disk-cache-size=1')
            
            # Start chrome
            cmd = self.chrome_path + ' ' + ' '.join(chrome_args)
            if self.debug:
                print('Starting chrome with "{}"'.format(' '.join(chrome_args).strip()))
                print(cmd)
            self.chrome_process = subprocess.Popen(cmd, env=os.environ.copy(), shell=True)         
        else:
            if not proxy:
                print('Since the chrome has started, the proxy parameter will be ignored.')
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
                if num >= 60:
                    self.quit()
                    raise Exception('Can not connect to chrome during 60 seconds.')
                else:
                    time.sleep(1)

        # create a browser instance
        self.browser = pychrome.Browser(url=self.remote_url)
        self.tab = None
        
    def get_default_chrome_path(self):
        """Get the realpath of chrome binary file
        """
        # Chrome installed in the default location for each system:
        # https://github.com/SeleniumHQ/selenium/wiki/ChromeDriver#requirements
        system_type = platform.system()
        if system_type == 'Windows':
            # On Windows
            for chrome_path in [r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
                                r'C:\Program Files\Google\Chrome\Application\chrome.exe',
                                os.path.join(os.path.expanduser('~'), 'AppData\\Local\\Google\\Chrome\\Application\\chrome.exe'),
                                os.path.join(os.path.expanduser('~'), 'Local Settings\\Application Data\\Google\\Chrome\\Application\\chrome.exe'),
                                ]:
                if os.path.exists(chrome_path):
                    return '"{}"'.format(chrome_path)
        elif system_type == 'Linux':
            # On Linux
            return '/usr/bin/google-chrome'
        
    def __request_intercepted(self, interceptionId, request, **kwargs):
        """Network.requestIntercepted Callback
        """
        if self.debug:
            print("Intercepted request {}".format(request.get('url')))
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
                print('Exception when call Network.continueInterceptedRequest: {}'.format(str(e)))
        else:
            try:
                self.tab.Network.continueInterceptedRequest(
                    interceptionId=interceptionId,
                    headers=headers
                )
            except Exception as e:
                print('Exception when call Network.continueInterceptedRequest: {}'.format(str(e)))
        
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
                        print('Failed to get response body for "{}": {}'.format(request.get('url'), str(e)))
                    body_text = ''
                self.after_response_reveiced_callback(request, response, body_text)
            else:
                if self.debug:
                    print('Does not find related reponse data for requestId: {}'.format(requestId))
             

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
            if self.proxy_credentials:
                if self.debug:
                    print('Add Network.requestIntercepted callback')
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
                    print('Add Network.requestWillBeSent callback')
                self.tab.Network.requestWillBeSent = self.__request_will_be_sent
                need_network_enabled = True
            if self.after_response_reveiced_callback:
                if self.debug:
                    print('Add Network.responseReceived callback')
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
        print('Loading {} ...'.format(url))
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
        for tab in self.browser.list_tab():
            self.browser.close_tab(tab)
        time.sleep(1)

    def get_chrome_subpids(self):
        """获取chrome子进程ID
        """
        chrome_pids = []
        if self.chrome_process:
            try:
                p = psutil.Process(self.chrome_process.pid)
            except psutil.NoSuchProcess:
                print('Process({}) does not exit.'.format(self.chrome_process.pid))
            else:
                for sub_p in p.children(recursive=True):
                    chrome_pids.append(sub_p.pid)
        return chrome_pids


    def quit(self):
        if self.chrome_process:
            # 获取子进程ID
            chrome_pids = self.get_chrome_subpids()
    
            # 结束主进程
            try:
                self.close_all_tabs()
            except Exception as e:
                print(e)
            self.chrome_process.terminate()
            self.chrome_process.wait()
            
            if chrome_pids:
                # 确保进程都退出了
                for pid in chrome_pids:
                    try:
                        p = psutil.Process(pid)
                        print('Killing process({}) {}.'.format(p.pid, p.name()))
                        p.send_signal(SIGTERM)                 
                    except psutil.NoSuchProcess:
                        print('Chrome process({}) exited indeed.'.format(pid))
            self.chrome_process = None
        
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
        print('#' * 20 + ' REQUEST DATA FOR "{}" '.format(request.get('url')) + '#' * 20)
        pprint.pprint(request)
        print('#' * 80)
        
        
    def after_response_received(request, response, body):
        """HTTP应答接收到了 - 回调函数
        """
        url = request.get('url')
        print('#' * 20 + ' RESPONSE DATA FOR "{}" '.format(url) + '#' * 20)
        pprint.pprint(response)
        print('RESPONSE BODY:')
        print(body)
        print('#' * 80)    
        
    
    browser = Chrome(user_agent='KUNZHIPENG UA',
                     proxy=None,
                     download_images=True,
                     display=True,
                     chrome_profile='debug',
                    #  before_request_sent_callback=before_request_sent,
                    #  after_response_reveiced_callback=after_response_received,
                     debug=True)
    # 查看当前IP
    print('查看当前IP')
    browser.open('http://httpbin.org/ip')
    # 等待页面加载就绪
    browser.wait_for_text(text='"origin"', timeout=10)
    # 获取当前页面HTML
    #print(browser.content)
    browser.capture_to('chrome-ip.png')
    input('Press ENTER to continue.')

    # 查看UA
    print('查看UA')
    browser.open('http://proxies.site-digger.com/headers-view/')
    browser.wait_for_text(text='HTTP_USER_AGENT', timeout=10)
    browser.capture_to('chrome-ua.png')
    # 获取当前页面HTML
    #print(browser.content)
    input('Press ENTER to continue.')

    # 查看Cookies
    print('查看Cookies')
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
    print('删除所有Cookies，然后查看当前Cookies')
    browser.delete_cookies(alldomains=True)
    browser.open('http://httpbin.org/cookies')
    browser.wait_for_text(text='"cookies"', timeout=10)
    # 打印当前Cookies
    pprint.pprint(browser.cookies)
    input('Press ENTER to continue.')

    print('导入Cookies，然后查看当前Cookies')
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