# chromepy

基于`Google Chrome Dev Protocol`协议实现对Chrome浏览器的控制

## 特色
1. 基于CDP协议控制浏览器，不依赖于webdriver，不容易被检测。
2. 支持带用户名密码认证的HTTP代理，不借助插件。注意：不支持带用户名密码认证的socks5代理。
3. 支持Linux无显示环境，使用Xvfb虚拟显示，而非headless模式，不容易被检测。

## 基本用法
```python
from chromepy import chrome

# 启动浏览器
browser = chrome.Chrome()

# 访问指定URL
browser.open('http://bot.sannysoft.com/')
browser.sleep(3)

# 获取当前页面URL
print('Current url:', browser.get_current_url())

# 获取页面HTML
html = browser.content
print('Page HTML:', html)

# 关闭浏览器
input("Press Enter to close the browser and exit...")
browser.close()
```

## 代理设置
```python

proxy = 'http://test:123456@127.0.0.1:2030'
# 注意：socks5代理不支持用户名密码认证，chrome原生不支持
#proxy = 'socks5://127.0.0.1:2030'

# 启动浏览器
browser = chrome.Chrome(proxy=proxy)
```

## Cookie相关操作
```python
import json
from chromepy import chrome

# 启动浏览器
browser = chrome.Chrome()

print('-' * 66)
print('查看当前Cookies')
browser.open('http://httpbin.org/cookies')
# 等待页面加载就绪
browser.wait_for_text(text='"cookies"', timeout=10)
# 获取当前页面的Cookies - 应该是空的
print('Cookies:', json.dumps(browser.get_cookies(), ensure_ascii=False, indent=4))
input("Press Enter to continue...")

print('-' * 66)
print('设置Cookie，并查看浏览器当前Cookies')
# 设置Cookie - 必须指定name\value\domain
browser.add_cookies([{'name': 'name', 'value': 'qi'}, {'name': 'city', 'value': 'xian'}])
# 刷新页面
browser.refresh(ignore_cache=True)
# 获取当前页面的Cookies
print('Cookies:', json.dumps(browser.get_cookies(), ensure_ascii=False, indent=4))
# 保存Cookies到文件
browser.save_cookies('cookies.json')
input("Press Enter to continue...")

# 清除Cookies
print('-' * 66)
print('删除所有Cookies，然后查看当前Cookies')
browser.delete_all_cookies()
# 访问指定URL - 读取Cookies
browser.open('http://httpbin.org/cookies')
browser.wait_for_text(text='"cookies"', timeout=10)
# 获取当前页面的Cookies
print('Cookies:', json.dumps(browser.get_cookies(), ensure_ascii=False, indent=4))
input("Press Enter to continue...")

# 从文件加载Cookies
print('-' * 66)
print('加载Cookies，然后查看当前Cookies')
browser.load_cookies('cookies.json')
browser.open('http://httpbin.org/cookies')
browser.wait_for_text(text='"cookies"', timeout=10)
# 获取当前页面的Cookies
print('Cookies:', json.dumps(browser.get_cookies(), ensure_ascii=False, indent=4))

# 关闭浏览器
input("Press Enter to close the browser and exit...")
browser.close()
```

输出示例：
```text
[Info]Waitting for Chrome CDP being ready...
------------------------------------------------------------------
查看当前Cookies
[Info]Loading http://httpbin.org/cookies ...
Cookies: []
------------------------------------------------------------------
设置Cookie，并查看浏览器当前Cookies
Cookies: [
    {
        "name": "city",
        "value": "xian",
        "domain": "httpbin.org",
        "path": "/",
        "expires": -1,
        "size": 8,
        "httpOnly": false,
        "secure": false,
        "session": true,
        "priority": "Medium",
        "sameParty": false,
        "sourceScheme": "NonSecure",
        "sourcePort": 80
    },
    {
        "name": "name",
        "value": "qi",
        "domain": "httpbin.org",
        "path": "/",
        "expires": -1,
        "size": 6,
        "httpOnly": false,
        "secure": false,
        "session": true,
        "priority": "Medium",
        "sameParty": false,
        "sourceScheme": "NonSecure",
        "sourcePort": 80
    }
]
------------------------------------------------------------------
删除所有Cookies，然后查看当前Cookies
[Info]Loading http://httpbin.org/cookies ...
Cookies: []
------------------------------------------------------------------
加载Cookies，然后查看当前Cookies
[Info]Loading http://httpbin.org/cookies ...
Cookies: [
    {
        "name": "name",
        "value": "qi",
        "domain": "httpbin.org",
        "path": "/",
        "expires": -1,
        "size": 6,
        "httpOnly": false,
        "secure": false,
        "session": true,
        "priority": "Medium",
        "sameParty": false,
        "sourceScheme": "NonSecure",
        "sourcePort": 80
    },
    {
        "name": "city",
        "value": "xian",
        "domain": "httpbin.org",
        "path": "/",
        "expires": -1,
        "size": 8,
        "httpOnly": false,
        "secure": false,
        "session": true,
        "priority": "Medium",
        "sameParty": false,
        "sourceScheme": "NonSecure",
        "sourcePort": 80
    }
]
```

## FAQ
### 如何指定浏览器路径？
`chrome_path`参数可以用来指定chrome浏览器的路径，不指定的情况下默认使用系统默认的chrome浏览器。

### 如何保持用户数据（使用固定的用户数据目录）？
`chrome_user_data_dir`参数可以用来指定chrome浏览器的用户数据目录，默认不指定情况下，每次启动浏览器的时候创建临时的数据目录，关闭的时候自动删除该目录，无法保持用户数据。
如果想要保持用户数据，可以通过`chrome_user_data_dir`指定一个固定的用户数据目录，需要使用绝对路径。

### 如何判断页面是否加载完成？
可以根据页面html内容是否包含指定的文本内容来判断页面是否加载完成。
- `wait_for_text(text, timeout=20)`：等待页面出现指定的文本内容，超时后抛出`TimeoutError`异常。
- `wait_for_any_text(texts, timeout=20)`：等待页面出现指定的任意文本（列表）内容，超时后抛出`TimeoutError`异常。
- `wait_for_all_text(texts, timeout=20)`：等待页面出现指定的所有文本（列表）内容，超时后抛出`TimeoutError`异常。
- 也可以自己循环判断。

### 如何捕获HTTP请求、应答？
通过注册`before_request_sent_callback`和`after_response_reveiced_callback`回调函数，可以捕获HTTP请求、应答。

```python
import pprint
from chromepy import chrome

def before_request_sent(request):
    """HTTP请求发出前 - 回调函数
    """
    print('--> REQUEST DATA FOR "{}":'.format(request.get('url')) )
    pprint.pprint(request)
    print('-' * 66)
    
def after_response_received(request, response, body):
    """HTTP应答接收到后 - 回调函数
    """
    url = request.get('url')
    print('<-- RESPONSE DATA FOR "{}":'.format(url))
    pprint.pprint(response)
    if body:
        print('<-- RESPONSE BODY FOR "{}":'.format(url))
        print(body)
    print('-' * 66)

# 创建Chrome对象并注册抓包回调函数
browser = chrome.Chrome(before_request_sent_callback=before_request_sent, 
                        after_response_reveiced_callback=after_response_received)

browser.open('http://www.webscraping.cn')
browser.sleep(10)
browser.close()
```

### 如何实现多线程（进程）？
1. 默认情况下，Chrome浏览器使用固定的用户数据存储目录（例如，Windows下`~\AppData\Local\Chromium\User Data`, Linux下`~/.config/google-chrome`），所以只能启动一个Chrome浏览器实例。
2. 可以通过`--user-data-dir`参数来指定用户数据存储目录，不同的Chrome浏览器实例使用不同的用户数据目录，从而实现同时启动多个Chrome浏览器实例。chromepy.Chrome现已添加`chrome_user_data_dir`参数来支持此功能，如下示例。当然，也可以像上面例子一样，通过`extra_cmd_args`参数来指定`--user-data-dir`参数来指定用户数据存储目录的路径。
3. 同一个用户数据目录下可以支持多个不同的用户配置目录，每个目录对应一个浏览器用户，默认的用户配置目录是`Default`（例如，Windows下`~\AppData\Local\Chromium\User Data\Default`, Linux下`~/.config/google-chrome/Default`）。chromepy.Chrome的`chrome_profile`参数可以用来指定具体使用哪个用户目录，不指定的情况下默认使用`Default`。当然，也可以向上面例子一样，通过`extra_cmd_args`参数来指定`--profile-directory`参数来指定用户配置目录（例如，`'--profile-directory="Profile1"'`）。

```python
import os
import time
from chromepy import chrome

# 自定义的Chrome用户数据存储目录
chrome_user_data_dir = os.path.join(os.getcwd(), 'chrome_user_data_dir')
os.makedirs(chrome_user_data_dir, exist_ok=True)
print('chrome_user_data_dir: {}'.format(chrome_user_data_dir))

# 启动两个Chrome实例，每个实例使用不同的用户数据目录
browser1 = chrome.Chrome(chrome_user_data_dir=os.path.join(chrome_user_data_dir, 'instance1'), chrome_profile='Default')
print('browser1.remote_url: {}'.format(browser1.remote_url))

browser2 = chrome.Chrome(chrome_user_data_dir=os.path.join(chrome_user_data_dir, 'instance2'), chrome_profile='Default')
print('browser2.remote_url: {}'.format(browser2.remote_url))

time.sleep(10)
browser1.quit()
browser2.quit()
```

运行结果示例：
```
chrome_user_data_dir: f:\scrapers\test\chrome_user_data_dir
Port 127.0.0.1:50766 is open
browser1.remote_url: http://127.0.0.1:50766
Port 127.0.0.1:50768 is open
browser2.remote_url: http://127.0.0.1:50768
```

###  如何实现在Chrome浏览器启动前清理掉历史的cookies和cache？
创建chromepy.Chrome实例前，先删除掉对应的用户配置目录即可。

