# chromepy

基于`Google Chrome Dev Protocol`协议实现对Chrome浏览器的控制。

## 特色

1. 基于CDP协议控制浏览器，不依赖于webdriver，不易被检测。
2. 支持带用户名密码认证的HTTP代理，不借助插件。 注意：不支持带用户名密码认证的socks5代理。
3. 支持多线程，可以在同一台机器上同时启动多个浏览器实例（每个实例使用不同的用户数据目录）。
4. 支持Linux无显示环境，使用Xvfb虚拟显示，而非headless模式，不容易被检测。

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

## 设置User-Agent、Accept-Language

`Chrome`类的`user_agent`参数用于设置User-Agent，`accept_language`参数用于设置Accept-Language。
```python
from chromepy import chrome

# User-Agent设置为"kunzhipeng"，Accept-Language设置为"fr"（法语）
browser = chrome.Chrome(user_agent='kunzhipeng', accept_language='fr')
try:
    # Mozilla 官网支持 90+ 种语言，会根据 Accept-Language 自动跳转。
    browser.open('https://www.mozilla.org')
    #browser.open('https://httpbin.org/headers')
except chrome.TimeoutError:
    print('Timeout!')
```


# 执行JS代码

```python
from chromepy import chrome

# 打开百度首页，输入关键词"西安鲲之鹏"，然后点击""
# 启动浏览器
browser = chrome.Chrome(proxy=proxy)

# 访问指定URL
browser.open('https://www.baidu.com')
browser.wait_for_text('id="kw"')

# 执行js - 实现填入关键词
browser.evaluate('document.getElementById("kw").value = "西安鲲之鹏"')
browser.sleep(1)
# "点击搜索"方法一：通过执行js实现
browser.evaluate('document.getElementById("su").click()')
# "点击搜索"方法二：通过模拟鼠标操作实现
# browser.click(css_selector='#su')

# 关闭浏览器
input("Press Enter to close the browser and exit...")
browser.close()
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

## 如何指定浏览器路径？

`Chrome`类的`chrome_path`参数可以用来指定chrome浏览器的路径，不指定的情况下默认使用系统默认的chrome浏览器。

## 如何保持用户数据（使用固定的用户数据目录）？

`Chrome`类的`chrome_user_data_dir`参数可以用来指定chrome浏览器的用户数据目录，默认不指定情况下，每次启动浏览器的时候创建临时的数据目录，关闭的时候自动删除该目录，无法保持用户数据。
如果想要保持用户数据，可以通过`chrome_user_data_dir`指定一个固定的用户数据目录，需要使用绝对路径。

## 如何添加额外的http请求头？

- 方法1：使用`browser.set_extra_http_headers(headers)`，如下示例代码。
- 方法2：在调用`browser.open(url, headers)`方法时，指定`headers'参数。

```python
# 设置额外的请求头
from chromepy import chrome

browser = chrome.Chrome()
try:
    browser.set_extra_http_headers(headers={'X-Test-Header': 'kunzhipeng'})
    # 回显请求头
    browser.open('https://httpbin.org/headers')
except chrome.TimeoutError:
    print('Timeout!')
```


## 如何判断页面是否加载完成？
`browser.open(url)`打开某个页面时，会在浏览器开始导航后立即返回，并不会等待页面加载完成。
可以根据页面html内容是否包含指定的文本内容来判断页面是否加载完成。`chromepy`提供了如下方法：

- `browser.wait_for_text(text, timeout=20)`：等待页面出现指定的文本内容，超时后抛出`TimeoutError`异常。
- `browser.wait_for_any_text(texts, timeout=20)`：等待页面出现指定的任意文本（列表）内容，超时后抛出`TimeoutError`异常。
- `browser.wait_for_all_text(texts, timeout=20)`：等待页面出现指定的所有文本（列表）内容，超时后抛出`TimeoutError`异常。
- 也可以自己循环判断。

下面是一个详细的示例：
```
import re
from chromepy import chrome

# 启动浏览器
browser = chrome.Chrome()

# 访问指定URL
try:
    browser.open('http://bot.sannysoft.com/', timeout=10)
except chrome.TimeoutError:
    # 打开页面超时
    print('Timeout to open the page!')
else:
    # 等待页面加载完成
    try:
        # 根据页面元素判断页面是否加载完成
        browser.wait_for_text(text=re.compile(r'<td id="webgl-renderer"[^<>]*>.+</td>', re.IGNORECASE), timeout=5)
    except chrome.TimeoutError:
        print('Timeout to wait for the page ready!')
    else:
        print('The page is ready now!')
        # 停止加载额外的资源
        browser.stop_loading()

    # 获取当前页面URL
    print('Current url:', browser.get_current_url())

    # 获取页面HTML
    html = browser.content
    print('Page HTML:', html)

# 关闭浏览器
input("Press Enter to close the browser and exit...")
browser.close()
```

## 如何点击页面元素？
- `browser.click(css_selector, scroll=True)`：模拟鼠标点击指定的css选择器对应的元素，例如前面示例中的`browser.click(css_selector='#su')`。`scroll`参数为`True`时，点击元素前会先将元素滚动到页面可见区域。
- `browser.click_xy(x, y)`：模拟鼠标点击指定的坐标位置。注意：这里的(x, y)坐标位置是相对于浏览器视口的左上角(0,0)的。
- 也可以通过执行js来实现。例如，`browser.evaluate('document.getElementById("su").click()')`。


## 如何向下滚动页面？
`browser.scroll_down(distance)`方法提供了向下滚动页面的功能，`distance`参数用于控制滚动的距离。返回值为`相对于页面顶端，窗口当前总共滚动了多少像素`(即window.scrollY)。
如下示例，将一直（最多100次）向下滚动页面直至滚动条位置不再发生变化。


```python
import os
from chromepy import chrome

browser = chrome.Chrome()
browser.open('https://news.qq.com/ch/edu')

num = 0
previouse_scroll_height = 0
not_change_times = 0
while num < 100:
    num += 1
    print('第{}次滚动'.format(num))
    current_scroll_height = browser.scroll_down(distance=500)
    if current_scroll_height > previouse_scroll_height:
        not_change_times = 0
        previouse_scroll_height = current_scroll_height
        browser.sleep(0.5)
    else:
        not_change_times += 1
        if not_change_times >= 3:
            # 连续3次垂直方向滚动像素值没有变化，认为到底了
            print('滚动到底部了!')
            break
        else:
            browser.sleep(0.5)

# 关闭浏览器
input("Press Enter to close the browser and exit...")
browser.close()
```

## 如何设置浏览器窗口位置、大小？

设置窗口位置：
`browser.location(x, y)`

设置窗口大小：
`browser.size(width, height)` 单位为像素

设置窗口最大化：
`browser.max()` 

设置窗口最小化：
`browser.mini()` 

将窗口恢复为普通状态：
`browser.normal()` 


## 如何捕获HTTP请求、应答？

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

## 如何实现多线程（进程）？

默认即支持多线程。注意事项：
1. 每个线程需要创建独立的`Chrome`实例。
2. 不同的`Chrome`实例不能使用相同的用户数据存储目录`chrome_user_data_dir`，否则只能成功启动其中的一个。建议不指定`chrome_user_data_dir`参数，或者每个线程使用不同的`chrome_user_data_dir`值。


### 如何实现在Chrome浏览器启动前清理掉历史的cookies和cache？

- 如果未指定`chrome_user_data_dir`，每次启动浏览器的时候创建临时的数据目录，也就不存在有历史cookies和cache数据。
- 如果指定了`chrome_user_data_dir`，创建`Chrome`实例前，先删掉（清空）对应的用户配置目录即可。