Python3版本chromepy

## 如何使用指定的浏览器？如何传递额外的命令行参数给浏览器？
chromepy.Chrome的chrome_path参数可以用来指定具体使用哪个浏览器，不指定的情况下默认使用系统默认的浏览器。如下示例，指定使用指纹浏览器VirtualBrowser。通过chromepy.Chrome的extra_cmd_args参数可以向浏览器传递额外的命令参数。
```python
from chromepy import chrome

chrome_path = r'"C:\Program Files\VirtualBrowser\VirtualBrowser\126.0.6478.127\VirtualBrowser.exe"'
extra_cmd_args = ['--worker-id=1', r'--user-data-dir=C:\Users\Administrator\AppData\Local\VirtualBrowser\Workers\1', '--load-extension=', '--ignore-certificate-errors']
browser = chrome.Chrome(chrome_path=chrome_path, extra_cmd_args=extra_cmd_args)
browser.open('https://fingerprintjs.github.io/fingerprintjs/')
time.sleep(10)
browser.quit()
```


## 如何实现多线程（进程）？
1. 默认情况下，Chrome浏览器使用固定的用户数据存储目录（例如，Windows下"~\AppData\Local\Chromium\User Data", Linux下"~/.config/google-chrome"），所以只能启动一个Chrome浏览器实例。
2. 可以通过--user-data-dir参数来指定用户数据存储目录，不同的Chrome浏览器实例使用不同的用户数据目录，从而实现同时启动多个Chrome浏览器实例。chromepy.Chrome现已添加chrome_user_data_dir参数来支持此功能，如下示例。当然，也可以像上面例子一样，通过extra_cmd_args参数来指定--user-data-dir参数来指定用户数据存储目录的路径。
3. 同一个用户数据目录下可以支持多个不同的用户配置目录，每个目录对应一个浏览器用户，默认的用户配置目录是"Default"（例如，Windows下"~\AppData\Local\Chromium\User Data\Default", Linux下"~/.config/google-chrome/Default"）。chromepy.Chrome的chrome_profile参数可以用来指定具体使用哪个用户目录，不指定的情况下默认使用"Default"。当然，也可以向上面例子一样，通过extra_cmd_args参数来指定--profile-directory参数来指定用户配置目录（例如，'--profile-directory="Profile1"'）。

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

## 如何实现在Chrome浏览器启动前清理掉历史的Cookies和Cache？
创建Chrome实例前，先删除掉对应的用户配置目录即可。


