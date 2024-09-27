Python3版本chrome.py

## 如何实现多线程（进程）？

由于一个Chrome版本只允许启动一个开发者协议端口的实例，所以要实现多线程（进程），需要同时有多个不同的chrome版本。

建议使用Google Chrome Portable版，这里有各个版本的下载连接：
https://sourceforge.net/projects/portableapps/files/Google%20Chrome%20Portable/?continueFlag=5767c9001c49f44f85819402a590d40a。

然后通过chrome_path参数来指定具体启动哪个版本的chrome进程。
