#!/usr/bin/env python3

import sys,getopt
import requests
import socket
import nmap
import time
import threading
import json
from queue import Queue

# 核心类
class Scan(object):
    ok_code = [200,403,302]
    q = Queue()
    GET_PROXY = ''
    def __init__(self,get_proxy=''):
        self.GET_PROXY = get_proxy
    # 基础tcp端口扫描 
    def portScan(self,ip,port,timeout = 0.01):
        try:
            #设置默认超时时间，可以根据网络状况扫描成度修改,这个扫描还有一定限制，只能是tcp扫描，会受到防火墙等等限制
            socket.setdefaulttimeout(timeout)
            s = socket.socket()
            s.connect((ip,port))
            print('port： %d \t[开放]' %port)
            s.close()
        except:
            pass
    # nmap扫描，参数ip或ip段 端口范围,也可以指定参数扫描，详见：https://xiaix.me/python-nmapxiang-jie/
    def nmapPortScan(self,ip,portRange):
        #   采用默认nmap -oX - -p 20-443 -sV 45.76.101.190扫描
        np = nmap.PortScanner()
        # 端口较多的话会在这里卡一会
        np.scan(ip,portRange)
        print('-----nmapScan-----')
        print('Host:%s (%s)'%(ip,np[ip].hostname()))
        print('State : %s' %np[ip].state())
        for proto in np[ip].all_protocols():
            print('-----------')
            print('Protocol : %s' %proto)
            lport = np[ip][proto].keys()
            #lport.sort()#排序 没必要
            for port in lport:
                print('port : %s \tstate : %s' %(port,np[ip][proto][port]['state'])) 
    # 基础目录扫描
    def indexScan(self,url,proxies = ''):
        try:
            s = requests.session()
            r = s.put(url,proxies=proxies)
            if r.status_code in self.ok_code:
                print(str(r.status_code)+" : "+url)
        except:
            pass
    # 常见端口扫描 测试扫描虚拟机耗时2s左右
    def portScanTop100(self,ip):
        filePort = open('./portScan/portTop_100.txt','r')
        for line in filePort.readlines():
            self.portScan(ip,int(line,10))
    # 多线程扫描端口工作程序
    def  queuePortScan(self):
        while not self.q.empty():
            port = self.q.get()
            try:
                self.portScan('192.168.0.109',port)
            finally:
                self.q.task_done()
    # 用于指定范围多线程端口扫描 thread1 = threading.Thread(target=threadPortScan,args=('10.203.87.61',1,100,))
    def threadPortScan(self,ip,startPort,stopPort):
        for port in range(startPort,stopPort):
            self.portScan(ip,port)
    # 全端口多线程扫描
    def threadAllPortScan(self,threadMount=500):
        # map(self.q.put,range(1,65535))
        for i in range(1,500):
            self.q.put(i)
        threads = [threading.Thread(target=self.queuePortScan) for i in range(threadMount)]
        # map+匿名函数启动线程
        # map(lambda x:x.start(),threads)这里需要弄清原理
        for i in range(threadMount):
            threads[i].start()
        self.q.join()
    # 目录扫描 根据字典大小耗时不等 相对耗时较长 要用多线程分配字典 24kb的字典扫了165s
    def indexScancommon(self,url,proxy=False):
        # 如果出现‘gbk' codec can't decode bytes in position 31023: illegal multibyte sequence 
        # fileIndex = open('./dirScan/PHP.txt','r',encoding='gb18030',errors='ignore')
        fileIndex = open('./dirScan/DIR.txt','r')
        for line in fileIndex.readlines():
            line=line.strip('\n')
            url = url+'/'+line
            proxies = ''
            if proxy:
                #获取代理
                proxies = self.__getProxyIp()
            self.indexScan(url,proxies)

    # 获取代理
    def __getProxyIp(self,types='2',count='1',country='国内'):
        try:
            r = requests.get(self.GET_PROXY+'?types='+types+'&count='+count+'&country='+country)
            print(self.GET_PROXY+'?types='+types+'&count='+count+'&country='+country,r.text)
            ip_ports = json.loads(r.text)
            ip = ip_ports[0][0]
            port = ip_ports[0][1]
            proxies={
                'http':'http://%s:%s'%(ip,port),
                'https':'http://%s:%s'%(ip,port)
            }
        except (IndexError,json.decoder.JSONDecodeError):
            print('获取代理IP失败，程序退出！！')
            sys.exit()
        except requests.exceptions.ConnectionError:
            print('代理接口拒绝连接，程序退出！！')
            sys.exit()
        return proxies
        


def main(argv):
    IP = ''         # 要端口扫描的站点ip
    HOST = ''       # 要目录扫描的站点域名
    URL = ''        # 要目录扫描的url
    PROXY = False   # 是否使用代理
    GET_PROXY = 'http://45.76.101.190:8000/'  # 填写已经搭建好的获取代理的IPProxyPool接口 不使用代理可以不写 如http://127.0.0.1:8000/(结尾有斜杠)
    SCAN = Scan(GET_PROXY)
    #获取命令行参数
    try:
        opts,args = getopt.getopt(argv,"h:u:",["version","help","proxy","url="])
    except getopt.GetoptError:
        # 打印help
        sys.exit(2)
    for opt,arg in opts:
        if opt == "--help":
            print(r'假装打印了一个help')
            sys.exit()
        elif opt == "--version":
            print(r'webscan version 1.0 ( http://github.com/ssssdl/thread-scan )')
            sys.exit()
        elif opt in ("-u","--url"):
            URL = arg
        elif opt == "--proxy":
            PROXY = True
    # 执行端口扫描

    # 执行目录扫描
    if URL != '':
        SCAN.indexScancommon(URL,PROXY)
        

if __name__=='__main__':
    main(sys.argv[1:])