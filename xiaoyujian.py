#!/usr/bin/env python3
import requests
import socket
import nmap
import time
import threading
from queue import Queue
# 分析一下 ：
# 正确的代码（200，403，302）写在一个列表里面,可以修改的
# 多线程  写在一个类里面 url等等作为类中的变量
# try等等

# 核心类
class Scan(object):
    ok_code = [200,403,302]
    q = Queue()
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
    def indexScan(self,url):
        try:
            s = requests.session()
            r = s.get(url)
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
    def indexScancommon(self,url):
        # 如果出现‘gbk' codec can't decode bytes in position 31023: illegal multibyte sequence 
        # fileIndex = open('./dirScan/PHP.txt','r',encoding='gb18030',errors='ignore')
        fileIndex = open('./dirScan/DIR.txt','r')
        for line in fileIndex.readlines():
            # 这里还有一个换行符的问题，一开始怎么也扫不到  发现合成的url结尾有换行
            line=line.strip('\n')
            self.indexScan(url+'/'+line)


def main():
    # 计时开始
    timeStart = time.time()
    #portScanTop100('10.203.87.64')
    #indexScancommon('http://120.24.86.145:8001/')
    # 需要合理的分配线程
    # s = Scan()
    # thread1 = threading.Thread(target=s.threadPortScan,args=('192.168.0.109',1,100,))
    # thread2 = threading.Thread(target=s.threadPortScan,args=('192.168.0.109',100,200,))
    # thread1.start()
    # thread2.start()
    # thread1.join()
    # thread2.join()
    s = Scan()
    s.threadAllPortScan()
    #s.nmapPortScan('192.168.0.109','1-500')
    timeEnd = time.time()
    print('共花费了 %0.2f s' %(timeEnd-timeStart))

if __name__=='__main__':
    main()