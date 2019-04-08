# 一个简单的python扫描器

### 开始重新组织一下代码 命令结构如下
![命令结构](https://i.loli.net/2019/04/03/5ca484191e4c3.png)

### 代理使用的[IPProxyPool](https://github.com/qiyeboy/IPProxyPool)获取代理ip和端口
> 简易搭建方式
```
docker run -d -t --restart=always --privileged --name Iproxypool -p 8000:8000 jackadam/ipproxypool
```
> 测试代理接口使用的是[搜狐IP地址查询接口](http://pv.sohu.com/cityjson)
> 测试命令：`python webscan.py -u http://www.maotailiaoning.com --proxy`

> 字典读取晚上回去参照假期写的数据批量修改工具

- socket响应时间调整根据路径远近进行时间长短的扫描
- 添加SYN扫描模块


## 这两天就写到这里，有点事，哈哈哈哈哈哈哈