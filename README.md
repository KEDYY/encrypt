encrypt
=======

SM4算法规范文档参见[SM4 算法标准Google Doc](https://drive.google.com/file/d/0B0o25hRlUdXcbzdjT0hrYkkwUjg/edit?usp=sharing)
## 支持版本
* Python 2.6 no test
* Python 2.7 Pass
* Python 3.3 no test
* Python 3.4 Pass
* Python 3.5 no test
* Python 3.6 no test

## 依赖
为了兼容Python2 和Python3 使用了 `six` 模块

## 性能
* slowSM4 在i7-4720HQ 使用 testApi.py 显示 170~200tps Python2 和Python3 相差无几


## Python模块有两种
1. Python原生 slowSM4.py 速度很慢
2. C的动态库 pySM4.so 速度极快 需要加载到python执行环境的动态库中

## 版本变更说明

0.1.1 支持Python2 Python3， 加解密支持 CBC模式

## TODO
* 支持常见的Padding增加和去除