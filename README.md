# ZC
AbleCloud 协议适配层
##1.AC_PCT_v1.0.00_20150811
AbleCloud云端协议适配层
##2.AC_PCT_v1.0.01_20150827
2.1支持设备解绑功能

2.2移除端口配置
##3.AC_PCT_v1.0.02_20150908
区分上报消息和响应消息以解决频繁上报发送empty消息导致云端与wifi断链的问题
##4.AC_PCT_v1.0.03_20150910
解决庆科wifi模块堆栈调用太深指针参数对应内存无法修改问题
##5.AC_PCT_v1.0.04_20150914
1.ZOTA结束消息调用重启接口修改为异步调用

2.将发送的buffer由2修改为3（MSG_QUEUE_MAXLEN）
##5.AC_PCT_v1.0.04_20150919
解决设备直连问题
##6.AC_PCT_v1.0.05_20151014
1.移除设备开机第一次发解绑消息
2.将云端域名长度由20字节扩展到24字节以支持海外域名
##7.AC_PCT_v1.0.06_20151103
 局域网发现响应消息增加domain信息
##8.AC_PCT_v1.0.07_20151114
增加解绑和配网下允许发广播的绑定信息，绑定成功之后停止
##9.AC_PCT_v1.0.08_20151130
1.修改flash校验方式为crc校验

2.读取flash接口修改在ZC_ConfigInitPara中调用

3.增加pfunReadFlash回调函数

4.增加ZC_ConfigReset函数重置wifi密码

5.修复ZOTA END之后REBOOT时间笔误
##10.AC_PCT_v1.0.09_20151217
1.移除了串口重传

2.设备解绑之后，不能直接绑定，必须通过配网绑定设备。

3.修复OTA消息回复EMPTY的问题

##11.AC_PCT_v1.0.10_20160224
1.修复Android消息回复不回EMPTY消息的问题

## 12.AC_PCT_v1.0.11_20160419

支持变长设备ID

## 13.AC_PCT_v1.0.12_20160423

支持三种局域网加密通信方式

## 14.AC_PCT_v1.0.13_20160517

1.移除mcu升级wifi部分代码

2.修复云端给设备下发重置接入点不生效的问题

3.增加云端接入点宏

## 15.AC_PCT_v1.0.14_20160525

1.支持aes认证方式

2.移除empty响应包



