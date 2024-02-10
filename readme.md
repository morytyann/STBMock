# 山东联通IPTV机顶盒模拟

## 用途

模拟机顶盒的鉴权流程，自动化获取IPTV节目单，免去每次都需要抓包解析的麻烦

## 使用方法

将`Main.java`中的参数修改为你自己的参数然后运行即可

## 参数获取方法

1. iptvAccount：`adb shell settings get secure iptv_account`
2. iptvPassword(Encrypted)：`adb shell settings get secure iptv_password`
3. stbModel：`adb shell getprop ro.product.model`
4. stbId：`adb shell getprop ro.serialno`
5. stbVersion：`adb shell getprop ro.build.version.incremental`
6. stbIp：机顶盒IP，此处应为IPTV接口的IP
7. stbMac：`adb shell getprop ro.mac`
8. stbInfo：未知/未使用
9. platform：$CTC
10. 服务器IP/Port：抓包，根据step中的url匹配

## 参数说明

1. 针对IP108H_53U5，可通过在任意界面按下`1473692580`打开ADB
2. 针对IP108H_53U5，iptvPassword是密文
3. 针对IP108H_53U5，stbInfo是未使用状态，并未设置此参数
4. 针对IP108H_53U5，platform是`$CTC`，其他设备有可能的值为`$CU`
5. 针对山东联通，服务器IP/Port大概率与默认值一致
6. 不确定加解密参数是否每台机器都相同，其位置在包名为`com.hisense.settings.aidl`的应用中的`com.hisense.settings.common.HWAesUtil`类

## 环境

1. 运营商：山东联通
2. 机顶盒：IP108H_53U5

## 声明

1. 此项目仅限用于学习使用
2. 不保证其他机顶盒/地区/运营商的可用性

## TODO

1. 使用Golang编写
2. 使用配置文件配置参数
