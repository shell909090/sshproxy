# sshproxy

proxy server for ssh

# feature

* 正常连接，支持大部分特性
* hostkey验证
* 过程记录
* scp支持和识别
* local port mapping支持和识别
* 内容压缩
* ssh proxy host跳板连接

# TODO

* 精细权限控制模型
* 敏感字断开
* show replay
* remote port mapping，不知为何无法成功
* x11 forward，支持，但不识别内容，只有MAGIC
* authentication agent，支持，但不识别内容
* ssh based vpn
