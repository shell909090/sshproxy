# sshproxy

proxy server for ssh

# feature

* 正常连接，支持大部分特性
* hostkey验证
* 过程记录
* scp支持和识别
* local port mapping/dymanic port mapping支持和识别
* 内容压缩
* server的穷举防御
* ssh proxy host跳板连接
* 用户/主机/账户管理
* ACL模型权限管理

# TODO

* 终端浏览记录
* web浏览记录
* group介于时间内生效
* 权限缓存和清除
* show replay
* 反向索引
* 敏感字断开
* remote port mapping，不知为何无法成功
* x11 forward，支持，但不识别内容，只有MAGIC
* authentication agent，支持，但不识别内容
* ssh based vpn
* web版本的密码复杂度限定和穷举防御
