# EasierConnect
This is a simple folk.
警告：目前本项目Feb 8, 2023之后的commit 都无法工作，等有时间再修复吧   
目前可以使用 Mythologyli 大佬的[项目](https://github.com/Mythologyli/zju-connect)

TODO list:
> 1. Parse dns config from rconf and use it as Default dns server (√)
> 2. ignore Exception domains (from conf) when using intranet dns server 
> 3. UDP protocol support  (√)
> 4. makes GUI compile separately and makes the main function as core Module  (√)
------------------------------------------------------------------------------------------------
`Dns Server` 因为没有相应环境，所以没办法测试，希望有好心人能反馈一下
其中 conf 里面是有 `Exception` 规则的
目前看来规则貌似主要集中在 `localhost` 之类的
