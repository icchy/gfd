# gfd
pseudo Great Firewall Daemon

* [ICTSC8の謎の国](http://icttoracon.net/tech-blog/2017/09/13/%E5%95%8F%E9%A    1%8C%E8%A7%A3%E8%AA%AC-%E8%AC%8E%E3%81%AE%E5%9B%BD/)で出題した問題のソースコ    ードです

## 機能
* PREROUTINGでNATを行うパケットに対して以下のような処理を行う
  * UDP
  ¦ * 宛先がポート53 (DNS) のものに対して，本来のサーバーの代わりにlocalhost    から応答を返す (応答パケットの送信元は本来の宛先に偽装される)
  ¦ * それ以外の通信はDROP
  * TCP
  ¦ * 接続確立後の通信がHTTPまたはDNSであるものを許可
  ¦ * それ以外の通信はDROP

## 使い方
* `vagrant up`
