p2p_delay
=========
自端末からサーバーへのホップ数を調べ、ホップ数に応じて遅延を挿入するプログラム

##目的
p2pサービスでは、通常RTTの短いサーバーへ接続を試みるような作りになっていることが多い。
そんなp2pサービスを使用するときに、接続先をRTTで判断するのではなく、擬似的にホップ数で決めるようにすることを可能にする

##動作環境
Mac

##使い方
./build.sh  
sudo ./p2p_delay <nic>

