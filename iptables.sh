#!/bin/bash
# iptables script for HZ::VPS Service Server
# Tomokazu Hirai <tomokazu.hirai@kddi-web.com>
# 7th Sep 2012
# Inspired from http://qiita.com/items/5c4e21fa284497782f71

### BEGIN INIT INFO
# Provides:          iptables.sh
# Required-Start:    $local_fs $remote_fs $network
# Required-Stop:     $local_fs $remote_fs $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# X-Interactive:     true
# Short-Description: Start/stop iptables
### END INIT INFO

# load LSB functions
. /lib/lsb/init-functions

# set command env
IPTABLES=/sbin/iptables

# set network env

SSH=22
DNS=53
SMTP=25,465,587

ALLOW_HOSTS=(
    "xxx.xxx.xxx.xxx"
    "xxx.xxx.xxx.xxx"
    "xxx.xxx.xxx.xxx"
)

#DENY_HOSTS=(
#    "xxx.xxx.xxx.xxx"
#    "xxx.xxx.xxx.xxx"
#)

#TRUSTED_NET1='124.41.86.100/32'  # Home
#TRUSTED_NET2='59.158.235.8/29'   # office.cpi.ad.jp
#TRUSTED_NET3='122.200.255.65/32' # jam
#TRUSTED_NET4='10.0.0.0/8'

initialize()
{
    iptables -F # テーブル初期化
    iptables -X # チェーンを削除
    iptables -Z # パケットカウンタ・バイトカウンタをクリア
    iptables -P INPUT   ACCEPT
    iptables -P OUTPUT  ACCEPT
    iptables -P FORWARD ACCEPT
}

###########################################################
# ルール適用後の処理
###########################################################
# 下記の内容を /etc/network/if-pre-up.d/iptables_start として保存する
# #!/bin/sh
# /sbin/iptables-restore < /etc/iptables.rules
# exit0
finailize()
{
    iptables-save -c > /etc/iptables.rules
}

###########################################################
# Stealth Scan
###########################################################
stealthscan()
{
    iptables -N STEALTH_SCAN # "STEALTH_SCAN" という名前でチェーンを作る
    iptables -A STEALTH_SCAN -j LOG --log-prefix "stealth_scan_attack: "
    iptables -A STEALTH_SCAN -j DROP

    # ステルススキャンらしきパケットは "STEALTH_SCAN" チェーンへジャンプする
    iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j STEALTH_SCAN
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j STEALTH_SCAN

    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN         -j STEALTH_SCAN
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST         -j STEALTH_SCAN
    iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j STEALTH_SCAN

    iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j STEALTH_SCAN
    iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN     -j STEALTH_SCAN
    iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH     -j STEALTH_SCAN
    iptables -A INPUT -p tcp --tcp-flags ACK,URG URG     -j STEALTH_SCAN
}

###########################################################
# フラグメントパケットによるポートスキャン, DOS 攻撃対策
###########################################################
flagment()
{
    iptables -A INPUT -f -j LOG --log-prefix 'fragment_packet:'
    iptables -A INPUT -f -j DROP
}

###########################################################
# 攻撃対策: SYN Flood Attack
# この対策に加えて Syn Cookie を有効にすべし。
###########################################################
syn_flood_attack()
{
    iptables -N SYN_FLOOD # "SYN_FLOOD" という名前でチェーンを作る
    iptables -A SYN_FLOOD -p tcp --syn \
        -m hashlimit \
        --hashlimit 200/s \
        --hashlimit-burst 3 \
        --hashlimit-htable-expire 300000 \
        --hashlimit-mode srcip \
        --hashlimit-name t_SYN_FLOOD \
        -j RETURN

# 解説
# -m hashlimit                       ホストごとに制限するため limit ではなく hashlimit を利用する
# --hashlimit 200/s                  秒間に200接続を上限にする
# --hashlimit-burst 3                上記の上限を超えた接続が3回連続であれば制限がかかる
# --hashlimit-htable-expire 300000   管理テーブル中のレコードの有効期間（単位：ms
# --hashlimit-mode srcip             送信元アドレスでリクエスト数を管理する
# --hashlimit-name t_SYN_FLOOD       /proc/net/ipt_hashlimit に保存されるハッシュテーブル名
# -j RETURN                          制限以内であれば、親チェーンに戻る

    # 制限を超えたSYNパケットを破棄
    iptables -A SYN_FLOOD -j LOG --log-prefix "syn_flood_attack: "
    iptables -A SYN_FLOOD -j DROP

    # SYNパケットは "SYN_FLOOD" チェーンへジャンプ
    iptables -A INPUT -p tcp --syn -j SYN_FLOOD
}

###########################################################
# 攻撃対策: HTTP DoS/DDoS Attack
###########################################################
http_dos_attack()
{
    iptables -N HTTP_DOS # "HTTP_DOS" という名前でチェーンを作る
    iptables -A HTTP_DOS -p tcp -m multiport --dports $HTTP \
        -m hashlimit \
        --hashlimit 1/s \
        --hashlimit-burst 100 \
        --hashlimit-htable-expire 300000 \
        --hashlimit-mode srcip \
        --hashlimit-name t_HTTP_DOS \
        -j RETURN

# 解説
# -m hashlimit                       ホストごとに制限するため limit ではなく hashlimit を利用する
# --hashlimit 1/s                    秒間1接続を上限とする
# --hashlimit-burst 100              上記の上限を100回連続で超えると制限がかかる
# --hashlimit-htable-expire 300000   管理テーブル中のレコードの有効期間（単位：ms
# --hashlimit-mode srcip             送信元アドレスでリクエスト数を管理する
# --hashlimit-name t_HTTP_DOS        /proc/net/ipt_hashlimit に保存されるハッシュテーブル名
# -j RETURN                          制限以内であれば、親チェーンに戻る

    # 制限を超えた接続を破棄
    iptables -A HTTP_DOS -j LOG --log-prefix "http_dos_attack: "
    iptables -A HTTP_DOS -j DROP

    # HTTPへのパケットは "HTTP_DOS" チェーンへジャンプ
    iptables -A INPUT -p tcp -m multiport --dports $HTTP -j HTTP_DOS
}

###########################################################
# 攻撃対策: SSH Brute Force
# SSHはパスワード認証を利用しているサーバの場合、パスワード総当り攻撃に備える。
# 1分間に5回しか接続トライをできないようにする。
# SSHクライアント側が再接続を繰り返すのを防ぐためDROPではなくREJECTにする。
# SSHサーバがパスワード認証ONの場合、以下をアンコメントアウトする
###########################################################
ssh_brute_force()
{
    iptables -A INPUT -p tcp --syn -m multiport --dports $SSH -m recent --name ssh_attack --set
    iptables -A INPUT -p tcp --syn -m multiport --dports $SSH -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 5 -j LOG --log-prefix "ssh_brute_force: "
    iptables -A INPUT -p tcp --syn -m multiport --dports $SSH -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 5 -j REJECT --reject-with tcp-reset
}

start() {
	# clear all rules
	#$IPTABLES -F
	#$IPTABLES -X
    initialize

	# set default access policy
	$IPTABLES -P INPUT DROP
	$IPTABLES -P OUTPUT ACCEPT
	$IPTABLES -P FORWARD ACCEPT

	# accept all access by icmp 
	$IPTABLES -A INPUT -p icmp -j ACCEPT
	# accept established packet
	$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	# accept all access to loopback I/F
	$IPTABLES -A INPUT -i lo -j ACCEPT

    ###########################################################
    # $DENY_HOSTSからのアクセスは破棄
    ###########################################################
    for host in ${DENY_HOSTS[@]}
    do
        iptables -A INPUT -s $ip -m limit --limit 1/s -j LOG --log-prefix "deny_host: "
        iptables -A INPUT -s $ip -j DROP
    done

    # 攻撃対策
    stealthscan
    flagment
    syn_flood_attack
    #http_dos_attack
    ssh_brute_force

    ##########################################################
    # $ALLOW_HOSTS からのアクセスを許可
    ##########################################################
    for allow_host in ${ALLOW_HOSTS[@]}
    do
        iptables -A INPUT -p tcp -s $allow_host -j ACCEPT # allow_host -> SELF
    done

    ###########################################################
    # 全ホスト(ANY)からの入力許可
    ###########################################################

    #iptables -A INPUT -p icmp -j ACCEPT # ANY -> SELF
    #iptables -A INPUT -p tcp -m multiport --dports $HTTP -j ACCEPT # ANY -> SELF
    #iptables -A INPUT -p tcp -m multiport --dports $SSH -j ACCEPT # ANY -> SEL
    iptables -A INPUT -p tcp -m multiport --dports $DNS -j ACCEPT # ANY -> SELF
    iptables -A INPUT -p udp -m multiport --dports $DNS -j ACCEPT # ANY -> SELF
    #iptables -A INPUT -p tcp -m multiport --sports $SMTP -j ACCEPT # ANY -> SELF

    finailize

	# write to LOG Files with DROP rules
	$IPTABLES -A INPUT -p tcp -j LOG --log-level info --log-prefix '[iptables:drop]'
}

stop() {
    # clear all rules
    $IPTABLES -F
    $IPTABLES -X

    # set default access policy
    $IPTABLES -P INPUT ACCEPT
    $IPTABLES -P OUTPUT ACCEPT
    $IPTABLES -P FORWARD ACCEPT

}

restart() {
        stop
        start
}

case "$1" in
        start)
                start
                ;;
        stop)
                stop
                ;;
        restart)
                stop
                start
                ;;
        *)
                echo $"Usage: $0 {start|stop|restart}"
                exit 1
                ;;
esac

exit 0
