iptables for Ubuntu
========

iptables for Ubuntu OS. Imspired from "俺史上最強の iptables をさらす"

http://qiita.com/items/5c4e21fa284497782f71

How to use
----

clone it, edit, and exec.

    % git clone git://github.com/jedipunkz/iptables.git
    % vim iptables/iptables.sh
    % sudo ./iptables/iptables.sh start

especially, you should edit ${ALLOW_HOSTS} 

set init script

    # cat > /etc/network/if-pre-up.d/iptables_start << EOF
    #!/bin/sh
    /sbin/iptables-restore < /etc/iptables.rules
    exit0
    EOF
    # chmod +x /etc/network/if-pre-up.d/iptables_start

