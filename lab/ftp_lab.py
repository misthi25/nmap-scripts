#!/usr/bin/env python3
"""
Simple mock FTP lab server for NSE script testing.
Listens on port 2121 and simulates an unauthenticated environment with passive data transfers.
"""
import socket
import threading

HOST = "127.0.0.1"
PORT = 2121

# Directory listing to simulate in PASV mode
DIRECTORY_LISTING = (
    b"-rw-r--r--   1 ftp      ftp           842 Oct 10 18:30 .env\r\n"
    b"-rw-r--r--   1 ftp      ftp          2602 Oct 10 18:30 id_rsa\r\n"
    b"-rw-r--r--   1 ftp      ftp       1048576 Oct 10 18:30 customers_backup.sql\r\n"
    b"-rw-r--r--   1 ftp      ftp          1420 Oct 10 18:30 config.php.bak\r\n"
    b"-rw-r--r--   1 ftp      ftp           210 Oct 10 18:30 readme.txt\r\n"
    b"drwxr-xr-x   2 ftp      ftp          4096 Oct 10 18:30 public_docs\r\n"
)

def handle_data_connection(data_sock):
    try:
        conn, _ = data_sock.accept()
        conn.sendall(DIRECTORY_LISTING)
        conn.close()
    except Exception:
        pass
    finally:
        data_sock.close()

def handle_client(conn):
    try:
        # Send greeting banner simulating ProFTPD 1.3.5
        conn.sendall(b"220 ProFTPD 1.3.5 Server (Lab Debian) ready.\r\n")
        data_sock = None
        logged_in = False

        while True:
            data = conn.recv(1024)
            if not data:
                break
            cmd_line = data.decode('utf-8', errors='ignore').strip()
            if not cmd_line:
                continue

            parts = cmd_line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd == "USER":
                if arg.lower() == "anonymous":
                    conn.sendall(b"331 Anonymous login ok, send your complete email address as password.\r\n")
                else:
                    conn.sendall(b"530 Only anonymous supported in this lab.\r\n")
            elif cmd == "PASS":
                logged_in = True
                conn.sendall(b"230 Anonymous access granted, restrictions apply.\r\n")
            elif cmd == "SYST":
                conn.sendall(b"215 UNIX Type: L8\r\n")
            elif cmd == "FEAT":
                # Do not offer AUTH TLS to trigger cleartext risk in audit scripts
                conn.sendall(b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n211 End\r\n")
            elif cmd == "PASV":
                # Create a temporary passive data listener
                data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                data_sock.bind((HOST, 0))
                data_sock.listen(1)
                _, pport = data_sock.getsockname()
                p1 = pport // 256
                p2 = pport % 256
                # Intentionally advertise a 192.168.1.50 address to demonstrate internal IP leakage
                conn.sendall(f"227 Entering Passive Mode (192,168,1,50,{p1},{p2}).\r\n".encode())
            elif cmd == "LIST":
                if data_sock:
                    conn.sendall(b"150 Opening ASCII mode data connection for file list\r\n")
                    t = threading.Thread(target=handle_data_connection, args=(data_sock,))
                    t.start()
                    t.join(timeout=3)
                    conn.sendall(b"226 Transfer complete\r\n")
                    data_sock = None
                else:
                    conn.sendall(b"425 Use PASV first.\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"221 Goodbye.\r\n")
                break
            else:
                conn.sendall(b"502 Command not implemented.\r\n")
    except Exception:
        pass
    finally:
        conn.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Mock FTP Lab listening on {HOST}:{PORT}")
    try:
        while True:
            client, _ = server.accept()
            t = threading.Thread(target=handle_client, args=(client,), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Stopping FTP server.")
    finally:
        server.close()

if __name__ == "__main__":
    main()
