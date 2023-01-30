import socket
import base64
import threading
import os
import sys

HEADER_SIZE = 64
SERVER_IP = "192.168.43.127"
SERVER_PORT = 8080
ADDR = (SERVER_IP, SERVER_PORT)
UDP_ADDR = (SERVER_IP, 9090)
FORMAT = 'utf-8'
DISCONNECT_MSG = '!DISCONNECT'

use_tcp = True

# client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client.connect(ADDR)
client = None

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def clear():  # this function will clear the console
    command = 'cls'  # cls is for windows
    if os.name != 'nt':  # if it isnt windows it will use clear
        command = 'clear'
    os.system(command)
    return 0

def send(msg, cli):
    message = msg.encode(FORMAT)
    message_len = str(len(message)).encode(FORMAT)
    message_len += b' ' * (HEADER_SIZE - len(message_len))
    if use_tcp:
        cli.send(message_len)
        cli.send(message)
    else:
        cli.sendto(message_len, UDP_ADDR)
        cli.sendto(message, UDP_ADDR)

def disconnect(cli):
    send(DISCONNECT_MSG, cli)

def receive(cli):
    res = ''
    body_size = ''
    if not use_tcp:
        body_size, addr = cli.recvfrom(HEADER_SIZE)
        body_size = body_size.decode(FORMAT).strip()
        if body_size:
            body_size = int(body_size)
            res = cli.recvfrom(body_size)[0].decode(FORMAT).strip()
    else:
        body_size = cli.recv(HEADER_SIZE).decode(FORMAT).strip()
        if body_size:
            body_size = int(body_size)
            res = cli.recv(body_size).decode(FORMAT).strip()

    return res.strip().split(';')


def GET(uri, headers, body, cli):
    send("GET " + uri + "\n" + headers + "\n" + body, cli)


def POST(uri, headers, body, cli):
    send("POST " + uri + "\n" + headers + "\n" + body, cli)

def input_uri():
    print("Enter Page URL: ")
    uri = input()
    return uri

def auth(username, password):
    a = ''
    if len(username) and len(password):
        a = "username=" + username + "&password=" + password
    return "auth:" + base64.b64decode(a.encode('ascii')).decode('ascii')

def body(row):
    b = ''
    for key in row.keys():
        b += key + "=" + row[key] + "&"
    if len(b) > 0:
        b = b[:-1]

    return "body:" + b


def run():
    AUTH = ''
    clear()
    print("select UDP or TCP (Default TCP): ")
    global client
    global  use_tcp
    pro = input()
    clear()
    if pro.upper() == "UDP":
        print(f'{bcolors.HEADER}You are select UDP{bcolors.ENDC}')
        use_tcp = False
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        GET('/CONNECT', 'auth:' + AUTH, body({}), client)
    else:
        print(f'{bcolors.HEADER}You are select TCP{bcolors.ENDC}')
        use_tcp = True
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(ADDR)

    print(f'{bcolors.BOLD}{bcolors.WARNING}In the "Enter Page URL:" section, enter the desired page, for example "/login" or "/signup" to login or register.\nEnter "/help" for more information on other pages.{bcolors.ENDC}')
    uri = input_uri()
    GET(uri, 'auth:' + AUTH, body({}), client)
    while uri != DISCONNECT_MSG:
        req_body = dict()
        [status, rb] = receive(client)
        print(rb)
        if uri == '/login' and status == 'OK':
            username = input()
            password = input()
            req_body['username'] = username
            req_body['password'] = password
            POST(uri, 'auth:' + AUTH, body(req_body), client)
            [status, rb] = receive(client)
            if rb.split('&')[0].split('=')[1] == 'NONE':
                print(rb.split('&')[1].split('=')[1])
            else:
                AUTH = rb.split('&')[0].split('=')[1]
                print(rb.split('&')[1].split('=')[1])
        elif uri == '/signup' and status == 'OK':
            username = input()
            password = input()
            req_body['username'] = username
            req_body['password'] = password
            POST(uri, 'auth:' + AUTH, body(req_body), client)
            [status, rb] = receive(client)
            print(rb)
        elif uri == '/inbox' and status == 'OK':
            user = input()
            req_body['user'] = user
            POST(uri, 'auth:' + AUTH, body(req_body), client)
            [status, rb] = receive(client)
            if rb.split('&')[0].split('=')[1] == 'succ':
                print(rb.split('&')[1].split('=')[1])
                message = input()
                uri = f"/message?user={user}"
                POST(uri, 'auth:' + AUTH, body({'message':message}), client)
            else :
                print(rb.split('&')[1].split('=')[1])
        elif uri == '/search' and status == 'OK':
            user = input()
            req_body['user'] = user
            POST(uri, 'auth:' + AUTH, body(req_body), client)
            [status, rb] = receive(client)
            if rb.split('&')[0].split('=')[1] == 'succ':
                print(rb.split('&')[1].split('=')[1])
                uri = f"/message?user={user}"
                message = input()
                while message != 'exit':
                    POST(uri, 'auth:' + AUTH, body({'message': message}), client)
                    [status, rb] = receive(client)
                    clear()
                    print(rb.split('=')[1])
                    message = input()

            else:
                print(rb.split('&')[0].split('=')[1])
        elif uri == '/dashboard' and status == 'OK':
            pass
        elif uri == '/logout' and status == 'OK':
            AUTH = ''
        else:
            pass

        uri = input_uri()
        GET(uri, 'auth:' + AUTH, body({}), client)
        clear()

    disconnect(client)


def main():
    run()


if __name__ == "__main__":
    main()

