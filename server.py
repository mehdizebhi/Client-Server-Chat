import socket
import threading
import base64
import sys
import time

HEADER_SIZE = 64
IP = "192.168.43.127"
PORT = 8080
ADDR = (IP, PORT)
UDP_ADDR = (IP, 9090)
FORMAT = 'utf-8'
DISCONNECT_MSG = '!DISCONNECT'

users = dict()
inbox = dict()
messages = dict()

server_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_tcp.bind(ADDR)

server_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_udp.bind(UDP_ADDR)

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

def clientHandler(conn, addr, use_tcp):
    print(f'[NEW CONNECTION] {addr} connected!')

    while True:
        req = receive(conn, use_tcp).splitlines()
        print(f"{addr} : {req}")
        if len(req) == 0 or req[0] == DISCONNECT_MSG or req[0].endswith(DISCONNECT_MSG):
            break
        info = req[0].strip().split(' ')
        method = info[0]
        uri = info[1]
        if uri == '/' and isLogin(req):
            send(conn, addr, "OK;"
                       "/set UDP / TCP \n"
                       "/enter: ", use_tcp)
        elif uri.startswith('/message') and isLogin(req):
            from_user = user(req)
            to_user = uri.split('?')[1].split('=')[1]
            pick_user = to_user
            body = req[-1].split(':')[1]
            message = body.split('=')[1]
            if to_user not in messages[from_user].keys():
                messages[from_user][to_user] = []
            if from_user not in messages[to_user].keys():
                messages[to_user][from_user] = []
            if len(message.strip()) == 0:
                send(conn, addr, "OK;" +
                     f"message={messages_to_string(user(req), pick_user)}You are sending message to {pick_user}:", use_tcp)
            else:
                messages[from_user][to_user].append(f"{bcolors.WARNING}me: {message}{bcolors.ENDC}")
                messages[to_user][from_user].append(f"{bcolors.OKGREEN}{from_user}: {message}{bcolors.ENDC}")
                send(conn, addr, "OK;" +
                     f"message={messages_to_string(user(req), pick_user)}You are sending message to {pick_user}:", use_tcp)
            # print(messages)
        elif uri == '/dashboard' and isLogin(req):
            send(conn, addr, "OK;"
                       "1.inbox \n"
                       "2.search user \n"
                       "3.logout \n"
                       "enter number: ", use_tcp)
        elif uri == '/inbox' and isLogin(req):
            if method == 'GET':
                send(conn, addr, "OK;"
                    "pls pick one username :\n" + list_to_str(inbox[user(req)]), use_tcp)
            elif method == 'POST':
                body = req[-1].split(':')[1]
                pick_user = body.split('&')[0].split('=')[1]
                send(conn, addr,"OK;"
                           + str(message[user(req)][pick_user]), use_tcp)
        elif uri == '/search' and isLogin(req):
            if method == 'GET':
                send(conn, addr, "OK;"
                           "Enter Username :", use_tcp)
            elif method == 'POST':
                body = req[-1].split(':')[1]
                pick_user = body.split('&')[0].split('=')[1]
                if pick_user in users.keys() and pick_user != user(req):
                    send(conn, addr,"OK;" + "search=succ&" +
                               f"message={messages_to_string(user(req), pick_user)}You are sending message to {pick_user}:", use_tcp)
                else:
                    send(conn, addr, "OK;"
                               f"message={bcolors.FAIL}user not found.{bcolors.ENDC}", use_tcp)

        elif uri == '/logout' and isLogin(req):
            send(conn, addr, "OK;"
                       f"{bcolors.WARNING}you are logout.{bcolors.ENDC}", use_tcp)
        elif (uri == '/login' or uri == '/signup') and isLogin(req):
            send(conn, addr, "FAIL;"
                       f"{bcolors.FAIL}you are login!{bcolors.ENDC}", use_tcp)
        elif uri == '/signup':
            if method == 'GET':
                send(conn, addr, "OK;"
                           "enter username and password per line to signup", use_tcp)
            elif method == 'POST':
                body = req[-1].split(':')[1]
                username = body.split('&')[0].split('=')[1]
                password = body.split('&')[1].split('=')[1]
                if username not in users.keys():
                    users[username] = password
                    inbox[username] = []
                    messages[username] = dict()
                    send(conn, addr, "OK;"
                               f"{bcolors.OKGREEN}sign up is successful. pls login{bcolors.ENDC}", use_tcp)
                else:
                    send(conn, addr, "OK;"
                               f"{bcolors.FAIL}sign up is not successful. username is unavailable.{bcolors.ENDC}", use_tcp)
        elif uri == '/login':
            if method == 'GET':
                send(conn, addr, "OK;"
                          "enter username and password per line to login", use_tcp)
            elif method == 'POST':
                body = req[-1].split(':')[1]
                username = body.split('&')[0].split('=')[1]
                password = body.split('&')[1].split('=')[1]
                if isUser(username, password):
                    auth = base64.b64encode(body.encode('ascii'))
                    send(conn, addr, "OK;" + "auth=" + auth.decode('ascii') + "&message=" + f"{bcolors.OKCYAN}welcome back " + username + bcolors.ENDC, use_tcp)
                else:
                    send(conn, addr, "OK;" + "auth=NONE" + "&message=" + f"{bcolors.FAIL}username or password is incorrect{bcolors.ENDC}", use_tcp)
        elif uri == '/help':
            send(conn, addr, "OK;"
                       f"{bcolors.OKBLUE}/login\n/signup\n/lougout\n/inbox\n/search{bcolors.ENDC}", use_tcp)
        else:
            send(conn, addr, "OK;"
                             f"{bcolors.OKBLUE}/login\n/signup\n/lougout\n/inbox\n/search{bcolors.ENDC}", use_tcp)

    conn.close()


def udp_clientHandler(addr, req, use_tcp = False):
    req = req.splitlines()
    print(f"{addr} : {req}")
    if len(req) == 0 or req[0] == DISCONNECT_MSG or req[0].endswith(DISCONNECT_MSG):
        return
    info = req[0].strip().split(' ')
    method = info[0]
    uri = info[1]
    conn = None
    pick_user = ''

    if uri == '/CONNECT':
        print(f'[NEW UDP CONNECTION] {addr} connected!')

    elif uri == '/' and isLogin(req):
        send(conn, addr, "OK;"
                         "/set UDP / TCP \n"
                         "/enter: ", use_tcp)
    elif uri.startswith('/message') and isLogin(req):
        from_user = user(req)
        to_user = uri.split('?')[1].split('=')[1]
        pick_user = to_user
        body = req[-1].split(':')[1]
        message = body.split('=')[1]
        if to_user not in messages[from_user].keys():
            messages[from_user][to_user] = []
        if from_user not in messages[to_user].keys():
            messages[to_user][from_user] = []
        if len(message.strip()) == 0:
            send(conn, addr, "OK;" +
                 f"message={messages_to_string(user(req), pick_user)}You are sending message to {pick_user}:", use_tcp)
        else:
            messages[from_user][to_user].append(f"{bcolors.WARNING}me: {message}{bcolors.ENDC}")
            messages[to_user][from_user].append(f"{bcolors.OKGREEN}{from_user}: {message}{bcolors.ENDC}")
            send(conn, addr, "OK;" +
                 f"message={messages_to_string(user(req), pick_user)}You are sending message to {pick_user}:", use_tcp)
        # print(messages)
    elif uri == '/dashboard' and isLogin(req):
        send(conn, addr, "OK;"
                         "1.inbox \n"
                         "2.search user \n"
                         "3.logout \n"
                         "enter number: ", use_tcp)
    elif uri == '/inbox' and isLogin(req):
        if method == 'GET':
            send(conn, addr, "OK;"
                             "pls pick one username :\n" + list_to_str(inbox[user(req)]), use_tcp)
        elif method == 'POST':
            body = req[-1].split(':')[1]
            pick_user = body.split('&')[0].split('=')[1]
            send(conn, addr, "OK;"
                 + str(message[user(req)][pick_user]), use_tcp)
    elif uri == '/search' and isLogin(req):
        if method == 'GET':
            send(conn, addr, "OK;"
                             "Enter Username :", use_tcp)
        elif method == 'POST':
            body = req[-1].split(':')[1]
            pick_user = body.split('&')[0].split('=')[1]
            if pick_user in users.keys() and pick_user != user(req):
                send(conn, addr, "OK;" + "search=succ&" +
                     f"message={messages_to_string(user(req), pick_user)}You are sending message to {pick_user}:",
                     use_tcp)
            else:
                send(conn, addr, "OK;"
                                 f"message={bcolors.FAIL}user not found.{bcolors.ENDC}", use_tcp)

    elif uri == '/logout' and isLogin(req):
        send(conn, addr, "OK;"
                         f"{bcolors.WARNING}you are logout.{bcolors.ENDC}", use_tcp)
    elif (uri == '/login' or uri == '/signup') and isLogin(req):
        send(conn, addr, "FAIL;"
                         f"{bcolors.FAIL}you are login!{bcolors.ENDC}", use_tcp)
    elif uri == '/signup':
        if method == 'GET':
            send(conn, addr, "OK;"
                             "enter username and password per line to signup", use_tcp)
        elif method == 'POST':
            body = req[-1].split(':')[1]
            username = body.split('&')[0].split('=')[1]
            password = body.split('&')[1].split('=')[1]
            if username not in users.keys():
                users[username] = password
                inbox[username] = []
                messages[username] = dict()
                send(conn, addr, "OK;"
                                 f"{bcolors.OKGREEN}sign up is successful. pls login{bcolors.ENDC}", use_tcp)
            else:
                send(conn, addr, "OK;"
                                 f"{bcolors.FAIL}sign up is not successful. username is unavailable.{bcolors.ENDC}",
                     use_tcp)
    elif uri == '/login':
        if method == 'GET':
            send(conn, addr, "OK;"
                             "enter username and password per line to login", use_tcp)
        elif method == 'POST':
            body = req[-1].split(':')[1]
            username = body.split('&')[0].split('=')[1]
            password = body.split('&')[1].split('=')[1]
            if isUser(username, password):
                auth = base64.b64encode(body.encode('ascii'))
                send(conn, addr, "OK;" + "auth=" + auth.decode(
                    'ascii') + "&message=" + f"{bcolors.OKCYAN}welcome back " + username + bcolors.ENDC, use_tcp)
            else:
                send(conn, addr,
                     "OK;" + "auth=NONE" + "&message=" + f"{bcolors.FAIL}username or password is incorrect{bcolors.ENDC}",
                     use_tcp)
    elif uri == '/help':
        send(conn, addr, "OK;"
                         f"{bcolors.OKBLUE}/login\n/signup\n/lougout\n/inbox\n/search{bcolors.ENDC}", use_tcp)
    else:
        send(conn, addr, "OK;"
                         f"{bcolors.OKBLUE}/login\n/signup\n/lougout\n/inbox\n/search{bcolors.ENDC}", use_tcp)


def messages_to_string(f, t):
    print(f"ffffffffff {f}, ttttttttttt: {t}")
    if t not in messages[f].keys():
        messages[f][t] = []
    if f not in messages[t].keys():
        messages[t][f] = []

    m = messages[f][t]
    str = ''
    for i in m:
        str += i + '\n'

    return str



def isUser(username, password):
    if username in users.keys() and users[username] == password:
        return True

    return False

def list_to_str(list):
    str = ''
    for i in list:
        str += i + "\n"

    return str

def send(conn, addr, msg, use_tcp):
    message = msg.encode(FORMAT)
    message_len = str(len(message)).encode(FORMAT)
    message_len += b' ' * (HEADER_SIZE - len(message_len))
    if not use_tcp or conn == None:
        server_udp.sendto(message_len, addr)
        server_udp.sendto(message, addr)
    else:
        conn.send(message_len)
        conn.send(message)

def receive(conn, use_tcp):
    req = ''
    body_size = ''
    if not use_tcp or conn == None:
        body_size, addr = server_udp.recvfrom(HEADER_SIZE)
        body_size = body_size.decode(FORMAT).strip()
        if body_size:
            body_size = int(body_size)
            req = server_udp.recvfrom(body_size)[0].decode(FORMAT).strip()
            return req, addr
    else:
        body_size = conn.recv(HEADER_SIZE).decode(FORMAT).strip()
        if body_size:
            body_size = int(body_size)
            req = conn.recv(body_size).decode(FORMAT).strip()

    return req


def isLogin(req):
    if len(req) < 2 or len(req[1].split(':')[1]) == 0:
        return False
    else:
        s = req[1].split(':')[1]
        auth = base64.b64decode(s + '=' * (-len(s) % 4))
        auth = auth.decode('ascii')
        username = auth.split('&')[0].split('=')[1]
        password = auth.split('&')[1].split('=')[1]
        if username in users.keys() and users[username] == password:
            return True

    return False

def user(req):
    if isLogin(req):
        s = req[1].split(':')[1]
        auth = base64.b64decode(s + '=' * (-len(s) % 4))
        auth = auth.decode('ascii')
        username = auth.split('&')[0].split('=')[1]
        return username

    return None


def start():
    print(f'[STARTING] tcp server is starting... {ADDR}')
    server_tcp.listen()
    while True:
        conn, addr = server_tcp.accept()
        thread = threading.Thread(target=clientHandler, args=(conn, addr, True))
        thread.start()

def start_udp():
    print(f'[STARTING] udp server is starting... {UDP_ADDR}')
    while True:
        data, addr = receive(None, False)
        udp_clientHandler(addr, data)
        # if data.decode(FORMAT).splitlines()[0].endswith('/CONNECT'):
        #     thread = threading.Thread(target=clientHandler, args=(None, addr, False))
        #     thread.start()
        #     thread.join()



def main():
    server_tcp_thread = threading.Thread(target=start, args=())
    server_tcp_thread.start()

    server_udp_thread = threading.Thread(target=start_udp, args=())
    server_udp_thread.start()


if __name__ == "__main__":
    main()



