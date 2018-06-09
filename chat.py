import socket
import thread
import sys

MAX_CLIENTS = 10
SOCKET_TIMEOUT = 3
DEFAULT_BUFFER = 1024
SERVER_PORT = 8888
SERVER_IP = "10.0.0.27"

class client(object):
	def __init__(self, name, server_ip, server_port):
		self.name = name
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.settimeout(SOCKET_TIMEOUT)
		self.sock.connect((server_ip, server_port))
		self.sock.send(name)
		self.is_running = False
	def get_name(self):
		return self.name
	def client_recv(self):
		temp_string = ""
		while True:
			try:
				data = self.sock.recv(DEFAULT_BUFFER)
			except socket.timeout:
				break
			if not data:
				break
			temp_string += data
		return temp_string
	def send_msg_to_client(self, msg, client_name):
		if '|server|' in msg:
			print 'Invalid message!'
			return
		self.sock.send(client_name + "|" + msg)
		print '[*] {0} bytes sent'.format(len(msg) + len(client_name) + 1)
	def server_command(self, cmd):
		self.sock.send(cmd)
		data = self.client_recv()
		if len(data) > 0:
			if '|' in data:
				inbox_data = data.split("\n")
				for msg in inbox_data:
					if '|' in msg:
						print '[{0}]: {1}'.format(msg.split('|')[0], msg.split('|')[1])
			else:
				print data
		else:
			print "No new messages! Look for new friends :("
	def start_client(self):
		self.is_running = True
		while self.is_running:
			data = raw_input("$ ")
			if '|server|' not in data:
				name = raw_input("To whom: ")
				self.send_msg_to_client(data, name)
			else:
				self.server_command(data)
				
				
class server(object):
	def __init__(self, ip, port):
		self.ip = ip
		self.port = port
		self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server_sock.bind((ip, port))
		self.is_running = False 
		self.inbox = dict()
		self.names = list()
	def get_all_client_names(self):
		return '\n'.join(self.names)
	def add_to_client_inbox(self, from_name, to_name, msg):	
		try:
			self.inbox[to_name].append("{0}|{1}".format(from_name, msg))
		except:
			self.inbox[to_name] = list()
			self.inbox[to_name].append("{0}|{1}".format(from_name, msg))
	def get_inbox_for_client(self, client_name):
		ret = '\n'.join(self.inbox[client_name])
		self.inbox[client_name] = list()
		return ret
	def handle_me(self, conn, name):
		while 1:
			data = conn.recv(DEFAULT_BUFFER)
			if not data:
				self.names.remove(name)
				print '[{0}] disconnected!'.format(name)
				return
			print '[{0}] sent: {1}'.format(name, data)
			if '|server|' in data:
				if 'check_inbox' in data:
					conn.send(self.get_inbox_for_client(name))
				elif 'names' in data:
					print "Doing shit for shas"
					to_send = self.get_all_client_names()
					conn.send(to_send)
				else:
					conn.send("Functions: check_inbox, names")
			else:
				to_client_name = data.split('|')[0]
				msg = data.split('|')[1]
				self.add_to_client_inbox(name, to_client_name, msg)
	def register_client(self, client_sock):
		client_name = client_sock.recv(DEFAULT_BUFFER)
		self.names.append(client_name)
		self.handle_me(client_sock, client_name)
	def start_server(self):
		thread.start_new_thread(listen_for_clients, ())
	def listen_for_clients(self):
		self.is_running = True
		print "Server listening on {0}:{1}".format(self.ip, self.port)
		self.server_sock.listen(MAX_CLIENTS)
		while self.is_running:
			conn, addr = self.server_sock.accept()
			print addr, "is waiting for connection"
			thread.start_new_thread(self.register_client, (conn, ))
		
def main():
	if len(sys.argv) != 2:
		print "Usage: {0} <c/s>".format(sys.argv[0])
		return
	if sys.argv[1] == 'c':
		c = client(raw_input("Enter name:"), raw_input("server_ip:"), int(raw_input("server_port:")))
		c.start_client()
	elif sys.argv[1] == 's':
		s = server(SERVER_IP, SERVER_PORT)
		s.listen_for_clients()
		
if __name__ == '__main__':
	main()