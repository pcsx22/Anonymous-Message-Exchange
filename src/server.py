import sys,socket,time,json,thread
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256,SHA
priv_key="""-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCCR9QQ5ch3qhTd9VA4auo5T3s2y4AEboZSbzgeACiNg+l3S0gd\nfVpNyTj4I3+AGNeYIktkc5vbyuXhdc0xKY2sFOphxLy6Ah/n8J0fXgUuxK5Tptxk\nNrrrJYFRDqN4BjqBDENd/Nzjx7s7gZXM4ILs+ZuqvxQwLwp6mUMVCLliFwIDAQAB\nAoGAHI9ghv/IrasEfhAMMQIHLN8mtMFx5AbSvXmSRMlmGnfjk3pWadiUFl9ZdNRb\nXBqWEMzb2D6b2VgmgwGPJQrl+pZcrx4DP26kb3uceLcex6iyjDRJ59+N+pmTd8bU\nD2nmekuK9ZgS5Zek3mP98dNbCFPtrJwPFyUftbAjl3ozsFECQQC1mqHw3dk49nyj\nAKvTstb8SRfxF7Z2fqbFnGgDE/valDOf3LNnlE3vjpH4sAuqfAR3JZhIdiXs3Zb3\nshsLhfI/AkEAt6a/wwH5CfPfOvAjuF+6hmjRCG1GiY1/192dwZksjsI4gQfMMD5G\nOKLezAzDTuwPrPVk81E8+/j8prFuWSjqKQJBAJDCt436OdqXWRjSQyXYbFjkpwoO\n3eqs4KGrIJo7hspg0pn+4p+Rb2KjIia7pkD65NBZDn/MdkTPCjVeKwLPfh8CQQCQ\nVIMmTbmbwcYxOqLH9qvPkDafacnitoq/apLdoHStKSRg+3DUhUyInC9+q5UexFS5\neA3DT5ge6pocoxr3BTmpAkByGMpnYxBFM5hLwXCr6E2UZnVGT23vZVRVeXyQjfrW\n6D62jHKbt7vs6tszavwi8xT655UUQPitrqwRjeQUMBtC\n-----END RSA PRIVATE KEY-----"""


#returns IP of the container
def get_ip():
	return [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
	#return print([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])


def key_query_handler(rsa_keys):
	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sock.bind(('172.17.0.2',5100))
	sock.listen(10)
	while True:
		conn,addr = sock.accept()
		v_addr = conn.recv(256)
		print "Request for %s keys" % v_addr
		conn.send(json.dumps(rsa_keys[v_addr]))
		#conn.close()

class Server:
	def __init__(self):
		print "Server Intialisation.."
		self.addr = get_ip()
		self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.sock.bind((self.addr,5000))
		self.sock.listen(10)
		self.client_list = list() #list to store all the clients with their v_add and ip_add
		self.rsa_keys = {} #v_add -> public key
		self.priv_key=RSA.importKey(priv_key)

	def get_peers(self):
		if len(self.client_list) >= 2:
			return json.dumps([self.client_list[-1],self.client_list[-2]])
		return json.dumps([self.client_list[0],self.client_list[1]])

	def start(self):
		while True:
			print "Waiting for connection..."
			connection,client_addr = self.sock.accept()
			print "%s connected.." % client_addr[0]
			data = json.loads(connection.recv(2048))
			hash = SHA256.new()
			hash.update(str(data['pub_key']) + str(data["v_addr"]))
			signature = self.priv_key.sign(hash.hexdigest(),'')
			self.rsa_keys[data["v_addr"]] = {"pub_key":data["pub_key"],"v_addr":data['v_addr'],"signature":signature}
			if len(self.client_list) >= 2:
				connection.send(self.get_peers())
			elif len(self.client_list) == 1:
				connection.send(json.dumps([self.client_list[0]]))
			self.client_list.append((client_addr[0],data["v_addr"])) #add ip and v_addr
			connection.close()

S=Server()
thread.start_new_thread(key_query_handler,(S.rsa_keys,))
S.start()
