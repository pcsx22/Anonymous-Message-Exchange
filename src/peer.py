import sys,socket,time,fcntl,struct,json,thread
from Crypto.Hash import SHA256,SHA,HMAC
from message import *
from Executor import Executor
from Crypto.PublicKey import RSA
from Crypto import Random
from base64 import b64decode
producer=False
Topic=""
peers = {} #dict that contains ip addr and v_addr
peer_map = {} #dictionary with key 'v_addr' and value 'set of known v_addr'
seen_msg = set()
subscribers = {}
subscribed_topics = set()
rsa_key = None #for public encryption
closed = False
passphrases = {} # topic -> passphrase
server_pub_key="""-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCCR9QQ5ch3qhTd9VA4auo5T3s2\ny4AEboZSbzgeACiNg+l3S0gdfVpNyTj4I3+AGNeYIktkc5vbyuXhdc0xKY2sFOph\nxLy6Ah/n8J0fXgUuxK5TptxkNrrrJYFRDqN4BjqBDENd/Nzjx7s7gZXM4ILs+Zuq\nvxQwLwp6mUMVCLliFwIDAQAB\n-----END PUBLIC KEY-----"""
def get_ip():
	return [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
	#return print([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])

#get physical addr 
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

def get_virtual_addr():
	mac_addr = getHwAddr('eth0')
	hash = SHA256.new()
	hash.update(mac_addr)
	return hash.hexdigest()

class Register:
	def __init__(self,server_addr):
		self.addr = server_addr
		self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.sock.connect(self.addr)

	def fill_peer_dict(self,p_list):
		global peers
		for r in p_list:
			peers[r[0]] = r[1]
			peers[r[1]] = r[0] #for 2-way dictionary


	def register(self):
		self.sock.sendall(json.dumps({"v_addr":v_addr,"pub_key":rsa_key.publickey().exportKey()}))
		data = self.sock.recv(1024)
		if len(data) > 3: 
			data = json.loads(data)
			self.fill_peer_dict(data)
			for peer in peers:
				if len(peer) != 64:
					print peer
					print "Map for peer %s created " % peer
					tmp_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
					tmp_sock.connect((peer,7000))
					tmp_sock.send(v_addr)
					global peer_map
					peer_map[peers[peer]] = set()
					print type(peer_map[peers[peer]])


def check_node(node): #checks entry of given node's v_addr in routing table i.e peer_map
	for peer in peer_map:
		if node in peer_map[peer]:
			print "Entry found in route table..........!!!."
			return peer
	return None

#sends msg to a given node
def send_msg(node,msg,sock):
	sock.sendto(json.dumps(msg.__dict__),(peers[node],6000))

		
def is_neighbour(dest):
	if dest in peers:
		return peers[dest]
	return None

def send_thread(arg):
	executor = arg
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	while True:
		print "Type Command: "
		cmd = raw_input()
		global subscribed_topics
		message_id = executor.parse_cmd(cmd,sock,subscribed_topics,None,False)
		global seen_msg
		message_id is not None and seen_msg.add(message_id)
		continue
		
		#code below is not used. Will take care of it later
		msg = Message(v_addr,node,content)
		seen_msg.add(msg.id)
		if is_neighbour(node) is not None: #if the destination of message is node's neighbour 
			print "Message to be sent to neighbour..."
			send_msg(node,msg,sock)
		else: 
			exist = check_node(node) 
			if exist is None:
				print "Destination node is not known so broadcasting.."
				for peer in peers:
					len(peer) != 64 and sock.sendto(json.dumps(msg.__dict__),(peer,6000))
			else:
				send_msg(exist,msg,sock)

def unhash_passphrase(data):
	print passphrases
	for topic,passphrase in passphrases.items():
		hash = SHA.new()
		hash.update(passphrase + data['src'] + topic)
		if hash.hexdigest() == data['passphrase']:
			return topic,data['src']
	return None,None
 

def get_hmac(key,msg):
	hmac = HMAC.new(key)
	hmac.update(msg)
	return hmac.hexdigest()

#recv thread listens on port 6000 and handles received messages
def recv_thread(arg):
	executor = arg
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	sock.bind((get_ip(),6000))
	print "Recv Thread started.."
	while True:
		data,addr = sock.recvfrom(4096)
		print "Message Received..."
		data = json.loads(data)
		
		#check if same message has already received
		global seen_msg
		if data['id'] in seen_msg:
			print "Duplicate message! id: %s .." % data['id']
			continue

		seen_msg.add(data['id'])	
		
		#populate routing table based on src and dest of the message packet
		global peer_map
		if data['src'] is not None and data['src'] not in peers and addr[0] in peers:
			data['dest'] != v_addr and peer_map[peers[addr[0]]].add(data['src'])
			print "%s added to route table" % data['src']

		#if received a subscribe message and it is also the producer of same topic or it also subscribes same topic
		if data['type'] == "subscribe":
			if data['topic'] is None: #closed system wont have topic field, we try to get topic field from passphrase
				topic,subscriber = unhash_passphrase(data)
				print "unhashing %s...." % topic
				if topic is not None:
					data['topic'] = topic #to reduce the no of line of code, I changed the topic from none to Topic

		 	if (data['topic'] in subscribed_topics ) or (producer and data['topic'] == Topic):
				global subscribers
				if data['topic'] not in subscribers:
					subscribers[data['topic']] = set()
				subscribers[data['topic']].add(data['src'])
				print "New Subscriber: %s " % data['src']
				if producer and data['topic'] ==  Topic:
					continue

		if 'passphrase' in data and data['passphrase'] is not None: #this subsribe msg gets forwarded so reverting the change that I made in the above block
			data['topic'] = None			

  		#WHEN SUBCRIBER RECEIVES "DATA" MESSAGE CHECK IF IT NEEDS TO DISSEMINATE OR NOT
  		if data['type'] == "data" and data['topic'] in subscribed_topics and data['dest'] != v_addr:
  			data['id'] in seen_msg and seen_msg.remove(data['id']) #this is done to avoid the scenario where a node might not receive msg despite subscribing a topic 
 			#print "Forwarding...."
  			#cmd = "publish " + data['topic'] + " " + data['content'] + " " + data['mac'] 
  			#executor.parse_cmd(cmd,sock,None,data['id'],True)
  			#continue

		dest = data['dest']
		if dest == v_addr:
			print "Message FOR ME..."
			cmd = "publish " + data['topic'] + " " + rsa_key.decrypt(b64decode(data['content'])) 
  			executor.parse_cmd(cmd,sock,None,data['id'],False)
  			
			if get_hmac(passphrases[data['topic']],data['content']) == data['mac']:
				print "YEAHHHH MAC MATCH"
			print data
			print "Message in clear format %s " % rsa_key.decrypt(b64decode(data['content']))
		else:
			peer_addr = is_neighbour(dest)
			if peer_addr is not None:
				print "Directing to neighbour %s..." % peer_addr
				sock.sendto(json.dumps(data),(peer_addr,6000))
			else:
				exist = check_node(dest)
				if exist is not None:
					sock.sendto(json.dumps(data),(peers[exist],6000))
				else:
					for peer in peers:
						len(peer) != 64 and sock.sendto(json.dumps(data),(peer,6000))

def connect_new_peer(arg):
	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sock.bind((get_ip(),7000))
	sock.listen(10)
	print "Con thread started..."
	while True:
		con,addr = sock.accept()
		data = con.recvfrom(256)
		global peers,peer_map
		#Filling peers dict with neighbour peer info
		peers[addr[0]] = data[0]
		peers[data[0]] = addr[0]
		peer_map[data[0]] = set()
		print "New node %s connected..." % addr[0]
		time.sleep(2)


if len(sys.argv) > 1 and sys.argv[1] == "prod":
	#for closed form of communication, 4th argument to specify if it is a closed system or not
	if len(sys.argv ) == 5 and sys.argv[3] == "closed":
		global closed,passphrases
		closed = True
		passphrases[sys.argv[2]] = sys.argv[4]
	global producer,Topic
	producer = True
	Topic = sys.argv[2]
	print "Topic of production: %s " % Topic
	subscribers[Topic] = set()

rnd = Random.new().read
print "Generating rsa keys...."
rsa_key = RSA.generate(1024,rnd)
server_public_key = RSA.importKey(server_pub_key)

v_addr = get_virtual_addr()
executor = Executor(v_addr,peers,peer_map,subscribers,passphrases,server_public_key)
R=Register(('172.17.0.2',5000))
R.register()


print "Node virtual address: %s" % v_addr
thread.start_new_thread(send_thread,(executor,))
thread.start_new_thread(recv_thread,(executor,))
thread.start_new_thread(connect_new_peer,(None,))



while True:
	time.sleep(10)