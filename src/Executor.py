from message import *
import json,socket
from Crypto.Hash import SHA256,SHA,HMAC
from Crypto.PublicKey import RSA
from base64 import b64encode

server_pub_key="""-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCCR9QQ5ch3qhTd9VA4auo5T3s2\ny4AEboZSbzgeACiNg+l3S0gdfVpNyTj4I3+AGNeYIktkc5vbyuXhdc0xKY2sFOph\nxLy6Ah/n8J0fXgUuxK5TptxkNrrrJYFRDqN4BjqBDENd/Nzjx7s7gZXM4ILs+Zuq\nvxQwLwp6mUMVCLliFwIDAQAB\n-----END PUBLIC KEY-----"""


def check_node(node,peer_map): #checks entry of given node's v_addr in routing table i.e peer_map
	for peer in peer_map:
		if node in peer_map[peer]:
			print "Entry found in route table..........!!!."
			return peer
	return None

#checks if dest is neighbour
def is_neighbour(dest,peers):
	if dest in peers:
		return peers[dest]
	return None

def get_rsa_keys(v_addr,server_public_key):
	hash = SHA256.new()
	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sock.connect(('172.17.0.2',5100))
	sock.sendall(v_addr)
	data = sock.recv(1024)
	data = json.loads(data)
	data['signature'] = (data['signature'][0],)
	hash.update(str(data['pub_key']) + str(data['v_addr']))
	if server_public_key.verify(hash.hexdigest(),data['signature']):
		pub_key = RSA.importKey(str(data['pub_key']))
		return pub_key
	
	return None		 

def get_hmac(key,msg):
	hmac = HMAC.new(key)
	hmac.update(msg)
	return hmac.hexdigest()

#returns no of peers to be selected for message dissemination(gossip protocol) 
def get_gossip_peer(subscribers): 
	counter = len(subscribers)
	if counter >= 4:
		counter = 3
	
	gossip_peers = []
	for peer in subscribers:
		gossip_peers.append(peer)
		counter -= 1
		if counter == 0:
			break
	
	return gossip_peers

class Executor:
	def __init__(self,v_addr,peers,peer_map,subscribers,passphrases,server_public_key):
		self.v_addr = v_addr
		self.peers = peers
		self.subscribers = subscribers
		self.peer_map = peer_map
		self.passphrases = passphrases
		self.server_public_key = server_public_key
	def parse_cmd(self,command,sock,subscribed_topics,msg_id,forward_msg): #msg_id is given to reuse the message id when non-sub node has to disseminate msg
		cmd_arr = command.split(' ')
		if cmd_arr[0] == "subscribe":
			print "Subscribe Message...."
			subscribed_topics.add(cmd_arr[1])
			if len(cmd_arr) == 3: #for closed connection
				self.passphrases[cmd_arr[1]] = cmd_arr[2]
				msg = SubscribeMessage(self.v_addr,None,cmd_arr[1],cmd_arr[2])
			else:
				msg = SubscribeMessage(self.v_addr,None,cmd_arr[1],None)
			print msg.__dict__
			for v_addr,ip_addr in self.peers.items():
				 len(v_addr) == 64 and sock.sendto(json.dumps(msg.__dict__),(ip_addr,6000))
			return msg.id
		elif cmd_arr[0] == "publish":
			topic,content = cmd_arr[1],cmd_arr[2]
			if topic not in self.subscribers:
				return None
			gossip_peers = get_gossip_peer(self.subscribers[topic])
			for peer in gossip_peers:
				print "sending to peer %s" % peer
				msg = DataMessage(None,peer,topic,content,msg_id,None)
				msg_id = msg.id
				if not forward_msg:
					pub_key = get_rsa_keys(peer,self.server_public_key)
					if pub_key is not None:
						msg.content = b64encode(pub_key.encrypt(str(msg.content),"")[0])
						msg.mac = get_hmac(self.passphrases[topic],msg.content)
					else:
						raise Exception("The public key is not valid")
				else:
					msg.mac = cmd_arr[3]
				#print "sending data message to %s " % peer
				peer_addr = is_neighbour(peer,self.peers)
				if peer_addr is not None:
					print "Directing to neighbour %s..." % peer_addr
					sock.sendto(json.dumps(msg.__dict__),(peer_addr,6000))
				else:
					exist = check_node(peer,self.peer_map)
					if exist is not None:
						print "Entry found in route table"
						sock.sendto(json.dumps(msg.__dict__),(self.peers[exist],6000))
					else:
						print "Entry not found in the route table so broadcasting..."
						for p in self.peers:
							len(p) != 64 and sock.sendto(json.dumps(msg),(p,6000))
			return msg.id
		else: 
			return None 		
