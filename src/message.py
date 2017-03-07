from Crypto.Hash import SHA256,SHA
import sys,socket,time,fcntl,struct,random


def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

def get_msg_id():
	hash = SHA.new()
	hash.update(getHwAddr('eth0') + str(time.time()) + str(random.randint(1,100)))
	return hash.hexdigest()

class Message:
	def __init__(self,src,dest,content):
		self.id = get_msg_id() 
		self.src = src
		self.dest = dest
		self.content = content

class SubscribeMessage(Message):
	
	def __init__(self,src,dest,topic,passphrase):
		self.type = "subscribe"
		self.topic = topic if passphrase is None else None
		self.passphrase = None if passphrase is None else self.get_passphrase(passphrase,topic,src) #hash of v_addr,topic and password
		Message.__init__(self,src,dest,None)

	def get_passphrase(self,passphrase,topic,src):
		hash = SHA.new()
		hash.update(passphrase + src + topic)
		return hash.hexdigest()

class DataMessage(Message):

	def __init__(self,src,dest,topic,content,msg_id,mac):
		Message.__init__(self,src,dest,content)
		if msg_id is not None:
			self.id = msg_id
		self.topic = topic
		self.type = "data"
		self.mac = mac
		