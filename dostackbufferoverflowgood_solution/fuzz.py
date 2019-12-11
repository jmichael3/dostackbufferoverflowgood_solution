import socket
import sys

def fuzz(ip,port=31337):
	
	buf = "a" *100

	for i in range(1,1000):

		# build a buffer
		buf += ("a" * 100)
		print("[*]Fuzzing {} {} with {} bytes...".format(ip,port,len(buf)+2))

		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.connect((ip,port))
		s.send((buf + "\r\n").encode())
		s.close()

if __name__=="__main__":
	# do magic
	
	usage = "[*]Usage: {} [ip] [port]".format(sys.argv[0])

	if len(sys.argv) == 1:
		print(usage)
		sys.exit()

	ip = sys.argv[1]
	port = sys.argv[2]

	fuzz(str(ip),int(port))