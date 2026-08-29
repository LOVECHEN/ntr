import socket,struct,sys
proxy=('cli',1080); target=('echo',9999); msg=b'PINGUDP-trojan-42'
tcp=socket.create_connection(proxy,timeout=6)
tcp.sendall(b'\x05\x01\x00')
if tcp.recv(2)!=b'\x05\x00': print('greet fail'); sys.exit(2)
tcp.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
r=tcp.recv(10)
if r[1]!=0: print('associate fail',r); sys.exit(3)
bnd_ip=socket.inet_ntoa(r[4:8]); bnd_port=struct.unpack('>H',r[8:10])[0]
if bnd_ip in ('0.0.0.0','127.0.0.1'): bnd_ip=proxy[0]
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); udp.settimeout(6)
th=target[0].encode()
pkt=b'\x00\x00\x00\x03'+bytes([len(th)])+th+struct.pack('>H',target[1])+msg
udp.sendto(pkt,(bnd_ip,bnd_port))
data,_=udp.recvfrom(4096)
atyp=data[3]
off=10 if atyp==1 else (22 if atyp==4 else 4+1+data[4]+2)
payload=data[off:]
print('GOT',payload)
sys.exit(0 if payload==msg else 1)
