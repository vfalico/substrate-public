#!/usr/bin/env python3
"""Task-owned upstream DNS responder with observed request log."""
import socket,select,json,sys,struct
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('127.0.0.1',0))
t=socket.socket();t.bind(('127.0.0.1',u.getsockname()[1]));t.listen(8)
print(u.getsockname()[1],flush=True)
def read_exact(c,n):
 out=b''
 while len(out)<n:
  chunk=c.recv(n-len(out))
  if not chunk:raise EOFError('short frame')
  out+=chunk
 return out
def response(data):
 if len(data)<12:raise ValueError('short DNS packet')
 answer=bytearray(data);answer[2]|=128;answer[3]|=128
 return bytes(answer)
with open(sys.argv[1],'a',buffering=1) as output:
 while True:
  ready,_,_=select.select([u,t],[],[])
  for s in ready:
   if s is u:
    data,peer=u.recvfrom(512);u.sendto(response(data),peer);protocol='udp'
   else:
    c,_=t.accept();c.settimeout(2)
    with c:
     header=read_exact(c,2);data=read_exact(c,struct.unpack('!H',header)[0]);answer=response(data);c.sendall(struct.pack('!H',len(answer))+answer)
    protocol='tcp'
   output.write(json.dumps({'protocol':protocol,'payload_hex':data.hex(),'probe':b'microvm-native' in data})+'\n')
