"""Pure bounded trace contract/parser. No API, cloud, socket or rule I/O."""
import ipaddress,struct
CID='5f77c5857fa78b0533eb4fddc46cc4a0e9c69369d8e7987ee068b88ec7ba8c2f'
SOURCE_COMMIT='4143d866ab97386411ff1ac4705aaa0e4579bcf6'
IMAGE='sha256:347bcb66318aa1b8ef1e949c6f57e28506e56a1497f2f4ae15b9ab74b8fed4c6'
BOOT='9617762e-19db-4a21-bdee-909dfb31e501';NS='net:[4026531840]'
SOURCE='10.70.0.2';RESOLVER='10.81.0.2';CONNECTION='b79d7eda-fafe-41cf-af2c-4115d4ef32c6'
def identity(snapshot):
 if any(snapshot.get(k)!=v for k,v in {'cid':CID,'image':IMAGE,'source_commit':SOURCE_COMMIT,'boot':BOOT,'namespace':NS}.items()):raise ValueError('exact deployed identity')
def ipv4_tcp(data,local_port):
 # SOCK_DGRAM AF_PACKET supplies IP at offset0 on Ethernet and ARPHRD_NONE.
 if type(local_port)is not int or not 1024<=local_port<=65535:raise ValueError('bounded independently bound local port')
 if len(data)<40 or data[0]>>4!=4:return None
 ihl=(data[0]&15)*4;total=struct.unpack('!H',data[2:4])[0];fragment=struct.unpack('!H',data[6:8])[0]
 if ihl<20 or total>len(data)or total<ihl+20 or data[9]!=6 or fragment&0xbfff:return None
 src=str(ipaddress.IPv4Address(data[12:16]));dst=str(ipaddress.IPv4Address(data[16:20]));sport,dport,seq,ack=struct.unpack('!HHII',data[ihl:ihl+12]);offset=(data[ihl+12]>>4)*4
 if offset<20 or ihl+offset>total:return None
 if (src,dst,sport,dport)==(SOURCE,RESOLVER,local_port,53):direction='request'
 elif (src,dst,sport,dport)==(RESOLVER,SOURCE,53,local_port):direction='reply'
 else:return None
 return {'direction':direction,'source':src,'destination':dst,'source_port':sport,'destination_port':dport,'sequence':seq,'acknowledgement':ack,'flags':data[ihl+13],'ip_length':total,'payload_bytes':total-ihl-offset}
def qualify(before,after,capture):
 identity(before);identity(after)
 if before!=after:return {'stable':False,'causal_acceptance':False,'reason':'identity,route,guard,SA or lease changed'}
 if capture.get('stopped')is not True or any(x.get('drops')!=0 for x in capture.get('sockets',[])):return {'stable':True,'causal_acceptance':False,'reason':'incomplete capture or packet drops'}
 # Prior outgoing XFRM AF_PACKET returned0 despite actual UDP echo. Absence there
 # is never a gateway-drop proof, even if this exact TCP trace is otherwise valid.
 return {'stable':True,'causal_acceptance':False,'reason':'observations require positive SYN/SYNACK and exact same-SA counter/guard correlation; XFRM absence alone is inconclusive'}
