#-------------------------------------------------------------------------------
# Py Name:      py3dns.py
# Author:       BikerDroid (@gmail.com -> bikerdroid)
#-------------------------------------------------------------------------------
# Requirements:
# Python 3.x (developed in Python 3.5.1)
# dnslib     #  pip install dnslib
# pythondns3 #  pip install pythondns3
#-------------------------------------------------------------------------------
# ToDo:
# - Make the server fully threaded
# - Read config from file
# - Add logging
#-------------------------------------------------------------------------------
# Usage:
#  nslookup <domain> <server_ip>
# QType = A (ip4):
#  Windows: nslookup -q=A <domain> <server_ip>
#  Linux  : nslookup type=A <domain> <server_ip>
# QType = AAAA (ip6):
#  Windows: nslookup -q=AAAA <domain> <server_ip>
#  Linux  : nslookup type=AAAA <domain> <server_ip>
# Stop the server:
#  nslookup stop.py3dns.now <server_ip>
#-------------------------------------------------------------------------------
import dnslib
import dns.resolver
import datetime

#---------------------------------------------------------------------------------------------------
def make_domain_blacklist():
    return ['facebook.com','twitter.com','snapchat.com']

#---------------------------------------------------------------------------------------------------
def make_ipaddr_blacklist():
    return ['10.10.10.10','2001::1']

#---------------------------------------------------------------------------------------------------
def py3dns(serverip='',serverport=0):
    
    class DNSify(str):
        def __getattr__(self, item):
            return DNSify(item + '.' + self)
    
    def get_lan_ip4(forcelocalhost=False):
        if forcelocalhost: return '127.0.0.1'
        s = dnslib.socket.socket(dnslib.socket.AF_INET,dnslib.socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255',0))
            IP = s.getsockname()[0]
        except:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def is_domain_blacklisted(sqname,domain_blacklist):
        for test_domain in domain_blacklist:
            if test_domain in sqname:
                return True
        return False

    # Init server settings
    killcommand = 'stop.py3dns.now'
    serve_forever = True
    udp_buffer_size = 1024
    server_name = dnslib.socket.getfqdn()
    server_ip = get_lan_ip4()
    if serverip: server_ip = serverip
    reverse_server_ip = '.'.join(reversed(server_ip.split('.')))+'.in-addr.arpa'
    server_port = 53
    if serverport: server_port = int(serverport)
    server_protocol = 'UDP'
    public_dns_resolvers = ['91.239.100.100','89.233.43.71','8.8.8.8','8.8.4.4']

    # Init simple host cache
    host_cache = {}
    host_cache[server_ip] = server_name

    # Init blacklists
    use_blacklists = True
    domain_blacklist = make_domain_blacklist()
    ipaddr_blacklist = make_ipaddr_blacklist()
    rpz_domain = DNSify('getthefuckaway.net')
    rpz_ip4 = '10.20.30.40'
    rpz_ip6 = '10:20:30:40:50:60:70:80'
        
    # Init UDP socket server
    udpsrv = dnslib.socket.socket(dnslib.socket.AF_INET,dnslib.socket.SOCK_DGRAM)
    udpsrv.bind((server_ip,server_port))
    udpsrv.setblocking(False)
    
    # Init external resolvers
    external_resolver = dns.resolver.Resolver()
    external_resolver_cache = dns.resolver.Cache(cleaning_interval=600.0)
    external_resolver.cache = external_resolver_cache
    external_resolver.nameservers = public_dns_resolvers
    external_resolver.retry_servfail = False
    external_resolver.port = 53
    ##external_resolver.timeout = 1.0
    ##external_resolver.lifetime = 2.0

    # Timestamp UTC
    now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
    
    # App Header
    print('+'+('-'*71))
    print('| PY3DNS v/1.0 by BikerDroid')
    print('+'+('-'*71))
    print ('| Server    :',server_name)
    print ('| Address   :',server_ip)
    print ('| Port Used :',server_port)
    print ('| Protocol  :',server_protocol)
    print ('| Recv Size :',udp_buffer_size,'bytes')
    print ('| Solvers   :',str(public_dns_resolvers).strip("[]").replace("'",""))
    print('+'+('-'*71))
    print ('| Stop PY3DNS by sending "nslookup '+killcommand+' '+server_ip+'"')
    print('+'+('-'*71))
    print(now,': Ready to serve...')
    
    # Main Loop
    while serve_forever:

        # Clear vars
        sres = sip4 = sip6 = smx = scname = sns = stxt = sptr = ssoa = sany = hostip = ''

        # Main: Get client request, add hostip and host name to host_cache
        try:
            data, addr = udpsrv.recvfrom(udp_buffer_size)
            hostip = str(addr[0])
            if not hostip in host_cache:
                host_cache[hostip] = dnslib.socket.getfqdn(str(dnslib.socket.gethostbyaddr(hostip)[0]))            
            now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f') # UTC
        except:
            continue
        
        # Client request -> id, qname (domain), qtype (A,AAAA,MX etc)
        request = dnslib.DNSRecord.parse(data)
        qid     = request.header.id
        qname   = request.q.qname
        qtype   = request.q.qtype
        slabel  = str(qname.label)
        sqname  = str(qname)
        sqtype  = str(dnslib.QTYPE[qtype])

        # Rem this line if rpz_domain is to overwrite 
        # blacklisted domains with their real names.
        sdomain = sqname
        
        # Dirty trick to shut down server from commandline:
        # Syntax : nslookup stop.dns.srv <server_ip>
        # Example: nslookup stop.dns.srv 127.0.0.1
        # Must be before external_resolver.query()
        if sqname.rstrip('.') == killcommand:
            serve_forever = False
            continue

        # Dirty Reverse Lookup of local server
        # Allows requesting client to get server_name
        if qtype == dnslib.QTYPE.PTR:
            if sqname.rstrip('.') == reverse_server_ip:
                reply = dnslib.DNSRecord(header=dnslib.DNSHeader(id=qid,qr=1,aa=1,ra=1,rcode=0),q=dnslib.DNSQuestion(sqname,qtype)).reply()
                reply.add_answer(dnslib.RR(sqname,dnslib.QTYPE.PTR,rdata=dnslib.PTR(server_name),ttl=3600))
                udpsrv.sendto(reply.pack(),addr)
                print(now,':',sqname,'|',sqtype,'=',qtype,'|',server_name,'|',hostip,'=',host_cache[hostip])
                continue
        
        # Get DNS record from public_dns_resolvers.
        # This section can be changed to serve from
        # own database, stationary files or similar.
        try:
            if not sqname.rstrip('.') in domain_blacklist:
                external_resolver_result = external_resolver.query(sqname.rstrip('.'),sqtype)
            found = True
        except:
            print(now,'> qtype',sqtype,'('+str(qtype)+') was not found for',sqname)
            external_resolver_result = []
            sres = sip4 = sip6 = ''
            found = False

        if not found:
            # Create DNSRecord Header reply: rcode = 5 (Query Refused). See RFC2136 for rcode's.
            reply = dnslib.DNSRecord(header=dnslib.DNSHeader(id=qid,qr=1,aa=1,ra=1,rcode=5),q=dnslib.DNSQuestion(sdomain,qtype)).reply()
        else:

            # Create DNSRecord Header reply: rcode = 0 (No Error)
            reply = dnslib.DNSRecord(header=dnslib.DNSHeader(id=qid,qr=1,aa=1,ra=1,rcode=0),q=dnslib.DNSQuestion(sdomain,qtype)).reply()
                                
            # Add A record answer for domain and IP
            # Filter blacklisted IP4/6 addresses.
            if qtype == dnslib.QTYPE.A:
                if is_domain_blacklisted(sqname.rstrip('.'),domain_blacklist): # Simple domain blacklist check
                    sres = sip4 = rpz_ip4
                    reply.add_answer(dnslib.RR(sdomain,dnslib.QTYPE.A,rdata=dnslib.A(sip4),ttl=60))
                else:
                    for data in external_resolver_result:
                        sres = sip4 = str(data).strip()
                        if sip4:
                            if sip4 in ipaddr_blacklist: # Simple IP (4+6) blacklist check
                                sres = sip4 = rpz_ip4
                            reply.add_answer(dnslib.RR(sdomain,dnslib.QTYPE.A,rdata=dnslib.A(sip4),ttl=60))
    
            # Add AAAA record answer for domain and IP            
            # Filter blacklisted IP4/6 addresses.
            elif qtype == dnslib.QTYPE.AAAA:
                if is_domain_blacklisted(sqname.rstrip('.'),domain_blacklist): # Simple domain blacklist check
                    sres = sip6 = rpz_ip6
                    reply.add_answer(dnslib.RR(sdomain,dnslib.QTYPE.AAAA,rdata=dnslib.AAAA(sip6),ttl=60))
                else:
                    for data in external_resolver_result:
                        sres = sip6 = str(data).strip()
                        if sip6:
                            if sip6 in ipaddr_blacklist: # Simple IP (4+6) blacklist check
                                sres = sip6 = rpz_ip6
                            reply.add_answer(dnslib.RR(sdomain,dnslib.QTYPE.AAAA,rdata=dnslib.AAAA(sip6),ttl=60))
    
            # Add NS record answer for domain
            elif qtype == dnslib.QTYPE.NS:
                for data in external_resolver_result:
                    sres = sns = str(data).strip()
                    if sns: reply.add_answer(dnslib.RR(sdomain,dnslib.QTYPE.NS,rdata=dnslib.NS(sns),ttl=60))
    
            # Add MX record answer for domain and IP
            elif qtype == dnslib.QTYPE.MX:
                for data in external_resolver_result:
                    sres = smx = str(data).strip()
                    if smx: reply.add_answer(dnslib.RR(sdomain,dnslib.QTYPE.MX,rdata=dnslib.MX(smx),ttl=60))
    
            # Add CNAME record answer for domain
            elif qtype == dnslib.QTYPE.CNAME:
                for data in external_resolver_result:
                    sres = scname = str(data).strip()
                    if scname: reply.add_answer(dnslib.RR(sdomain,dnslib.QTYPE.CNAME,rdata=dnslib.CNAME(scname),ttl=60))
                
            # Add TXT record answer for domain
            elif qtype == dnslib.QTYPE.TXT:
                for data in external_resolver_result:
                    sres = stxt = str(data).strip()
                    if stxt: reply.add_answer(dnslib.RR(sdomain,dnslib.QTYPE.TXT,rdata=dnslib.TXT(stxt),ttl=60))
    
            # Add PTR record answer for domain
            elif qtype == dnslib.QTYPE.PTR:
                for data in external_resolver_result:
                    sres = sptr = str(data).strip()
                    if sptr: reply.add_answer(dnslib.RR(sdomain,dnslib.QTYPE.PTR,rdata=dnslib.PTR(sptr),ttl=60))
            
            # Add ANY record answer for domain
            elif qtype == dnslib.QTYPE.ANY:
                for data in external_resolver_result:
                    sres = sany = str(data).strip()
                    if sany: reply.add_answer(dnslib.RR(sdomain,dnslib.QTYPE.ANY,rdata=dnslib.ANY(sany),ttl=60))
            
            # Add SOA record answer for domain
            elif qtype == dnslib.QTYPE.SOA:
                for data in external_resolver_result:
                    if str(data).strip():
                        soa_data    = str(data).strip().split(' ')
                        soa_mname   = soa_data[0]
                        soa_rname   = soa_data[1]
                        soa_serial  = soa_data[2]
                        soa_refresh = soa_data[3]
                        soa_retry   = soa_data[4]
                        soa_expire  = soa_data[5]
                        soa_minimum = soa_data[6]
                        soa_time    = (int(soa_serial),int(soa_refresh),int(soa_retry),int(soa_expire),int(soa_minimum))
                        sres        = soa_mname+','+soa_rname+','+soa_serial+','+soa_refresh+','+soa_retry+','+soa_expire+','+soa_minimum
                        reply.add_answer(dnslib.RR(sdomain,dnslib.QTYPE.SOA,rdata=dnslib.SOA(soa_mname,soa_rname,soa_time),ttl=60))
            else:
                # Unknown qtype - add CNAME as answer :)
                reply.add_answer(dnslib.RR(qname,dnslib.QTYPE.CNAME,rdata=dnslib.CNAME(server_name),ttl=60))
            
        # Send DNS reply to client address using UDP
        udpsrv.sendto(reply.pack(),addr)
        
        # Show status in console
        print(now,':',sqname,'|',sqtype,'=',qtype,'|',sres,'|',hostip,'=',host_cache[hostip]) #,reply.pack()
            
    # Shutting down    
    print(now,': Shutting down...')
    udpsrv.shutdown(0)
    print(now,': Done.')

#---------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    py3dns()
