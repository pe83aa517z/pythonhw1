import socket, argparse, struct, random, uuid, time


MAX_BYTES = 65535

def ipToHexNum(ip):
    temp=0
    for i in ip:
        temp = i + temp*0x100
    return temp

def ipTofourNum(ip):
    d = ip%0x100
    c = int((ip%0x10000)/0x100)
    b = int((ip%0x1000000)/0x10000)
    a = int(ip/0x1000000)
        
    return (a,b,c,d)

def getOptions(data, length, isShow):
    code, temp = struct.unpack('B'+ str(length-1)+'s', data)
    if code == 255:
        if isShow:
            print('option ', code, ': end')
        return (255,0,0,0,length-1)
    elif code == 1 or code == 3 or code == 50 or code == 51 or code == 54:
       code, codeLen, value1, value2, value3, value4, temp = struct.unpack('2B4B' + str(length-6)+'s', data)
       if isShow:
           print('option ', code, ': length=', codeLen, 'value=',value1,'.', value2,'.',value3,'.',value4)
       return (code, codeLen, (value1, value2, value3, value4), temp, length-6)
    elif code == 53:
        code, codeLen, messageType, temp = struct.unpack('3B' + str(length-3)+'s', data)
        if isShow:
            print('option ', code, ': length=', codeLen, 'message Type=', messageType)
        return (code, codeLen, messageType, temp, length-3)
    elif code == 55:
        code, codeLen, temp = struct.unpack('BB'+ str(length-2)+'s', data)
        value = ()
        for i in range(codeLen):
            print(codeLen, length-2-codeLen)
            value1, temp = struct.unpack('B'+ str(length-3-i)+'s', temp)
            value = value+(value1,)
        if isShow:
            print('option ', code, ': length=', codeLen, 'Option Codes=', value)
        return (code, codeLen, value, temp, length-2-codeLen)
    else:
        return (0,0,0,0,0)


def printDHCP(data, strType):

    optionsLen = len(data) - struct.calcsize(strType)
    op, htype, hlen, hops, xid, seconds, flags, ciaddr, yiaddr, siaddr, \
    giaddr, chaddr, sname, file, options1, temp  \
    = struct.unpack(strType+str(optionsLen)+'s', data)

    print('op=',hex(op), ', htype=', hex(htype), ', hlen=',hex(hlen), ', hops=', hex(hops),
          '\nxid=', hex(xid), ', seconds=', hex(seconds), ', flags=', hex(flags),
          ', ciaddr=', hex(ciaddr), '\nyiaddr=', hex(yiaddr), ', siaddr=', hex(siaddr),
          ', giaddr=', hex(giaddr), '\nchaddr=', chaddr, '\nsname=', sname,
          '\nfile=', file, '\nMagic cookie=', hex(options1))
    
    
    

def server(port, cPort):
    tempAddress = socket.gethostbyname(socket.gethostname())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((tempAddress, port))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    print('Listening at {}'.format(sock.getsockname()))
    isShow = True
    strType = '!4BI2H4I16s64s128sI'
    
    while True:
#     get discover
 
        data, address = sock.recvfrom(MAX_BYTES)
        tempAddress = socket.gethostbyname(socket.gethostname())
        
        optionsLen = len(data) - struct.calcsize(strType)
        op, htype, hlen, hops, xid, seconds, flags, ciaddr, yiaddr, siaddr, \
        giaddr, chaddr, sname, file, options1, temp \
        = struct.unpack( strType +str(optionsLen)+'s', data)
        
        clientAddress = (0,0,0,0)

        print('discover:')
        printDHCP(data, strType)
       
        while(optionsLen > 0 ):
            code, codeLen, optionsData, temp, optionsLen = getOptions(temp, optionsLen, isShow)
            if code == 50:
                clientAddress = optionsData
             

        
#   offer

        tempAddress2 = [int(i,10) for i in tempAddress.split('.')]
        
        op      = 2
        htype   = 1
        hlen    = 6
        hops    = 0
        flags   = 0
        yiaddr  = ipToHexNum(clientAddress)
        siaddr  = ipToHexNum(tempAddress2)
        giaddr  = 0
        sname   = b'\x00'
        file    = b'\x00'
        options1 = 0x63825363
        options2 = 53, 1, 2
        options3 = 1, 4, 255,255,255,0
        options4 = (3, 4) + tuple([int(i,10) for i in tempAddress.split('.')])
        options5 = 51, 4, 0,1,0,0
        options6 = (54, 4) + tuple([int(i,10) for i in tempAddress.split('.')])
        options7 = 255
   

        offer = struct.pack( strType+'3s6s6s6s6sB',op, htype, hlen, hops, xid, seconds,
                           flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file, options1,
                           bytes(options2), bytes(options3),bytes(options4), bytes(options5), bytes(options6), options7)
        
            
        sock.sendto(offer, ('255.255.255.255', cPort))
        #print(ipToHexNum(clientAddress))
        print('Offer done\nprint request:')
        
#    get request  
        data, address = sock.recvfrom(MAX_BYTES)

        optionsLen = len(data) - struct.calcsize(strType)
        op, htype, hlen, hops, xid, seconds, flags, ciaddr, yiaddr, siaddr, \
        giaddr, chaddr, sname, file, options1,  \
        temp  = struct.unpack('!4BI2H4I16s64s128sI'+str(optionsLen)+'s', data)
        
        printDHCP(data, strType)
        while(optionsLen > 0 ):
            code, codeLen, optionsData, temp, optionsLen = getOptions(temp, optionsLen, isShow)
            
#       pack            
        op      = 2
        htype   = 1
        hlen    = 6
        hops    = 0
        flags   = 0
        yiaddr  = ipToHexNum(clientAddress)
        siaddr  = ipToHexNum(tempAddress2)
        giaddr  = 0
        sname   = b'\x00'
        file    = b'\x00'
        options1 = 0x63825363
        options2 = 53, 1, 5
        options3 = 1, 4, 255,255,255,0
        options4 = (3, 4) + tuple([int(i,10) for i in tempAddress.split('.')])
        options5 = 51, 4, 0,1,0,0
        options6 = (54, 4) + tuple([int(i,10) for i in tempAddress.split('.')])
        options7 = 255
        
        pack = struct.pack(strType+'3s6s6s6s6sB',op, htype, hlen, hops, xid, seconds,
                           flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file, options1,
                           bytes(options2), bytes(options3), bytes(options4), bytes(options5), bytes(options6), options7)
        
        sock.sendto(pack, ('255.255.255.255', cPort))
        print('Pack done')

        

def client(port, cPort):
    tempAddress = socket.gethostbyname(socket.gethostname())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((tempAddress, cPort))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    isShow = True
    print('This is {}'.format(sock.getsockname()))
    
    strType = '!4BI2H4I16s64s128sI'
    localtime = time.time()
    
#        discover

    mac = uuid.getnode().to_bytes(6, 'big')

    op      = 1
    htype   = 1    #???
    hlen    = 6    #???
    hops    = 0
    xid     = random.randint(0, int('0xffffffff', 16))
    seconds = 0
    flags   = 0
    ciaddr  = 0
    yiaddr  = 0
    siaddr  = 0
    giaddr  = 0
    chaddr = mac+b'\x00'*10
    sname   = b'\x00'
    file    = b'\x00'
    options1 = 0x63825363
    options2 = 53, 1, 1
    options3 = (50, 4) + tuple([int(i,10) for i in tempAddress.split('.')])
    options4 = 55, 1, 3
    options5 = 255
    
    discover = struct.pack(strType+'3s6s3sB',op, htype, hlen, hops, xid, seconds,
                           flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file,
                           options1, bytes(options2), bytes(options3),bytes(options4), options5)

    sock.sendto(discover, ('255.255.255.255', port))
    print('Discover done\nprint offer:')
    
#    get offer  
    data, address = sock.recvfrom(MAX_BYTES)

    printDHCP(data, strType)
    
    optionsLen = len(data) - struct.calcsize(strType)
    op, htype, hlen, hops, xid, seconds, flags, ciaddr, yiaddr, siaddr, \
    giaddr, chaddr, sname, file, options1,  \
    temp  = struct.unpack(strType+str(optionsLen)+'s', data)

    printDHCP(data, strType)

    while(optionsLen > 0 ):
            code, codeLen, optionsData, temp, optionsLen = getOptions(temp, optionsLen, isShow)
            
#    request
    localtimeNow = time.time()    
    
    op      = 1
    htype   = 1    #???
    hlen    = 6    #???
    hops    = 0
    seconds = int(localtimeNow - localtime)
    flags   = 0
    ciaddr  = 0  
    giaddr  = 0
    sname   = b'\x00'
    file    = b'\x00'
    options1 = 0x63825363
    options2 = 53, 1, 3

    temp1, temp2, temp3, temp4 = ipTofourNum(yiaddr)
    options3 = 50, 4, temp1, temp2, temp3, temp4
    temp1, temp2, temp3, temp4 = ipTofourNum(siaddr)
    options4 = 54, 4, temp1, temp2, temp3, temp4
    options5 = 255
    
    yiaddr  = 0

    request = struct.pack(strType+'3s6s6sB',op, htype, hlen, hops, xid, seconds,
                           flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file,
                          options1, bytes(options2), bytes(options3), bytes(options4), options5)
    
    sock.sendto(request, ('255.255.255.255', port))
    print('Request done\nprint pack:')
#    get pack
    data, address = sock.recvfrom(MAX_BYTES)
    optionsLen = len(data) - struct.calcsize(strType)
    op, htype, hlen, hops, xid, seconds, flags, ciaddr, yiaddr, siaddr, \
    giaddr, chaddr, sname, file, options1,  \
    temp  = struct.unpack(strType+str(optionsLen)+'s', data)

    printDHCP(data, strType)
    while(optionsLen > 0 ):
            code, codeLen, optionsData, temp, optionsLen = getOptions(temp, optionsLen, isShow)
            
    print('all done')

    
if __name__ == '__main__':
    choices = {'client':client, 'server':server}
    parser = argparse.ArgumentParser(description='Send and receive UDP locally')
    parser.add_argument('role', choices=choices, help='which role to play')
    parser.add_argument('-p', metavar='PORT', type=int, default=67,
                        help='UDP port (default 67)')
    parser.add_argument('-cp', metavar='CPORT', type=int, default=68,
                        help='client UDP port (default 68)')
    args = parser.parse_args()
    function = choices[args.role]

    function(args.p, args.cp)



