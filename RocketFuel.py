import telnetlib
import os
import time
import subprocess
import re
import subnet_soup
from netaddr import IPNetwork, IPAddress
import thread
from mpl_toolkits.basemap import Basemap
import matplotlib.pyplot as plt
import pylab as p
import networkx
import shelve
from geoip import geolite2
from alias_resolution import *

# the main module of the program, call for it to run Rocketfuel. 
# It contains the functions for dependent prefix, exit, ISP path detection 
# and the functions for printing the ISP graph and geomap. 

#[Stage One] 
#To get the BGP table, run routeview

#[Stage Two - Egress Detection]
#send traceroute probe to each of the dependent prefixes 
#In order to identify the ISP exit servers.

routeViewList = [
#                  [b"route-views.routeviews.org",b"rviews"],
                  ###["route-views2.routeviews.org"],
#                  [b"route-views3.routeviews.org"],
#                  [b"route-views4.routeviews.org"],
                  ###["route-views6.routeviews.org"],
                  ###["route-views.eqix.routeviews.org"],
#                  [b"route-views.isc.routeviews.org"],
#                  [b"route-views.kixp.routeviews.org"],
#                  [b"route-views.linx.routeviews.org"],                  
                  ###["route-views.nwax.routeviews.org"],
                  [b"route-views.wide.routeviews.org"],
#                  [b"route-views.sydney.routeviews.org"],
                  [b"route-views.saopaulo.routeviews.org"],
                  [b"route-views.telxatl.routeviews.org"],
                  ###["bgpmon.routeviews.org"],
                  ###SSH username&password[,"archive.routeviews.org"],
                  ###SSH username&password[,"bgplay.routeviews.org"],
                  ###[,"zebra.routeviews.org"]
                  ]

#[Stage Three - Path Mapping]
#Use external servers to send traceroute requests to each of the ISP exits, 
#and record each path.

#Traceroute servers provided by traceroute.org
#Server classification provided by http://www.he.net/
#ASN:traceRouteServer,username,password
traceRouteServerList = {
#                        '553':['route-server.belwue.de'],
                        ###'812':'route-server.rogers.com',
                        ###'852':'route-views.on.bb.telus.com',
                        ###'852':'route-views.ab.bb.telus.com',
#                        '1838':['route-server.cerf.net'],
                        ###'2018':'route-server.tenet.ac.za',
#                        '3257':['route-server.ip.tiscali.net','login:','public','Password:','public'], #login: public / Password:public
                        ###'3292':'route-server.ip.tdc.net',
#                        '3303':['route-server.ip-plus.net'],
                        ##slow'3549':'route-server.gblx.net',
                        '3549':['route-server.eu.gblx.net'],
                        ###'3561':'route-server.savvis.net',
#                        '3741':['public-route-server.is.co.za','Username:','rviews','Password:','rviews'], #rviews=username&password
#                        '4323':['route-server.twtelecom.net','login:','rviews','Password:','rviews123'], #username=rviews password=rviews123
                        ###'5388':['route-server.as5388.net'],
#                        '5413':['route-server.as5413.net'],
                        ###'5511':['route-server.opentransit.net'],
                        ###'5713':['tpr-route-server.saix.net'],
                        ###'5769':['route-server.videotron.net'],
                        ###'6539':['route-server-east.gt.ca'],
                        ###'6539':['route-server-west.gt.ca'],
                        ###'6648':['route-server.skyinet.net'],
#                        '6667':['route-server.as6667.net','login:','rviews','Password:','Rviews'],
#                        '6730':['routeserver.sunrise.ch'],
                        ###'6746':['route-server.astralnet.ro'],
                        ###'6939':'route-server.he.net',
                        '7018':['route-server.ip.att.net','login:','rviews','Password:','rviews'],
                        ###'7132':['route-server.sbcglobal.net'],
                        '7474':['route-views.optus.net.au'],
                        ###'7911':['route-server.wcg.net'],
#                        '7922':['route-server.newyork.ny.ibone.comcast.net','Username:','rviews'],
                        ###'8218':['route-server.as8218.eu'],
                        ###'8220':['route-server.colt.net'],
#                        '8301':['route-server.gibtelecom.net'],
                        ###'9328':['route-server-au.exodus.net'],
                        ###'9670':['route-server.mix.com.ph'],
#                        '11260':['route-server.eastlink.ca'],
                        ###'12312':['route-view.ip.nacamar.net'],
                        ###'13645':['route-server.host.net','-','routes'],
#                        '15290':['route-server.east.allstream.com','Username:','rserv'],
                        ###'15290':['route-server.west.allstream.com','rserv'],
                        ###'15837':['route-server.rhein-main-saar.net'],
                        ###'21229':['bgp-view.tvnetwork.hu'],
                        ###'23005':['route-server.nevadanap.com','-','rviews'],
                        ###'28747':['route-server.as28747.net'],
                        ###'30071':['route-server.occaid.net'],
                        ###'30890':['route-server.ipilink.net'],
                        ###'35908':['route-server.vpls.net'],
                        ###'35975':['route-server.centauricom.com:2605'],
#                        '3582':['route-views.oregon-ix.net','Username:','rviews']
                         }
RV_SEM = 0
EXITS_SEM = 0
TRS_SEM = 0
LU_SEM = 0

class EgressDiscovery: # search dependent prefix from BGP table
    @staticmethod
    def findAllDependentPrefixes(sss,myASN):
        print('START find all dependent Prefixes')
        global RV_SEM
        for rv in routeViewList:
            print(rv[0])
            print(os.path.isfile(rv[0] +'-'+str(myASN)+ b"-allDependentPrefixes.txt"))
            if os.path.isfile(rv[0] +'-'+str(myASN)+ b"-allDependentPrefixes.txt"): # check () is file or not
                print(rv[0])
                RV_SEM=RV_SEM+1
                print('EgreeDiscovery RV_SEM : ', RV_SEM)
                continue  #os.remove(x[0] + b"-allDependentPrefixes.txt") # only skip this stage in the 'for' loop.
            bgpTall=open(rv[0] +'-'+str(myASN)+ b"-allDependentPrefixes.txt","wb",0)
            print('BGPTall', bgpTall)
            try:
                print('telnetting now... toward ', rv)
                tn=telnetlib.Telnet(rv[0],0,timeout=12000)
            except:
                bgpTall.close()
                continue
            if len(rv)>1:
                tn.read_until(b"Username:")
                tn.write(rv[1] + b"\r\n")
                print("****username(rviews) was entered****")
            #print(len(rv))
#            tn.write("terminal length 0\r\n".encode('ascii'))
            tn.write("terminal length 0".encode('ascii') + "\r\n".encode('ascii'))
#            tn.write("show bgp ipv4 unicast\r\n".encode('ascii'))
            tn.write("show bgp ipv4 unicast".encode('ascii') + "\r\n".encode('ascii'))
            tn.read_until(b"Network")
            tn.read_until(b"\n")
            line=tn.read_until(b"\n") # line is result of BGP unicast of routeviews.
            parts=line.split()
            print('telnet result toward ',rv,' : ',  parts)

            #need to do for each output line(
            #need to find last line of the BGP table for the condition)
            while not ((rv[0] in line) or ('\r\n' == line)): 
                if((len(parts)>2) and (b"." in parts[2])):   #do for each network destination
                    networkDestination = parts[1]            #save network prefix
                    while True:
                        if(str(myASN).encode('ascii') in parts): #ISP's ASN in route
                            line=tn.read_until(b"\n") # read end line
                            parts = line.split()
                            if(((len(parts)>2) and (b"." in parts[2])) or (rv[0] in line) or ('\r\n' == line)):
                                bgpTall.write(networkDestination + "\n".encode('ascii'))
                                print "Independent Prefix added:"+ networkDestination +"\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!findAllDependentPrefixes Function!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                                break;
                        else:
                            line=tn.read_until(b"\n")
                            parts = line.split()
                            while not (((len(parts)>2) and (b"." in parts[2])) or (rv[0] in line) or ('\r\n' == line)):
                                line=tn.read_until(b"\n")
                                parts = line.split()
                            break;
            bgpTall.close()
            RV_SEM=RE_SEM+1
            tn.close

class TasklistGeneration:
    def findISPexits(ss,sss,myASN): 
        global RV_SEM
        global EXIT_SEM
        prefixesFile='as'+str(myASN)+'htm'
        prefixes=subnet_soup.getprefixes(prefixesFile)
        for rv in routeViewList:
            while RV_SEM <= 0:
                time.sleep(30)
            if RV_SEM > 0:
                RV_SEM = RV_SEM -1
                if os.path.isfile(rv[0]+'-'+str(myASN)+"-allDependentPrefixes.txt".encode('ascii')):
                    dependentPrefixes=open(rv[0] +'-'+str(myASN)+ "-allDependentPrefixes.txt".encode('ascii'),"rb",0)
                else:
                    print "This file doesn't exsit: " + rv[0] +'-'+str(myASN)+ "-allDependentPrefixes.txt".encode('ascii')
                    continue
                print(rv[0])
                print(os.path.isfile(rv[0] + '-'+str(myASN)+"-exits.txt".encode('ascii')))
                if os.path.isfile(rv[0] + '-'+str(myASN)+"-exits.txt".encode('ascii')):
                    print('now.. increased by 1 of EXITS_SEM : ', EXITS_SEM+1) 
                    EXITS_SEM=EXITS_SEM+1
                    dependentPrefixes.close()
                    continue   #os.remove(x[0] + "-exits.txt".encode('ascii'))
                ispExits=open(rv[0] +'-'+str(myASN)+ "-exits.txt".encode('ascii'),"wb",0)
                print('ispExits : ', ispExits)                     
                for line in dependentPrefixes:
                    dependentPrefix=(str(line).split('/'))[0] # split before /
                    print "Searching ISP exit to dependentPrefix: " + dependentPrefix
                    print "tracerouting.... to the depedentPrefix"
                    proc = subprocess.Popen(["traceroute", dependentPrefix], stdout=subprocess.PIPE, shell=False)
                    (out, err) = proc.communicate()
                    hops=out.split('\n')
                    print('result : ', hops)
                    print('len(hops) : ', len(hops))
                    ipInISP=0
#                    for i in range(0,31):
                    for i in range(len(hops)):
                        if len(hops) >=i:
#                                print"line by line result of hops :"+hops[i] # hop is result of traceroute toward dependentprefix
                                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', hops[i] )
                                isIpInISP=0
                                if ip!=[]:
                                    for prefix in myPrefixes:
                                        subnet= str(prefix[0]) + "/" + str(prefix[1])
                                        #print('subnet is : ', subnet)
                                        #print('IPAddress(ip[0]) : ', IPAddress(ip[0]))
                                        if IPAddress(ip[0]) in IPNetwork(subnet): # if each result line of traceroute is same as BGP He.net prefix
                                            isIpInISP=1
                                            ipInISP=ip[0] # put the traceroute result into the ipInISP(=ISP exit IP)
                                            print('ISP exit IP(ipInISP) : ',ipINISP) # this is eventually ISP exit  IP.
                                            break
                                    if (ipInISP!=0 and isIpInISP==0):
                                        ispExits.write(ipInISP + "\n")
                                        print "Exit added: " + ipInISP + "\n@@@@@@@@@@@@@@@@@@@@@@@@findISPexits Function@@@@@@@@@@@@@@@@@@@@@@@@"
                                        break
                                if (i==len(hops) and ipInISP!=0):
                                    ispExits.write(ipInISP + "\n")
                                    print "Exit added : " + ipInISP + "\n@@@@@@@@@@@@@@@@@@@@@@@@@@findISPexits Function@@@@@@@@@@@@@@@@@@@@@@@@"
                dependentPrefixes.close()
                EXITS_SEM=EXITS_SEM+1

class ExecutionAndParsing:
    def findAllPaths(ss,sss,myASN): #making tasklist for trace routing - ASN & IP
        print('START execution and parsing') 
        global EXITS_SEM
        global TRS_SEM  #to erase
        prefixesFile='as'+str(myASN)+'.htm'
        myPrefixes = subnet_soup.getprefixes(prefixesFile)
        
        for rv in routeViewList:
            while EXITS_SEM <= 0:
                print 'EXIT semaphor closed, sleeping.'
                time.sleep(30)
            if EXITS_SEM>0:
                EXITS_SEM=EXITS_SEM-1
                print(rv)
                print(os.path.isfile(rv[0] + '-'+str(myASN)+"-exits.txt".encode('ascii')))
                if os.path.isfile(rv[0] + '-'+str(myASN)+"-exits.txt".encode('ascii')):
                    ispExits=open(rv[0] + '-'+str(myASN)+"-exits.txt".encode('ascii'),"rb",0)
#                   print('ispExits : ', ispExits)
                else:
                    print "This file doesn't exsit: " +rv[0] + '-'+str(myASN)+"-exits.txt".encode('ascii')
                    continue
                print"path file exist???"
                print(os.path.isfile(rv[0] +'-'+str(myASN)+ "-paths.txt".encode('ascii')))
                print"then make it!!"
                if os.path.isfile(rv[0] +'-'+str(myASN)+ "-paths.txt".encode('ascii')):
                    TRS_SEM=TRS_SEM+1
                    ispExits.close()
                    continue  #os.remove(x[0] + "-exits.txt".encode('ascii'))
                ispPaths=open(rv[0] +'-'+str(myASN)+ "-paths.txt".encode('ascii'),"wb",0) # wb means file is opened for writing in binary mode.
                print('ispPaths : ', ispPaths)

                for exit in ispExits:
                    for asnTrs, trs in traceRouteServerList.iteritems():
                        try:
                            tn=telnetlib.Telnet(trs[0],0,timeout=12000)
                        except:
                            continue
                        if len(trs)>1:
                            if trs[1]!='-':
                                tn.read_until(trs[1])
                                tn.write(trs[2] + b"\n")
                                if len(trs)>3:
                                    tn.read_until(trs[3])
                                    tn.write(trs[4] + b"\n")
                        tn.write("terminal length 0".encode('ascii')+"\n".encode('ascii'))
                    
                        print "\n"+"tracerouting... to  " + exit
                        traceRoute="traceroute ".encode('ascii') + exit
#                        print "traceroute : " + traceRoute
                        try:
                                tn.write(traceRoute)
                                line = tn.read_until("Tracing")
#                                print 'current location :'+ str(line)
                                line = tn.read_until(b"\r\n")
#                                print 'current location :'+ str(line)
                                line = tn.read_until(b"\n")
#                                print 'current location :'+ str(line)
#                                line = tn.read_until(b"\n")
#                                line = tn.read_until(b"\n")
#                                line = tn.read_until(b"\n")
                        except:
                                break
                        exitIP=str(exit).split('\r\n')
                        path=""
                        ttl=0
                        ip=[]
                        kk=0
                        try:
                                while ip==[] or ip[0] != exitIP[0] :
                                    print 'reading res with ttl ' + str(ttl)
                                    line = tn.read_until(b"\n")
                                    ttl=ttl+1
                                    parts=line.split()
                                    print 'parts : '+str(parts)
                                    if any("!A" in s for s in parts):
                                        print"meet !A escape"
                                        break
                                    if any("*" in s for s in parts[3]):
                                        if kk > 1 :
                                            print "too much *, escape"
                                            break
                                        kk=kk+1
                                        continue
                                    else:
                                        ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )

                                    isIpInISP=0
                                    if ip!=[]:
                                        for prefix in myPrefixes:
                                            subnet= str(prefix[0]) + "/" + str(prefix[1])
                                            if IPAddress(ip[0]) in IPNetwork(subnet): # check if traceroute result is same as BGP.he
                                                print 'found!! in BGP.he prefix'
                                                if parts[1].isalpha() :
                                                    path=path+ip[0]+':'+parts[1]+', '
                                                    print 'path : '+ str(path)
                                                    break
                                                elif parts[0] == ip[0]:
                                                    path=path+ip[0]+':'+parts[0]+', '
                                                    print 'path : '+str(path)
                                                    break
                                                else:
                                                    path=path+ip[0]+':'+parts[1]+', '
                                                    print 'path : '+str(path)
                                                    break
                                    print ('ip[0] : ' , str(ip[0]))
                                    print ('exitIP[0] : ' , str(exitIP[0]))
                                    if ip[0]==exitIP[0]: 
                                             break
                                    print 'go to while'
                        except:
                                break
                        ispPaths.write(path+"\n")
                        print "Path added: " + path + '\n############################findAllPaths Function######################'
                        time.sleep(5)
                        tn.close()
                ispExits.close()
                ispPaths.close()
                TRS_SEM=TRS_SEM+1

    def findAllPathsByLocalUser(ss,sss,myASN): #making tasklist for trace routing
        print('START find all paths by local user')
        global EXITS_SEM
        global LU_SEM    #to erase
        prefixesFile='as'+str(myASN)+'.htm'
        myPrefixes = subnet_soup.getprefixes(prefixesFile)
        
        for rv in routeViewList:
            while EXITS_SEM <= 0:
                time.sleep(30)
            if EXITS_SEM>0:
                EXITS_SEM=EXITS_SEM-1
                if os.path.isfile(rv[0] + '-'+str(myASN)+"-exits.txt".encode('ascii')):
                    ispExits=open(rv[0] + '-'+str(myASN)+"-exits.txt".encode('ascii'),"rb",0) # rb means read binary.
                else:
                    print "This file doesn't exsit: " +rv[0] + '-'+str(myASN)+"-exits.txt".encode('ascii')
                    continue
                if os.path.isfile(rv[0] +'-'+str(myASN)+ "-pathsByLocalUser.txt".encode('ascii')):
                    LU_SEM=LU_SEM+1
                    ispExits.close()
                    continue #os.remove(x[0] + "-exits.txt".encode('ascii'))
                ispPaths=open(rv[0] +'-'+str(myASN)+ "-pathsByLocalUser.txt".encode('ascii'),"wb",0)
                    
                for exit in ispExits:
                    print "Searching ISP path to exit: " + exit
                    exitIP=str(exit).split('\r\n')
#                    print( "exitIP : " , exitIP)
#                    print "tracerouting.... to the exit"
                    proc = subprocess.Popen(["traceroute", exitIP[0]], stdout=subprocess.PIPE, shell=False)
                    (out, err) = proc.communicate()
                    hops=out.split('\n')
                    print('len(hops) : ' , len(hops))
                    path=""
                    ttl=0
                    ip=[]
                    kkCount=0
#                    print('result : ', hops[4])
#                    for i in range(4,34):
                    for i in range(1,len(hops)-1):
                        line = hops[i]
                        ttl=ttl+1
                        parts=line.split()
                        print ('parts : ' ,parts)
                        ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )
                        isIpInISP=0
                        if any("*" in s for s in parts[3]):
                            kkCount = kkCount+1
                            if kkCount > 2 :
                                print "too much *, escaped"
                                break
                            continue
                        if ip!=[]:
                            for prefix in myPrefixes:
                                subnet= str(prefix[0]) + "/" + str(prefix[1])
                                if IPAddress(ip[0]) in IPNetwork(subnet):
                                    print 'found!! in BGP.he prefix'
#                                    path=path+ip[0]+':'+parts[1]+','
#                                    print('current path: ', path)
#                                    break
                                    if parts[1].isalpha() :
                                        path=path+ip[0]+':'+parts[1]+', '
                                        print 'path : '+ str(path)
                                        break
                                    elif parts[0] == ip[0]:
                                        path=path+ip[0]+':'+parts[0]+', '
                                        print 'path : '+str(path)
                                        break
                                    elif parts[1] == '*':
                                        path=path+ip[0]+':'+parts[1]+', '
                                        print 'path : '+str(path)
                                        break
                                    else:
                                        path=path+ip[0]+':'+parts[1]+', '
                                        print 'path : '+str(path)
                                        break
                            print ('ip[0] : ' , str(ip[0]))                
                            print ('exitIP[0] : ' , str(exitIP[0]))
                            if ip[0]==exitIP[0]:
                                print "ip[0] is matched with exitIP[0]!!!"
                                break;
                            print 'read next hop line'+'\n'
                    ispPaths.write(path+"\n")
                    print "Path added: " + path + '\n$$$$$$$$$$$$$$$$$$$$$$$$findAllPathsByLocalUser Function$$$$$$$$$$$$$$$$$$$'
            ispExits.close()
            ispPaths.close()
            LU_SEM=LU_SEM+1

class RocketFuel:
    myASN=0   #the ASN of the ISP: 9116 / 12849
    ed=EgressDiscovery()
    tg=TasklistGeneration()
#    ep=ExecutionAndParsing()
    def __init__(self, asn=0):
        asn=input("Set ASN:")
        self.myASN=int(asn)

class MapGraph:

    def __init__(self,ASN):
        self.filename = str(ASN) + 'network graph'
        self.alias_filename = str(ASN) + 'alias_candidates.txt'
        self.ISP_Network = networkx.Graph()
        self.files_read = 0
        self.border_points = set()
        if os.path.isfile(self.filename):
            load_file = shelve.open(self.filename, 'r')
            self.files_read = load_file['files_read']
            self.ISP_Network = load_file['ISP_Network']
            self.border_points = load_file['border_points']
        self.ASN = ASN
        plt.ion()

        country = raw_input('enter country to focus on map [Israel/Usa/Bahrain/other]: ')
        if country == 'Israel' or country == 'israel' or country == 'ISRAEL':
            self.wmap = Basemap(projection='mill', lat_0 = 31.4, lon_0 = 35, width = 200000, height = 450000, resolution = 'i')
        elif country == 'USA' or country == 'usa':
            self.wmap = Basemap(projection='aeqd', lat_0 = 40, lon_0 = -98, width = 4500000, height = 2700000, resolution = 'i')
        elif country == 'Bahrain' or 'australia' or 'AUSTRALIA':
            self.wmap = Basemap(projection='lcc', lat_0 = -23.07, lon_0 = 132.08, width = 4500000, height = 3500000, resolution = 'i')
        elif country == 'other':
            #self.wmap = Basemap(projection='cyl', resolution = 'c')
            #self.wmap=Basemap(projection='cyl',llcrnrlat=-90,urcrnrlat=90,llcrnrlon=-180,urcrnrlon=180,resolution='c')
            self.wmap = Basemap(width=12000000,height=9000000,projection='lcc', resolution=None,lat_1=45.,lat_2=55,lat_0=50,lon_0=-107.)
        #plt.hold(False)

    def PrintToMap(self):
    # Updates the graphic presentation of the geographical map, and show it as output.
        print"PrinttoMap"
        self.wmap.drawmapboundary(fill_color = 'aqua')
        self.wmap.drawcoastlines(linewidth = 0.75)
        self.wmap.drawcountries(linewidth = 0.75)
        self.wmap.fillcontinents(color='coral', lake_color = 'aqua')
        #plt.hold(True)
        for edge in self.ISP_Network.edges():
            print 'placing ' + str(edge[0][1][1]) + ' ' + str(edge[0][1][0])

            #First coordinate appear three time
            map_line_x = [edge[0][1][1],edge[0][1][1],edge[0][1][1],edge[1][1][1]]
            print('map_line_x : ', map_line_x)

            #Because printing smaller parth returns an error.
            map_line_y = [edge[0][1][0],edge[0][1][0],edge[0][1][0],edge[1][1][0]]
            print('map_line_y :', map_line_y)

            self.wmap.plot(map_line_x, map_line_y, latlon = True, marker = 'o', color = 'r')
        plt.show()
        #p.show()
        #plt.hold(False)
        plt.pause(5)
        
    def PrintToGraph(self):
    # Updates the graphic presentation of the logical graph, and show it as output.
        print"PrintToGraph"
        label_list = {}
        color_list = {}
        plt.clf()
        for node in self.ISP_Network.nodes():
                print('**** node[0] is ', node[0])
                label_list[node] = node[0]
                if node in self.border_points:
                    color_list[node] = 'g'
                    print('****color_list[node] is ', color_list[node])
                else:
                    color_list[node] = 'r'
                    print('****color_list[node] is ', color_list[node])
        networkx.draw_shell(self.ISP_Network, with_labels = True, labels =  label_list, node_color = color_list.values())

    def address_to_real_address(self, unionFind, AddressToIndex, IndexToAddress, IP_address):
        if IP_address in AddressToIndex.keys():
            return IndexToAddress[unionFind.find(AddressToIndex[IP_address])]

    def makeGraph(self):
    # Loops around and print the map and graph every time new paths are added
        print('MakeGraph')
        global TRS_SEM
        self.PrintToMap()
        self.PrintToGraph()
        plt.pause(5)
        for rv in routeViewList:
            print('TRS_SEM : ',TRS_SEM)
            while TRS_SEM <= self.files_read:
                print 'PATH semaphor closed sleeping'
                for i in range(3):
                    self.PrintToGraph()
                    plt.pause(5) 
                    self.PrintToMap()
            if TRS_SEM > self.files_read:
                current_file = rv[0] +'-'+str(self.ASN)+ "-paths.txt".encode('ascii')
                print 'Adding paths from ' + current_file
                if os.path.isfile(current_file):
                    path_file=open(current_file,"r",0)
                else:
                    print "This file doesn't exsit: " + current_file
                    continue
                
                graph_path = []
                for line in path_file: 
                    if line == "":
                        break
                    if line == "\n":
                        continue
                    path = line.split(', ')
#                    print('current path line : ', path)
                    garbage = path.pop() 
                    print('len(path) : ', len(path))
                    self.border_points.add(path[0])
                    self.border_points.add(path[len(path)-1])
                    for server in path:
                        ip = server.split(':')[0]
                        name = server.split(':')[1]
                        match = geolite2.lookup(ip)
                        graph_path.append((ip, match.location, name))
#                        print ('graph_path : ', str(graph_path))
                        print 'added vertex ' + str(match.location[0]) + ' ' + str(match.location[1])
                        print "next server in path!"
                        print("IP: %s" % match.ip)
                        print("Country: %s" % match.country)
                        print("Continent: %s" % match.continent)
#                        print("Subvisions: %s" % comma_sep(match.subdivisions))
#                        print("Timezone: %s" % match.timezone)
#                        print("Location: %s" % comma_sep(match.location))
                    self.border_points.add(graph_path[0])
                    self.border_points.add(graph_path[len(path)-1])
                    self.ISP_Network.add_path(graph_path)
#                    if next(path_file) is None:
#                            break
                    print "next path line" + "\n"
                self.files_read += 1
                self.PrintToMap()
                self.PrintToGraph()
                plt.pause(5)

                print 'Alias Started!'
                alias_data = ''
                label_list = {}
                print( 'len(self.ISP_Network.nodes) : ', len(self.ISP_Network.nodes()))
                for node in self.ISP_Network.nodes():
                    alias_data = alias_data + node[0] + ' ' + str(node[1][0]) +'_' + str(node[1][1]) + ' ' +  node[2] + '\n'
                alias_file = open(self.alias_filename,'w')
                alias_file.write(alias_data) 
                alias_file.close()
                unionFind, IndexToAddress, AddressToIndex, listOfLists = alias_resolve(os.getcwd(), self.alias_filename)

                new_graph = networkx.Graph()
                for edge in self.ISP_Network.edges():
                    ip1 = self.address_to_real_address(unionFind, AddressToIndex, IndexToAddress, edge[0][0])
                    ip2 = self.address_to_real_address(unionFind, AddressToIndex, IndexToAddress, edge[1][0])
                    if ip1:
                        u = (ip1, edge[0][1], edge[0][2])
                    else:
                        u = (edge[0][0], edge[0][1], edge[0][2])
                    if ip2:
                        v = (ip2, edge[1][1], edge[1][2])
                    else:
                        v = (edge[1][0], edge[1][1], edge[1][2])
                    new_graph.add_edge(u, v)
                self.ISP_Network = new_graph
                
                print('save file start')
                save_file = shelve.open(self.filename, 'n')
                save_file['ISP_Network'] = self.ISP_Network
                save_file['files_read'] = self.files_read
                save_file['border_points'] = self.border_points
                save_file.close()
                self.PrintToGraph()
                plt.pause(10)
                self.PrintToMap()
                plt.pause(5)
                print 'printed map at the end after saving'

r=RocketFuel()
mg = MapGraph(r.myASN)

# 'start_new_thread' means func(=thread execution function), args(=argument to be thrown to the func), kwargs(=keyword argument) 
# for example, below, r.ed is func and r.myASN is args   
thread.start_new_thread(r.ed.findAllDependentPrefixes,(r.ed,r.myASN)) # egree discovery
thread.start_new_thread(r.tg.findISPexits,(r.tg,r.myASN)) # tasklist generation
#thread.start_new_thread(r.ep.findAllPaths,(r.ep,r.myASN)) # execution and parsing
#thread.start_new_thread(r.ep.findAllPathsByLocalUser,(r.ep,r.myASN)) # execution and parsing
#mg.makeGraph()

while True:
        continue

