#!/usr/bin/python
###############################
# Circa 2011 for class project.
# Written by Delane Jackson and Aaron Bazar
###################################


import json
import sqlite3
from time import sleep
from scapy.all import *
from os.path import basename



class Dumpy(object):
    PACKETSLIST = [Ether, IP, TCP, Raw]
   
    def __init__(self, pcapfilepath, convertfields=True):
        ''' 
            Creates an instance of the Dumpy class.
            pcapfilepath - the pcap file used to instantiate this calss and to get parsed
            converfields = determines if the fields should be converted to their string representation or not.
        '''
        self.file = pcapfilepath
        self.cf = convertfields
        self.dbfile = basename(self.file + '.db')
        self.__readPCAP__()
        self.__setNumberOfPackets__()
        self.createDB()

    def __readPCAP__(self):
        ''' reads in the pcap file into class '''
        self.pcap = rdpcap(self.file)

    
    ''' ########## PACKET OBJECTS ########## '''
    def getEtherObject(self,pkt_num):
        '''
            Return the Ethernet object for a packet.  False is returned if Ethernet is not in packet
            pkt_num = the packet number (0-based) to get the Ethernet object for
            raises ValueError if pkt_num is not within range
        '''
        retVal = False
        if self.__checkPacketNumber__(pkt_num):
            
            if Ether in self.pcap[pkt_num]:
                retVal = self.pcap[pkt_num][Ether]
            else:
                retVal = False
        else:
            raise ValueError(self.__packetNumberMessage__())
        
        return retVal
    
    def getIPObject(self,pkt_num):
        '''
            Return the IP object for a packet.  False is returned if Ethernet is not in packet
            pkt_num = the packet number (0-based) to get the Ethernet object for
            raises ValueError if pkt_num is not within range
        '''
        retVal = False
        if self.__checkPacketNumber__(pkt_num):
            
            if IP in self.pcap[pkt_num]:
                retVal = self.pcap[pkt_num][IP]
            else:
                retVal = False
        else:
            raise ValueError(self.__packetNumberMessage__())
        
        return retVal
    
    def getTCPObject(self,pkt_num):
        '''
            Return the TCP object for a packet.  False is returned if TCP is not in packet
            pkt_num = the packet number (0-based) to get the Ethernet object for
            raises ValueError if pkt_num is not within range
        '''
        retVal = False
        if self.__checkPacketNumber__(pkt_num):
            
            if TCP in self.pcap[pkt_num]:
                retVal = self.pcap[pkt_num][TCP]
            else:
                retVal = False
        else:
            raise ValueError(self.__packetNumberMessage__())
        
        return retVal

    def getRawObject(self, pkt_num):
        '''
            Raw objects contain the upper layer "load".
            Return the Raw object for a packet.  False is returned if there's no Raw object in the packet
            pkt_num = the packet number (0-based) to get the Ethernet object for
            raises ValueError if pkt_num is not within range
        '''
        retVal = False
        if self.__checkPacketNumber__(pkt_num):
            
            if Raw in self.pcap[pkt_num]:
                retVal = self.pcap[pkt_num][Raw]
            else:
                retVal = False
        else:
            raise ValueError(self.__packetNumberMessage__())
        
        return retVal

    
    ''' ########## ETHERNET SPECIFIC METHODS ########## '''
    def getMacs(self):
        '''
            Returns a list of mac addresses from pcap file
            List is of tuples in the form of (src, dst)
        '''
        retVal = []
        for pkt in self.pcap.filter(lambda x: Ether in x):
            retVal.append( (pkt.src, pkt.dst) )
            
        return list(retVal)
    
    def convertEtherType(self, val):
        '''
            Returns the converted value.  If value cannot be converted, the original value is returned.
            val = the value to return.  Should be a hex value
        '''
        etherFields = {
                        '0x800': 'IPv4', '0x806': 'ARP', '0x842': 'WOL MP',
                        '0x1337': 'SYN-3', '0x6003': 'DECnet', '0x8035': 'RARP',
                        '0x809B': 'Ethertalk', '0x80F3': 'AARP', '0x8100': '802.1q',
                        '0x8137': 'IPXalt', '0x8138': 'Novell', '0x86DD': 'IPv6',
                        '0x8808': 'MAC Control', '0x8809': 'IEEE 802.3', '0x8819': 'CobraNet',
                        '0x8847': 'MPLS uni', '0x8848': 'MPLS multi', '0x8863': 'PPPoE Discovery',
                        '0x8864': 'PPPoE Session', '0x886F': 'MS NLB Heartbeat', '0x8870': 'Jumbo Frames',
                        '0x887B': 'HomePlug 1.0 MME', '0x888E': 'IEEE 802.1X', '0x8892': 'PROFINET',
                        '0x889A': 'HyperSCSI', '0x88A2': 'ATAoE', '0x88A4': 'EtherCAT',
                        '0x88A8': 'IEEE 802.1ad', '0x88AB': 'Ethernet Powerlink', '0x88CC': 'LLDP',
                        '0x88CD': 'SERCOS III', '0x88D8': 'MEF-8', '0x88E1': 'HomePlug AV MME',
                        '0x88E5': 'IEEE 802.1AE', '0x88F7': 'IEEE 1588', '0x8902': 'IEEE 802.1ag CFM',
                        '0x8906': 'FCoE', '0x8914': 'FCoE Init', '0x9000': 'Loop',
                        '0x9100': 'Q-in-Q', '0xCAFE': 'Veritas LLT'
                    }
                    
        retVal = val
        if val in etherFields.keys():
            retVal = etherFields[val]
            
        return retVal

    
    ''' ########## IP SPECIFIC METHODS ########## '''
    def getIPs(self):
        '''
            Returns a list of ip's extracted from pcap file
            List is of tuples with (src, dst)
        '''
        retVal = []
        for pkt in self.pcap.filter(lambda x: IP in x):
            retVal.append( (pkt[IP].src, pkt[IP].dst) )

        return list(retVal)
 

    ''' ########## SQL METHODS ########## '''
    def createDB(self):
        '''
            Create the database for this capture file.  DB name will be the
            name of the file with db appended (http.cap.db).
        '''
        
        conn = sqlite3.connect(self.dbfile)
        c = conn.cursor()
        c.executescript('drop table if exists main_pcap;')
        c.execute('''CREATE TABLE main_pcap ( pkt_id INTEGER,ether_src MEDIUMTEXT , ether_dst MEDIUMTEXT, ether_type INTEGER , ip_version INTEGER , ip_ihl INTEGER , ip_tos INTEGER , ip_len INTEGER , ip_id INTEGER , ip_flags MEDIUMTEXT , ip_frag INTEGER , ip_ttl INTEGER , ip_proto MEDIUMTEXT , ip_chksum INTEGER , ip_src MEDIUMTEXT , ip_dst INTEGER , ip_options MEDIUMTEXT , tcp_sport INTEGER , tcp_dport INTEGER , tcp_seq INTEGER , tcp_ack INTEGER , tcp_dataofs INTEGER , tcp_reserved INTEGER , tcp_flags MEDIUMTEXT , tcp_window INTEGER , tcp_chksum INTEGER , tcp_urgptr INTEGER , tcp_options MEDIUMTEXT , tcp_load MEDIUMTEXT )''')
        conn.commit()
        
    def sqlitedump(self):
        '''
            Prepares the fields for entry into the sqlite database.
            This method uses the objects within the pcap file to store the info.
        '''
        for pkt in range(self.getNumberOfPackets()):

            eth_obj = self.getEtherObject(pkt)
            if eth_obj:
                ethFields=self.getFieldDict(eth_obj)

            ip_obj = self.getIPObject(pkt)
            if ip_obj:
                ipFields=self.getFieldDict(ip_obj)

            tcp_obj = self.getTCPObject(pkt)
            if tcp_obj:
                tcpFields=self.getFieldDict(tcp_obj)

        populateDB(self, pkt,ethFields,ipFields,tcpFields)
        
    def sqlitedump2(self):
        '''
            Prepares the fields for entry into the database.
            This method utilizes the getAll method and stores based on the
            resulting list.
        '''
        stuff = self.getAll()
        
        for pkt in range(len(stuff)):
            ethDict = {}
            ipDict = {}
            tcpDict = {}
            rawDict = {}
            pktKeys = stuff[pkt].keys()
            if 'Ethernet' in pktKeys:
                ethDict = stuff[pkt]['Ethernet']
            if 'IP' in pktKeys:
                ipDict = stuff[pkt]['IP']
            if 'TCP' in pktKeys:
                tcpDict = stuff[pkt]['TCP']
            if 'Raw' in pktKeys:
                rawDict = stuff[pkt]['Raw']
            
            self.populateDB(pkt, ethDict, ipDict, tcpDict, rawDict)
        
    def populateDB(self, pkt,ethDict,ipDict,tcpDict, rawDict):
        '''
            inserts value into db. If a dictionary is empty, default values
            are stored.  Defaults will contain the string "empty" for all fields.
         '''
        
        finalList=[]
        finalList.append(pkt)
        
        # set some defaults
        defaultEthDict = {'src':'empty', 'dst': 'empty', 'type': 'empty'}
        defaultRawDict = {'load': 'empty'}
        defaultIPDict = {
                        'version': 'empty', 'ihl': 'empty', 'tos': 'empty',
                        'len': 'empty', 'id': 'empty', 'flags': 'empty',
                        'frag': 'empty', 'ttl': 'empty', 'proto': 'empty',
                        'chksum': 'empty', 'src': 'empty', 'dst': 'empty',
                        'options': 'empty'
                        }
        defaultTCPDict = {
                        'sport': 'empty', 'dport': 'empty', 'seq': 'empty',
                        'ack': 'empty', 'dataofs': 'empty', 'flags': 'empty',
                        'window': 'empty', 'chksum': 'empty', 'urgptr': 'empty',
                        'options': 'empty'
                        }
        
        #NOTE: Wonder if we can just append the entire dict and python will
        #      extract the values we need automagically when inserting???
        #      finalList.append(ethDict)
        
        # add the Ethernet layer stuff
        if ethDict:
            finalList.append(ethDict["src"])
            finalList.append(ethDict["dst"])
            finalList.append(ethDict["type"])
        else:
            finalList.append(defaultEthDict["src"])
            finalList.append(defaultEthDict["dst"])
            finalList.append(defaultEthDict["type"])

        #add the IP layer stuff
        if ipDict:
            finalList.append(ipDict["version"])
            finalList.append(ipDict["ihl"])
            finalList.append(ipDict["tos"])
            finalList.append(ipDict["len"])
            finalList.append(ipDict["id"])
            finalList.append(ipDict["flags"])
            finalList.append(ipDict["frag"])
            finalList.append(ipDict["ttl"])
            finalList.append(ipDict["proto"])
            finalList.append(ipDict["chksum"])
            finalList.append(ipDict["src"])
            finalList.append(ipDict["dst"])
            finalList.append(str(ipDict["options"]))
            finalList.append(ipDict["chksum"])
        else:
            finalList.append(defaultIPDict["version"])
            finalList.append(defaultIPDict["ihl"])
            finalList.append(defaultIPDict["tos"])
            finalList.append(defaultIPDict["len"])
            finalList.append(defaultIPDict["id"])
            finalList.append(defaultIPDict["flags"])
            finalList.append(defaultIPDict["frag"])
            finalList.append(defaultIPDict["ttl"])
            finalList.append(defaultIPDict["proto"])
            finalList.append(defaultIPDict["chksum"])
            finalList.append(defaultIPDict["src"])
            finalList.append(defaultIPDict["dst"])
            finalList.append(str(defaultIPDict["options"]))
            finalList.append(defaultIPDict["chksum"])


        # add the TCP layer stuff
        if tcpDict:
            finalList.append(tcpDict["sport"])
            finalList.append(tcpDict["dport"])
            finalList.append(tcpDict["seq"])
            finalList.append(tcpDict["ack"])
            finalList.append(tcpDict["dataofs"])
            finalList.append(tcpDict["flags"])
            finalList.append(tcpDict["window"])
            finalList.append(tcpDict["chksum"])
            finalList.append(tcpDict["urgptr"])
            finalList.append(str(tcpDict["options"]))
        else:
            finalList.append(defaultTCPDict["sport"])
            finalList.append(defaultTCPDict["dport"])
            finalList.append(defaultTCPDict["seq"])
            finalList.append(defaultTCPDict["ack"])
            finalList.append(defaultTCPDict["dataofs"])
            finalList.append(defaultTCPDict["flags"])
            finalList.append(defaultTCPDict["window"])
            finalList.append(defaultTCPDict["chksum"])
            finalList.append(defaultTCPDict["urgptr"])
            finalList.append(str(defaultTCPDict["options"]))
        
        #add the Upper layer stuff
        if rawDict:
            finalList.append(rawDict["load"])
        else:
            finalList.append(defaultRawDict["load"])




        conn = sqlite3.connect(self.dbfile)
        c = conn.cursor()
        c.execute('insert into main_pcap values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',finalList)

        conn.commit()

    
    ''' ########## GENERAL/HELPER METHODS ########## '''
    def getAll(self, returnjson=False):
        '''
            Returns a list of dictionaries that contain all the fields in every
            packet in the capture.  Each item in the list represents the packet number.
            returnjson = return value will be json if set to True
            structure:
                [
                    {
                        'Ether': {'src': 'xx:xx:xx:xx', 'dst': 'xx:xx:xx:xx', 'type': 0x800},
                        'IP': {'frag': 0L, 'src': '65.208.228.223', 'proto': 'tcp',...},
                        'TCP': {},
                        'Raw': {}
                    },
                    {
                        'Ether': {'src': 'xx:xx:xx:xx', 'dst': 'xx:xx:xx:xx', 'type': 0x800},
                        'IP': {'frag': 0L, 'src': '192.168.1.54', 'proto': 'tcp',...},
                        'TCP': {},
                        'Raw': {}
                    }
                ]
        '''
        retVal = list()
        for packet in self.pcap:
            layerdict = dict()
            for proto in self.PACKETSLIST:
                if proto in packet:
                    layerdict[proto.name] = self.getFieldDict(packet[proto])
            if layerdict:
                retVal.append(layerdict)
        
        if returnjson:
            retVal = json.dumps(retVal)
            print retVal
            print "JSON TRUE"
        
        return retVal
                    
                    
    def getNumberOfPackets(self):
        '''
            Returns the number of packets in the capture file
        '''
        return self.numOfPackets
        
    def __setNumberOfPackets__(self):
        '''
            Set the number of packets in the pcap file
        '''
        self.numOfPackets = len(self.pcap)
        
    def __checkPacketNumber__(self, pkt_num):
        '''
            Checks that the pkt number is valid
            returns true if packet number is valid, false otherwise
        '''        
        retVal = False
        if self.numOfPackets >= pkt_num >= 0:
            retVal = True
        
        return retVal
        
    def __getFieldRepr__(self, packetobj):
        '''
            Returns the fields representation.  Example tcp.flags could be S (SYN)
            packetobj = the packet object to get the field info from
        '''
        retVal = {}
        if packetobj is not None:
            fieldlist = packetobj.fields_desc
            for fieldobj in fieldlist:
                # need to make sure to call the convertEtherType method for the Ether layer
                # only ether contains a type field
                if fieldobj.name == 'type':
                    fvalue = fieldobj.i2repr(packetobj, packetobj.getfieldval(fieldobj.name))
                    retVal[fieldobj.name] =  self.convertEtherType(fvalue)
                else:
                    retVal[fieldobj.name] =  fieldobj.i2repr(packetobj, packetobj.getfieldval(fieldobj.name))
        else:
            msg = "packetobj set to %s, fieldobj set to %s..  Check the values and try again" % packetobj
            raise ValueError(msg)
        
        return retVal
        
    def __packetNumberMessage__(self, pkt_num):
        '''
            Was placing the same message in multiple locations so instead,
            this message will be responsible for returning that message
        '''
        return "pkt_num set to %d - value should be >= 0 or <= %d" % (pkt_num, self.numOfPackets)
    
        
    def getFieldDict(self, packetobj):
        '''
            Returns a dictionary of all the fields in the packetobj
            packetobj = should be a Packet object to grab the fields out of
            Example of a packet object is TCP, IP, Ether, etc...
        '''
        retVal = dict()
        if packetobj is not None:
            if self.cf:
                retVal = self.__getFieldRepr__(packetobj)
            else:
                retVal = packetobj.fields
        else:
            msg = "packetobj set to %s.  Check the values and try again" % packetobj
            raise ValueError(msg)
        
        return retVal

if __name__ == '__main__':
    dmp = Dumpy('http_gzip.cap')
##    dmp = Dumpy('/home/delane/Documents/sample_dumps/icmp.pcap')
##    dmp = Dumpy('/home/delane/Documents/sample_dumps/multiple_icmp.pcap')
##    dmp = Dumpy('/home/delane/Documents/sample_dumps/wol.pcap')

    print "NUMBER OF PACKETS"
    print "%d (0 - %d)" % (dmp.getNumberOfPackets(), dmp.getNumberOfPackets() - 1)
    print

##    print "ETHER FIELDS"
##    eth_obj = dmp.getEtherObject(3)
##    if eth_obj:
##        print dmp.getFieldDict(eth_obj)
##    else:
##        print "No Eth Obj"
##    print
##    
##    print "IP FIELDS"
##    ip_obj = dmp.getIPObject(3)
##    if ip_obj:
##        print dmp.getFieldDict(ip_obj)
##    else:
##        print "No IP Object"
##    print
##    
##    print "TCP FIELDS"
##    tcp_obj = dmp.getTCPObject(7)
##    if tcp_obj:
##        print dmp.getFieldDict(tcp_obj)
##    else:
##        print "No TCP Object"
##    print
##   
##    print "RAW INFO" 
##    raw_obj = dmp.getRawObject(7)
##    if raw_obj:
##        print dmp.getFieldDict(raw_obj)
##    else:
##        print "No Raw Object"
##    print
    
##    print '########## RETRIEVING EVERYTHING ##########'
##    all = dmp.getAll()
##    alljson = dmp.getAll()
    # in multiple.icmp.pcap file packets 10 and 11 are ARPs
##    print all[10]
    #print alljson
    
##    print '########## TESTING MAC CONVERSION ##########'''
##    print dmp.convertEtherType('900')
##    print dmp.convertEtherType('0x88E1')
##    print
    
    print '########## TESTING SQLITEDUMP ##########'''
    dmp.sqlitedump2()
##    print dmp.getEtherObject(0).fields
##    print dmp.getTCPObject(0).fields
##    print dmp.getFieldDict(dmp.getEtherObject(0), convertfields=False)


