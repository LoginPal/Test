#!/usr/bin/python

import sys, getopt
import glob
import pymonetdb
import itertools
import re
sys.path.append('gen-py')
sys.path.insert(0, glob.glob('/root/aeverie/libs/lib*')[0])

from config import aev_config
from config.ttypes import aev_if_prop
from config.ttypes import aev_vxlan_tunnel_prop

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
import binascii
import  socket

cursor = 0
ifprop   = 0
vxtunprop = 0
ret    = 0
vxret = 0
collector_list = []

'''
There are select and insert queries and they can be converted to the functions

'''

##******************Future code*********************##

#def selectQueryFunc(table_name#mandatory, if not passed return error#,tuples#if nothing is passed, * as default#,condition#optional parameter#,\
#condition_params ## if the condition is true, then the params should be there, if not given, send back error):

#Return whatever we get back from this function.

#def insertQueryFunc (table_name#mandatory, if not passed return error#, values #if nothing has been sent, then all tuples should be set\
#, valuesparam# if the values is empty, then run the following query
#
#
# SELECT COUNT(*)
#   FROM INFORMATION_SCHEMA.COLUMNS
#  WHERE table_catalog = 'database_name' -- the database
#    AND table_name = 'table_name'
#
#
#   check if the columns match the list count, if not send the error back that all values are not present
#
#   else
#
#   if values list is not 0, then check if the valueparam list count == values list count)


##******************Future code*********************##

##******************show commands*********************##

def collectorShowInfo():
    global cursor
    selectQueryString = "SELECT * FROM collector_sess_table"
    pivot = cursor.execute(selectQueryString)
    if bool(pivot) == True:
        print(cursor.fetchall())
        return True
    else:
        return False


def tunnelShowInfo():
    global cursor
    selectQueryString = "SELECT * FROM vxlan_tnl_table"
    pivot = cursor.execute(selectQueryString)
    if bool(pivot) == True:
        print(cursor.fetchall())
        return True
    else:
        return False


##******************CollectorTunnel section*********##

'''
Check for the collectorid provided by the user to the terminal.
If it doesn't exist, the session should be created.
Return is set upon the idea if the session exists or not
'''

def collector_session_check(collectorid):
    #This function checks if a session id is already there or needs to be created
    global cursor
    selectQueryString = "SELECT sess_id FROM collector_sess_table WHERE sess_id=%d" % int(collectorid)
    queryret = cursor.execute(selectQueryString)
    if queryret==False:
        selectSubQueryString = "INSERT INTO collector_sess_table (sess_id) VALUES (%d)" % int(collectorid)
        subqueryret = cursor.execute(selectSubQueryString)


def modifyNewCollectorTable(interface,sessionId):
    #Modify the session row when interface related to the session id is provided
    global cursor
    selectQueryString = "SELECT sess_id FROM collector_sess_table WHERE src_intf='%s'" % interface
    queryRet = cursor.execute(selectQueryString)

    if queryRet == False:
        #Means this source interface is not in use and no session is using it
        updateQueryString = "UPDATE collector_sess_table SET src_intf='%s' WHERE sess_id= %d " % (interface, int(sessionId))
        cursor.execute(updateQueryString)
        return 1

    else:
        existingSessId = cursor.fetchone()[0] #Fetch the first element from the tuple
        if int(existingSessId) == int(sessionId):
            return 0

        else:
            return -1

def dstTunnelName(tunnelName, vlanid, sessId):
    global vxtunprop
    global cursor
    global collector_list

    #Update VLAN id in the collector table
    #For now the source vlan will be 0. For future purpose

    insertQueryString = "UPDATE collector_sess_table SET src_vlan=%d WHERE sess_id=%d" % (vlanid, int(sessId))
    cursor.execute(insertQueryString)

    ##********************CASE NOT REQUIRED*********************************************##
    '''
    ##Check if the source interface is already set, if not set then there is no work of tunnel
    selectQueryString = "SELECT src_intf FROM collector_sess_table WHERE dst_tnl='%s'" % tunnelName
    portVal = cursor.execute(selectQueryString)
    if portVal==False:
        return 2
    else:
        portVal = cursor.fetchone()[0]
    '''
    ##********************CASE NOT REQUIRED*********************************************##

    #Try to check if the tunnel name exists in the tunnel table
    selectQueryString = "SELECT tnl_name FROM tunnel_table WHERE tunnel_table.tnl_name='%s'" % tunnelName
    queryret = cursor.execute(selectQueryString)

    if queryret == False:
        '''
        ##To add the tunnel name to the collector session table or not##
        ##Scenario: the collector command used first even before creating the tunnel and its properties:
        #collector session <collectorid>
        #   (config-collector-sess-1)#  dst tunnel <tunnelName>
        '''
        querystring = "SELECT dst_tnl FROM collector_sess_table where dst_tnl = '%s'" % tunnelName
        queryret = cursor.execute (querystring)
        if bool (queryret) == True:
            addTunnelToCollectorTab(tunnelName, sessId)
            return 1
        else:
            print ('Tunnel does not exist, but has been assigned to another collector session ')
    else:
        ##Scenario: The tunnel name exists, it has been created, may be the properties are set or they can be set later(exit).##
        ##Scenario: The tunnel name check in the collector session table if used by any other session##
        if checkOtherSessTunnel(tunnelName, sessId):

            #If the tunnel is free and it exists it can be used by this session, updating the collector table
            addTunnelToCollectorTab(tunnelName,sessId)

            #The tunnel is already created and now the session will use it, updating tunnel table
            addSesstoTunnelTab(sessId,tunnelName)

            # Check the interface from the session table a
            selectQueryString = "SELECT src_intf FROM collector_sess_table WHERE dst_tnl='%s'" % tunnelName
            portVal = cursor.execute(selectQueryString)

            if portVal != False: #No need to update any tunnel table
                # Update interface in the table: vxlan_tnl_table if it exists in the session table
                portVal = cursor.fetchone()[0]
                updatePortAcess(portVal, tunnelName)

            return 0

        else:
            print ("Some other session is currently using the tunnel")
            return -1

def addSesstoTunnelTab(sessid,tunname):
    global cursor
    insertQueryString = "UPDATE tunnel_table set sess_id = %d WHERE tnl_name=('%s')" % (int (sessid), tunname)
    cursor.execute(insertQueryString)

def addTunnelToCollectorTab(tunnelName,sessid):
    global cursor
    insertQueryString = "UPDATE collector_sess_table set dst_tnl ='%s' WHERE sess_id=%d" % (tunnelName, int(sessid))
    cursor.execute(insertQueryString)

def checkOtherSessTunnel(name,id):
    global cursor
    selectQueryString= "SELECT sess_id FROM collector_sess_table WHERE dst_tnl='%s'" % name
    othSessionVal = cursor.execute(selectQueryString)
    if othSessionVal==False:
        return 1
    elif cursor.fetchone()[0] == id:
        return -1
    else:
        return 0


def checkValidInterface(sourceInt):
    sourceIntFlag = 0
    checkVal=set_config_mode(sourceInt)
    if checkVal == 0: #Valid interface sends 0
        sourceIntFlag=1
        return sourceIntFlag
    else: #Not valid sends -1
        return sourceIntFlag

def updatePortAcess(srcInt,tunname):
    global vxtunprop
    #If the tunnel name exists with a row in vxlan_tnl_table then push the source interface index
    global cursor

    #Check if already interface index is set or not, compare with the one which we are trying to set
    #Extract our interface values's index

    #Flag to check the state of the interface
    interfaceCheck = False

    selectQueryString="SELECT ifindex FROM if_table WHERE name='%s'" % srcInt
    indexVal=cursor.execute(selectQueryString) #Int return ifindex
    if indexVal !=False:
        indexVal=cursor.fetchone()[0]


    #Extract the interface value from vx_tnl_tab
    selectQueryString= "SELECT port_access FROM vxlan_tnl_table WHERE tnl_name='%s'" % tunname
    existingIndexVal=cursor.execute(selectQueryString)
    if existingIndexVal!=False:
        existingIndexVal = cursor.fetchone()[0]

    #Compare both interface indexes
    if indexVal != existingIndexVal: #Two integer equivalence
        #Update the new interface index in the table row
        updateQueryString="UPDATE vxlan_tnl_table SET port_access='%s' WHERE tnl_name='%s'" % (indexVal, tunname)
        #change to update, where tunnelname
        cursor.execute(updateQueryString)
        if interfaceStateVerify(indexVal) == True:
            interfaceCheck = True

    else:
        if interfaceStateVerify(existingIndexVal) == True:
            interfaceCheck = True

    #check other fields are set or not
    checkOthFTblRet = checkOtherFieldsVxlanTbl(tunname)
    checkportAccret = checkPortAccessFieldsVxlanTbl(tunname)
    if bool(checkOthFTblRet)==True and bool(checkportAccret) == True:
        #All fields exist, we can push everything to vxtunprop and send the client call.

        ##**Extract the session_id
        vxtunprop.collector_sess_id = findSessId(tunname)

        #*extracting the dlf_mac from IP multicast address. Taken care of as when we are setting tunnel properties in the db.
        selectQueryString="SELECT * FROM vxlan_tnl_table WHERE tnl_name='%s'" % tunname
        cursor.execute(selectQueryString)
        rowList = cursor.fetchone()

        if interfaceStateVerify(int(rowList[6])) == True and interfaceCheck == True: # The state of source interface is Up, then check the netport

            vxtunprop.tunnel_name = rowList[0] #Although we have the tunname, still we are taking this fromm db
            vxtunprop.vpn = rowList[1] # Fetching the VPN from the table
            vxtunprop.vnid = int(rowList[2]) #vnid extract
            vxtunprop.source_ip_address=rowList[3]
            vxtunprop.destination_ip_address = rowList[4]
            vxtunprop.port_access = int (rowList[5])
            vxtunprop.port_network = int (rowList[6])
            vxtunprop.local_mac_access = rowList[7]
            vxtunprop.remote_mac_access = rowList[8]
            vxtunprop.local_mac_network = rowList[9]
            vxtunprop.remote_mac_network = rowList[10]
            vxtunprop.dlf_mac = rowList[11] #Extracting from the db

            return True #If all the variables are set into vxtunprop, send true back

        else:
            print('\n The interface state of source or networks is not up')
            return False

    else:
        print('\n All properties are not set for the tunnel')
        return False


def checkPortAccessFieldsVxlanTbl(tunname):
    global cursor
    #Check the vnid from the table, if it's set then it's evident that the other fields are also set already
    #And we are checking after getting the tunnel port_access into the table
    selectQueryString = "SELECT port_access FROM vxlan_tnl_table WHERE tnl_name='%s'" % tunname
    pivot = cursor.execute(selectQueryString)
    if pivot == True:
        fetchElement = cursor.fetchone()[0]
        if fetchElement != None :
            return fetchElement
    else :
        return False 
def checkOtherFieldsVxlanTbl(tunname):
    global cursor
    #Check the vnid from the table, if it's set then it's evident that the other fields are also set already
    #And we are checking after getting the tunnel port_access into the table
    selectQueryString = "SELECT vnid FROM vxlan_tnl_table WHERE tnl_name='%s'" % tunname
    pivot = cursor.execute(selectQueryString)
    fetchElement = cursor.fetchone()[0]
    if pivot == True and fetchElement != None :
        return fetchElement
    else :
        return False 



def dstTunnelTest(srcint,sessid):
    global cursor
    #check with the sessid if the tunnel exists or not in the row
    #dst_tnl is a string
    selectQueryString = "SELECT dst_tnl FROM collector_sess_table WHERE sess_id='%s'"%sessid
    selectQueryResult = cursor.execute(selectQueryString)
    if selectQueryResult == True:
        #Means the tunnel is set in the collector table
        #Need to query if such tunnel exists in the tunnel table or not
        selectQueryString = "SELECT tnl_name FROM tunnel_table WHERE tnl_name='%s'"% cursor.fetchone()[0]
        selectQueryResult = cursor.execute(selectQueryString)

        if selectQueryResult == True: #Tunnel with the name exists
            tunnametemp = cursor.fetchone()[0] #String srctint: String
            opTunnelBoardret= updateTnlTab(srcint, tunnametemp)
            return (opTunnelBoardret)



def updateTnlTab(srcint,tunname):
    updatePortRet = updatePortAcess(srcint,tunname) #Send the resul
    return (updatePortRet)

##******************no Tunnel section*********##                                                     
def deleteTnlFromMonetdb(tunname):
    global cursor

    ###Delete record from tunnel table                                                           
    deleteQueryString = "DELETE FROM tunnel_table WHERE tnl_name='%s'" % tunname                 
    cursor.execute(deleteQueryString)                                                            
    deleteQueryString = "DELETE FROM vxlan_tnl_table WHERE tnl_name='%s'" % tunname              
    cursor.execute(deleteQueryString)                                                            


def verifyTunnel(tunname):                                                                       
    global vxtunprop                                                                                 
    global cursor 
    selectQueryString = "SELECT tnl_name FROM tunnel_table WHERE tnl_name='%s'" % tunname            
    pivot = cursor.execute(selectQueryString)
    if bool(pivot) == True:                  
        selectQueryString = "SELECT dst_tnl from collector_sess_table where dst_tnl = '%s'" % tunname
        pivot = cursor.execute (selectQueryString)
        if bool (pivot) == True:                                                             
            vxtunprop.tunnel_name = tunname                                                              
            return 1 
        else:
            return -1                                                                                    
    else:                                                                                            
        return 0                                                                                     
                                                                                                     
##******************no Tunnel section*********##                                                     

##******************CollectorTunnel no section*********##

def delSessTabRow(sessid):
    global cursor
    deleteQueryString = "DELETE FROM collector_sess_table WHERE sess_id=%d" % int(sessid)
    return(cursor.execute(deleteQueryString))

def deleteSessIdTnlTbl(sessid):
    global cursor
    selectQueryString = "SELECT tnl_name FROM tunnel_table WHERE sess_id=%d" % int(sessid)
    queryret = cursor.execute(selectQueryString)
    if bool (queryret) == True:
        tnlname = cursor.fetchone()[0]
        if bool(tnlname) == True:
            updateQueryString = "UPDATE tunnel_table SET sess_id=Null WHERE tnl_name='%s'" % tnlname
            cursor.execute(updateQueryString)
            return tnlname
    else:
        return 0

##******************CollectorTunnel section*********##

##******************Tunnel section*********##

def checkTnlTab(name):
    global cursor
    selectQueryString = "SELECT tnl_name FROM tunnel_table WHERE tnl_name='%s'" % name
    queryVal = cursor.execute(selectQueryString)

    if queryVal == False:
        return 0
    else:
        return 1

def checkVxlanTnlTab(name):
    global cursor
    selectQueryString = "SELECT tnl_name FROM vxlan_tnl_table WHERE tnl_name='%s'" % name
    queryVal = cursor.execute(selectQueryString)

    if queryVal == False:
        return 0
    else:
        return 1

def checkCollSessTabForTun(tunnel_name):
    global cursor
    selectstring = "SELECT sess_id from Collector_sess_table where dst_tnl = '%s'" % tunnel_name
    pivot = cursor.execute(selectstring)
    if pivot == True :
        sessId = cursor.fetchone()[0]
        updateQueryString = "UPDATE tunnel_table SET sess_id =%d WHERE tnl_name = '%s'" %(int(sessId), tunnel_name)
        cursor.execute (updateQueryString)
        selectQueryString = "SELECT src_intf FROM collector_sess_table WHERE sess_id = %d" % int(sessId)
        pivot1 = cursor.execute (selectQueryString)
        if pivot1 == True :
            src_intf = cursor.fetchone()[0]
            ifindex = ifIndexNetPort (src_intf)
            crVxlanTab (tunnel_name, ifindex)

def crupdateTnlTab(tunName, tunType):

    global cursor
    execFlag= 0 #Execution flag

    tnlXistFlag = checkTnlTab(tunName)

    if tnlXistFlag == False:
        # Tunnel row doesn't exist, create one row and push the type and tunnel_name
        insertQueryString = "INSERT INTO tunnel_table (tnl_name,tnl_type) VALUES ('%s',%d)" % (tunName, int (tunType))
        dropVal = cursor.execute(insertQueryString)

        insertQueryString = "INSERT into vxlan_tnl_table (tnl_name) VALUES ('%s')" %tunName
        dropVal = cursor.execute (insertQueryString)
        checkCollSessTabForTun (tunName)
        execFlag = 1

    elif tnlXistFlag == True:
        #Tunnel only exists, so we have to verify the type, so extract the type from the table
        selectQueryString = "SELECT tnl_type FROM tunnel_table WHERE tnl_name='%s'" % tunName
        typeVal = cursor.execute(selectQueryString)
        typeVal = cursor.fetchone()[0]

        #Compare the type provided by the client and the type extracted out from the table.
        if tunType != typeVal:
            updateQueryString = "UPDATE tunnel_table SET tnl_type= '%s' WHERE tnl_name='%s'" % (tunType, tunName)
            cursor.execute(updateQueryString)
            execFlag = 2

        elif tunType == typeVal:
            execFlag = 3
    return execFlag

def crVxlanTab(tunName, ifindex):
    global  cursor
    tnlXistFlag = checkVxlanTnlTab(tunName)
    if tnlXistFlag == 1:
        updateQueryString = "UPDATE vxlan_tnl_table SET port_access=%d WHERE tnl_name = '%s'" %(int(ifindex), tunName)
        cursor.execute (updateQueryString)

    elif tnlXistFlag==0:
        pass

def interfaceStateVerify(ifIndex):
    global cursor
    selectQueryString = "select link_state from if_table where ifindex = %d" % ifIndex
    pivot = cursor.execute(selectQueryString)
    if pivot == True: #Basically don't reqquire this
        state = cursor.fetchone()[0]
        if bool(state) == True:
            return True
        else:
            return False

def updateVxlanTab(*args):
    global cursor
    global vxtunprop

    paramCheck= True #Flag to check if all the parameters are proper or not
    dlfmacMandate = False #dlfmacmandate tracks the destination ip address and if multicast, gen multicast mac addr


    # If the either of these two flags are false, that verifies that the info is not on bcm chip, no need to send delete
    modifyOthParamsCheck = False #If the modify flag is true then the properties in the row were set and now needs to be modified
    sourceIntCheck = True  # Source Interface Check flag
    interfaceState = False #True means up and False means down
    #interfaceIndexExistCheck = False  #Check if the ifindex exists already in the vxlantab

    paramArgs = (list(args[0]))

    #tunnelName = paramArgs[9]
    #Just checking if the values are already set into the vxlan table, if both flags are true, then send delete
    #modifyOthParamsCheck = checkOtherFieldsVxlanTbl(tunnelName)
    #interfaceIndexExistCheck = findPortAccess(tunnelName)

    ##All props init
    tunnel_name=collector_sess_id=vnid=port_access=port_network=dlf_mac=source_ip_address=destination_ip_address=local_mac_access\
    =remote_mac_access=local_mac_network=remote_mac_network=None

    ##Put any checks needed, if found wrong, put paramCheck flag to False
    if paramCheck == True:
        ##Check if the string is empty or not
        #No need of a check, while creating the row we have already made sure the tunnel name is checked for the empty string
        tunnel_name = paramArgs[9]
        modifyOthParamsCheck = checkOtherFieldsVxlanTbl(tunnel_name)

    if paramCheck == True:
        sessId = findSessId(paramArgs[9])
        if bool(sessId) == True and int(sessId) != 0: #Should be digit but not 0
            collector_sess_id = sessId
        else:
            print('\n the session id has not been set')

    #vpn is auto configured in db and hence not in the client structure

    #Well the session may not be there, check if we have a session id

    if paramCheck == True:
        if paramArgs[0].isdigit() == True:
            vnid = paramArgs[0]
        else:
            paramCheck = False

    #IP Address and mac are checked at the command line, can't be empty
    if paramCheck == True:
            # if multicast there, dlf_mac mandatory
        if bool(checkMultcastAddress(paramArgs[2])):
            dlfmacMandate = True

    if paramCheck == True:
        #Send IP addresses received to the db and hex to the board
        source_ip_address = paramArgs[1]
        destination_ip_address = paramArgs[2] #For the time being we are passing just one element here

        remote_mac_access = paramArgs[4]
        local_mac_access = paramArgs[3]
        remote_mac_network = paramArgs[6]
        local_mac_network = paramArgs[5]

    if paramCheck ==True:
        # No more asking for mac from the user end, we are generating the mac address from the destination ip address only
        # dlf_mac is optional if the dlfmacMandate flag is False, otherwise it should be given.
        # For now ignore the paramargs[8] element.
        if dlfmacMandate == True:
            #generate multicast mac frm multicast ip addr
            mcast_mac ="01:00:5e:"

            octets = paramArgs[2].split(".")

            second_oct = int(octets[1]) & 127

            third_oct = int(octets[2])

            fourth_oct = int(octets[3])

            mcast_mac = mcast_mac + "%s:%s:%s" %(format(second_oct,"02x"), format(third_oct, "02x") , format(fourth_oct, "02x"))
            dlf_mac = mcast_mac

        elif dlfmacMandate== False:
            mcast_mac = ""
            dlf_mac = mcast_mac

    if paramCheck==True:
        #Index is fetched from table, can be empty if the tunnel is built at first and session afterwards
        tunnel_name = paramArgs[9]
        port_access_ret = findPortAccess(tunnel_name)
        if bool(port_access_ret) == False:
            sourceIntCheck = False
        elif bool(port_access_ret) == True:
            port_access = port_access_ret
            if interfaceStateVerify(port_access) == True:
                interfaceState = True
            

    if paramCheck==True:
        #Check the valid network interface and get the index value of the interface
        checkNetworkInt = checkValidInterface(paramArgs[7])
        if (checkNetworkInt == 1):
            ifVal = ifIndexNetPort(paramArgs[7])
            port_network = ifVal
            if interfaceStateVerify(ifVal) == True and interfaceState == True:
                interfaceState = True

        else:
            print('\n Not a valid interface')
            paramCheck = False

    if modifyOthParamsCheck == True and sourceIntCheck == True and paramCheck == True:
        # If we are at all trying to modify the details of the tunnel, the above three flags should be true
        # And then we can send delete to the board
        # Use yield instead of return for the function to carry on execution
        #First drop the table row and then call for the delete from the BCM board using the delete function

        #send only the tunnel value
        vxtunprop.tunnel_name = tunnel_name
        yield -1
        
    if paramCheck == True and sourceIntCheck == True:

        # We have to update the table and even have to yield a value which will call create

        insertQueryString = "UPDATE vxlan_tnl_table SET vnid = '%s',src_ip = '%s',dst_ip = '%s',port_dst = '%s'\
        ,local_mac_access = '%s',remote_mac_access = '%s',local_mac_network = '%s',remote_mac_network = '%s',dlf_mac = '%s'\
         WHERE vxlan_tnl_table.tnl_name='%s'"\
        % (vnid, source_ip_address, destination_ip_address, port_network, local_mac_access, remote_mac_access, local_mac_network,
           remote_mac_network, dlf_mac, tunnel_name)

        cursor.execute(insertQueryString)

        if port_access == True and interfaceState == True:
            insertQueryString = "UPDATE vxlan_tnl_table SET port_access = '%s' WHERE tnl_name = '%s' " % (port_access, tunnel_name)
            cursor.execute(insertQueryString)
        #Setting values in the vxprop struct

        vxtunprop.tunnel_name=tunnel_name
        vxtunprop.collector_sess_id= collector_sess_id
        vxtunprop.vnid= int (vnid)
        # Convert the IP address to the hex before sending to the board
        vxtunprop.source_ip_address= "0x" + binascii.hexlify(socket.inet_aton(source_ip_address)).decode("utf-8")
        vxtunprop.destination_ip_address= "0x" + binascii.hexlify(socket.inet_aton(destination_ip_address)).decode("utf-8")
        vxtunprop.port_access=int (port_access)
        vxtunprop.port_network=int (port_network)
        vxtunprop.remote_mac_access=remote_mac_access
        vxtunprop.local_mac_access=local_mac_access
        vxtunprop.remote_mac_network=remote_mac_network
        vxtunprop.local_mac_network=local_mac_network
        if dlfmacMandate == True:
            vxtunprop.dlf_mac=dlf_mac
    
        yield 1

    elif paramCheck == False:
        # 2 defines something is wrong with the provided parameters
        # 1 means all of them are set, need to send create to the BCM
        #-1 means we need to send delete to the BCM only with a tunnel name
        # 0 means the source interface is not set till now, so update the entries if they are working well
        yield 2


    elif paramCheck==True and sourceIntCheck==False:

        #Tunnel is first created with all params fine
        #Only source interface is not present in the session table
        insertQueryString = "UPDATE vxlan_tnl_table SET vnid = %d ,src_ip = '%s',dst_ip = '%s',port_dst = %d\
        ,local_mac_access = '%s',remote_mac_access = '%s',local_mac_network = '%s',remote_mac_network = '%s',dlf_mac = '%s'\
         WHERE vxlan_tnl_table.tnl_name='%s'"\
        % (int(vnid), source_ip_address, destination_ip_address, int(port_network), local_mac_access, remote_mac_access, local_mac_network,
           remote_mac_network, dlf_mac, tunnel_name)

        cursor.execute(insertQueryString)


        yield 0


def ifIndexNetPort(netInt):
    global cursor
    global collector_list
    selectQueryString = "SELECT ifindex FROM if_table WHERE name='%s'" % netInt
    indexVal = cursor.execute(selectQueryString)
    indexVal = cursor.fetchone()[0]
    return indexVal

def checkMultcastAddress(ipaddr):
    multiCastSig = 0
    ipaddrstr = ipaddr.strip()
    ip_address_split = ipaddrstr.split(".")
    ip_address_length = len(ip_address_split)

    firstOctet = ip_address_split[0]

    if int(firstOctet)>=224 and int(firstOctet)<=239:
        multiCastSig = 1
    return multiCastSig



def findSessId(tunName):
    global cursor
    selectQueryString = "SELECT sess_id FROM collector_sess_table WHERE dst_tnl='%s'" % tunName
    retval = cursor.execute(selectQueryString)
    if bool(retval) == True:
        sessId = cursor.fetchone()[0]
        return sessId
    else :
        return 0


def findPortAccess(tunName):
    global cursor
    selectQueryString = "SELECT port_access FROM vxlan_tnl_table WHERE tnl_name='%s'" % tunName
    cursor.execute(selectQueryString) #can be empty , case check
    port_acc = cursor.fetchone()[0]
    return port_acc

##******************Tunnel section*********##


def set_mtu(port_name,mtu_value):
    global ret
    global ifprop
    global cursor
    if int(mtu_value) < 1500 or int(mtu_value) > 9412:
       print 'MTU is not in range(1500-9412)'
       return -1
    ifprop.port = port_name
    ifprop.mtu = int(mtu_value)
    selectstring = "SELECT mtu  FROM if_table where name='%s'"%(port_name)
    ret = cursor.execute(selectstring)
    ret = cursor.fetchone()[0]
    if ret == ifprop.mtu:
       print 'No Modification required to MTU'
       return -1
    return 0

def set_autonego(port_name,autonego_value):
    global ret
    global ifprop
    global cursor
    ifprop.port = port_name
    ifprop.autonego = int(autonego_value)
    selectstring = "SELECT autonego  FROM if_table where name='%s'"%(port_name)
    ret = cursor.execute(selectstring)
    ret = cursor.fetchone()[0]
    if ret == ifprop.autonego:
       print 'No Modification required to autonego'
       return -1
    return 0     
 
def set_config_mode(port_name):
       global ret
       global ifprop
       global cursor
       selectstring = "SELECT * FROM if_table where name='%s'"%(port_name)
       ret = cursor.execute(selectstring)
       if ret == False:
          print 'Invalid Interface Name'  
          return -1 
       return 0

def set_speed(port_name,speed_value):
    global ret
    global ifprop
    global cursor
    ifprop.port = port_name
    port_list = re.split('(\d+)',port_name)
    port_number = port_list[1]
    speed_value = speed_value.upper()
    speed_list = re.split('(\d+)',speed_value)
    value = int(speed_list[1])   
    char = speed_list[2]

    if char == 'G':
        factor = 1000
        if port_number < 48:
            if value > 10:
                print 'Invalid speed(max speed is 10 G)'
                return -1
        else:
            if port_number > 48:
                if value > 40 :
                    print 'Invalid speed(max speed is 40G)'
                    return -1
    elif char == 'M':
        factor = 100
        if value < 10:
            print ('Invalid speed(min speed is 10M)')
            return -1
    else:
        print 'Invalid speed range(10M-40G)'
        return -1
    ifprop.speed = value * factor
    selectstring = "SELECT speed  FROM if_table where name='%s'" % port_name
    ret = cursor.execute(selectstring)
    ret = cursor.fetchone()[0]
    if ret == ifprop.speed:
        print 'No Modification required to Speed'
        return -1
    return 0

def set_shutdown (port_name):
    global ret
    global ifprop
    global cursor
    ifprop.port = port_name
    ifprop.enable = 0
    selectstring = "SELECT enable  FROM if_table where name='%s'"% port_name
    ret = cursor.execute(selectstring)
    ret = cursor.fetchone()[0]
    if ret == ifprop.enable:
       print 'No Modification required to Shutdown'
       return -1
    return 0

def set_noshutdown(port_name):
    global ret
    global ifprop
    global cursor
    ifprop.port = port_name
    ifprop.enable = 1
    selectstring = "SELECT enable  FROM if_table where name='%s'"%(port_name)
    ret = cursor.execute(selectstring)
    ret = cursor.fetchone()[0]
    if ret == ifprop.enable:
       print 'No Modification required to NoShutdown'
       return -1
    return 0
    
def main(argv):
    global cursor
    global ifprop
    global vxtunprop
    global ret
    global vxret
    global collector_list

    collSessRet = 100
    collSessId = ''

    connection = pymonetdb.connect(username="monetdb", password="monetdb", hostname="localhost", database="voc")
    connection.set_autocommit(True)
    cursor = connection.cursor()
    cursor.arraysize = 100
    # Make socket
    transport = TSocket.TSocket('localhost', 34532)
    # Buffering is critical. Raw sockets are very slow
    transport = TTransport.TBufferedTransport(transport)

    # Wrap in a protocol
    protocol = TBinaryProtocol.TBinaryProtocol(transport)

    # Create a client to use the protocol encoder
    client = aev_config.Client(protocol)

    # Connect!
    transport.open()

    client.ping()
    #print('ping()')

    try:
        #DOCUMENTATION USAGE COMPRESSED SECTION#
        '''
        //Documentation
        //Usage of the parsing of getopt
        
        //Sample run of the function:
        
        ******************
        
        import getopt
        import sys
        
        version = "1.0"
        verbose = False
        output_filename = 'default.out'
        first_arg=""
        second_arg=""
        third_arg=""


        print ("arguments  :   " + str(sys.argv[1:]))
        
        options, remainder = getopt.getopt(sys.argv[1:], "o:", ['output=',
                                                         'verbose',
                                                         'version=',
                                                        'i1=',
                                                        'i2=',
                                                        'i3='
                                                         ])
        print ("OPTIONS   : "+ str(options))
        
        for opt, arg in options:
            if opt in ('-o', '--output'):
                output_filename = arg
            elif opt in ('-v', '--verbose'):
                verbose = True
            elif opt == '--version':
                version = arg
            elif opt in ('--i1'):
                first_arg = arg
            elif opt in ('--i2'):
                second_arg= arg
            elif opt in ('--i3'):
                third_arg = arg;
        
        print ('VERSION   :'+ version )
        print ('VERBOSE   :' )
        print(verbose )
        print ('OUTPUT    :'+ output_filename )
        print ('REMAINING :'+ str(remainder) )
        print ('i1' + first_arg)
        print('i2' + second_arg)
        print('i3' + third_arg)
        ******************

        //The output tells us about the must or mandatory arguments starts with '-' and optional '--' and the second list is about 
        some other arguments passed without - or -- usage.
        
        
        '''

        opts, args = getopt.getopt(argv,"m:c:n",["i1=","i2=","i3=","i4=","i5=","i6=","i7=","i8=","i9=", "i10="])

       #opts, args = getopt.getopt(argv,"hi:j:m:c:",["ifile=","ofile="])

    except getopt.GetoptError:
       print 'test.py -i <inputfile> -o <outputfile>'
       sys.exit(2)

    no = 0

    '''
    All the params passed by the clish are in the local scope of main function.
    '''
    param1=param2=param3=param4=param5=param6=param7=param8=param9=param10=None
    mode=command=None

    for opt, arg in opts:
       if opt in ("--i1"):
          param1 = arg
       elif opt in ("--i2"):
          param2 = arg
       elif opt in ("--i3"):
          param3 = arg
       elif opt in ("--i4"):
           param4 = arg
       elif opt in ("--i5"):
           param5 = arg
       elif opt in ("--i6"):
           param6 = arg
       elif opt in ("--i7"):
           param7 = arg
       elif opt in ("--i8"):
           param8 = arg
       elif opt in ("--i9"):
           param9 = arg
       elif opt in ("--i10"):
           param10 = arg


       elif opt in ("-m"):
          mode = arg
       elif opt in ("-c"):
          command = arg
       elif opt in ("-n"):
          no = arg

    if mode == 'enable':

        if command == 'show_iface':
            selectstring = "SELECT * FROM if_table"
            cursor.execute(selectstring)
            print cursor.fetchmany()

        elif command == 'shcollsession':
            shoRet = collectorShowInfo()
            if shoRet == False:
                print ("\n No information available on collector")

        elif command == 'shtuninfo':
            tunName = param1
            shoRet = tunnelShowInfo()
            if shoRet == False:
                print ("\n No information available on tunnel")


    elif mode == 'config':
        '''
        If the mode is config and command is collsession, we call collector_session_check(sessionId)
        '''
        if command == "collsession":
            #Checked as int at CLI only
            collSessRet = collector_session_check(param1)

        elif command == "delcollsession":
            vxtunprop = aev_vxlan_tunnel_prop()
            delSessId = param1
            if (bool(delSessId)) == True :
                #Acts to be performed:
                #1.Delete the session id row
                #2.Delete the session id from the tunnel table
                #3.Send delete to the board for aev
                delSessTabRow(delSessId)
                tunnelName = deleteSessIdTnlTbl(delSessId)
                if bool(tunnelName) ==True:
                    vxtunprop.tunnel_name = tunnelName
                    example = client.aev_vxlan_tunnel_remove(1, vxtunprop)

        elif command == "deltunnel":                                                    
            vxtunprop = aev_vxlan_tunnel_prop()                                         
            delTunnelName = param1                                                      
            ##Send command to delete both table rows in case the tunnel name exists     
            deleteRet = verifyTunnel(delTunnelName)                                 
            if bool(deleteRet) == True and deleteRet != -1:                                                       
            #send delete to the BCM server       
                vxtunprop.tunnel_name = delTunnelName                           
                retval = client.aev_vxlan_tunnel_remove(1, vxtunprop)            
                if retval == True:
                    deleteTnlFromMonetdb(delTunnelName)
            elif deleteRet == -1:
                deleteTnlFromMonetdb (delTunnelName)                     
                                                                                
            elif deleteRet == False:                                                    
                print('\n Such a tunnel name do not exists, please check the input')    


        elif command == "iface":
            ret = set_config_mode(param1)

        elif command == "tunnel":
            tunName = param2
            tunType = param1

            if (bool(str(tunName).strip())) == False or str(tunName).strip() == '':
                print('\n The tunnel name is not as per the sepcification')
            if tunType == 'vxlan':
                tunType = 1
            flag = crupdateTnlTab(tunName, tunType)


    elif mode == "config-iface":
       ifprop = aev_if_prop()
       if command == 'speed':
          ret = set_speed(param1,param2)
       elif command == 'shutdown':
          ret = set_shutdown(param1)
       elif command == 'noshutdown':
          ret = set_noshutdown(param1)
       elif command == 'mtu':
          ret = set_mtu(param1,param2)
       elif command == 'autonego':
          ret =  set_autonego(param1,param2)

          if ret == 0:
              example = client.aev_if_prop_update(1, ifprop)

    elif mode == "config_collector_sess":

        if command=="dest_tunnel":
            collSessId = param2 #Int
            tunName = param1 #String
            srcVlan = 0 #Int
            destTunnelRet = dstTunnelName(tunName, srcVlan, collSessId)

            if destTunnelRet==2:
                print("\n The tunnel cannot be set as the source interface has not been found in the session table row")
            elif destTunnelRet==-1:
                print("\n Tunnel exists but currently in use by other session")



        elif command=="sourceint":
            vxtunprop = aev_vxlan_tunnel_prop()
            collSessId = param2 #integer
            sourceInt = param1 #subcommand string

            #Check valid source interface or not
            sourceIntRet= checkValidInterface(sourceInt)

            #If the sourceIntRet is true as it should receive 1
            if sourceIntRet==True:
                #If the source interface is valid and free, try to update into collector table
                intSessRel = modifyNewCollectorTable(sourceInt, collSessId)

                if intSessRel == 0 or intSessRel == 1:
                    #Check destination tunnel is set or not, if it is we need to chec the ifindex or update it
                    dstTunnelTestRet = dstTunnelTest(sourceInt, collSessId)

                    if dstTunnelTestRet==True:
                        #True will be sent only if the vxtunprop is set by the method.
                        example = client.aev_vxlan_tunnel_create(1, vxtunprop)


                elif intSessRel == -1:
                    print("\n Can't help, somebody else is using it")

            elif sourceIntRet==False:
                print("Not a valid interface selected")

    elif mode=="config-tunnel":

        vxtunprop = aev_vxlan_tunnel_prop()

        if command == "tunnelprop":

            param = list()
            param.append(param1)
            param.append(param2)
            param.append(param3)
            param.append(param4)
            param.append(param5)
            param.append(param6)
            param.append(param7)
            param.append(param8)
            param.append(param9)
            param.append(param10)

            for vxretobj in updateVxlanTab(param):
                # 2 defines something is wrong with the provided parameters
                # 1 means all of them are set, need to send create to the BCM
                # -1 means we need to send delete to the BCM only with a tunnel name
                # 0 means the source interface is not set till now, so update the entries if they are working well
                if vxretobj == 0:
                    print('\n The values except the source interface has been updated into vx_tnl_tbl')

                if vxretobj == -1:
                    example = client.aev_vxlan_tunnel_remove(1, vxtunprop)
                    if example == True:
                        deleteQueryString = "DELETE FROM vxlan_tnl_table WHERE vxlan_tnl_table.tnl_name='%s'" % vxtunprop.tunnel_name
                        cursor.execute(deleteQueryString)


                if vxretobj == 1:
                    example = client.aev_vxlan_tunnel_create(1, vxtunprop)

                if vxretobj == 2:
                    print("\n Something is wrong with provided parameters")

    connection.close()
    transport.close()

if __name__ == "__main__":
   try: 
      main(sys.argv[1:])
   except Thrift.TException as tx:
      print("MonetDB or aev_os is not running")
#if __name__ == '__main__':
#    try:
#        main()
#    except Thrift.TException as tx:
#        print('%s' % tx.message)

