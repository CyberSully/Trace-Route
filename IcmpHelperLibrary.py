# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


#   Works Cited for program by Brett Sullivan, on 2-07-24: 

#   https://www.geeksforgeeks.org/traceroute-implementation-on-python/ 
#   https://pythonawesome.com/a-simple-command-line-tracert-implementation-in-python-3-using-icmp-packets/
#   https://www.youtube.com/watch?v=zesTvBZCESk&t=1041s 
#   https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
#   https://obkio.com/blog/how-to-measure-packet-loss/#:~:text=Calculate%20the%20packet%20loss%20rate,total%20number%20of%20packets%20transmitted 


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live
        _rtt = 0                        # round trip time 
        _packetLoss = False             #bool for packet loss 

        __DEBUG_IcmpPacket = False      # Allows for debug output !!!!!!!!!SHOWS CHECKSUM OUTPUT!!!!!!!!!

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getRTT(self):                   #added get function for rtt
            return self.__rtt
        
        def getPacketLoss(self):            #added get function for packet loss 
            return self.__packetLoss
        
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setRTT(self, rtt):              #added set function for rtt
            self.__rtt = rtt

        def setPacketLoss(self, packetLoss):   #added set function for packet loss
            self.__packetLoss = True
        
        
        
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):    # no changes needed for this function 
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self): #no changes needed for this function
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm (looks like the link doesn't work any more so check below) 
            # https://web.archive.org/web/20220414173629/http://www.networksorcery.com/
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):  # no changes needed for this function
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self): # no changes needed for this function
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value
            
            #~~~~~~~~~~UPDATED~~~~~~~~~~~~~~~~~~~~~~~~~~~~start

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            valid_response = True

            # Compare sequence numbers and identify if valid
            if self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber():
                valid_response = True
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)
            else:
                valid_response = False
                icmpReplyPacket.setIcmpSequenceNumber_isValid(False)
                print("Expected sequence number: {}".format(self.getPacketSequenceNumber()))
                print("Actual sequence number: {}".format(icmpReplyPacket.getIcmpSequenceNumber()))

            # Compare packet identifers and identify if valid
            if self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier():
                valid_response = True
                icmpReplyPacket.setIcmpIdentifier_isValid(True)
            else:
                valid_response = False
                icmpReplyPacket.setIcmpIdentifier_isValid(False)
                print("Expected packet identifer: {}".format(self.getPacketIdentifier()))
                print("Actual packet identifer: {}".format(icmpReplyPacket.getIcmpIdentifier()))

            # Compare raw data and identify if valid
            if self.getDataRaw() == icmpReplyPacket.getIcmpData():
                valid_response = True
                icmpReplyPacket.setIcmpData_isValid(True)
            else:
                valid_response = False
                icmpReplyPacket.setIcmpData_isValid(False)
                print("Expected raw data: {}".format(self.getDataRaw()))
                print("Actual raw data: {}".format(icmpReplyPacket.getIcmpData()))
                
            if valid_response == True:
                icmpReplyPacket.setIsValidResponse(valid_response)
            else:
                icmpReplyPacket.setIsValidResponse(valid_response)
                self.setPacketLoss() 
            
            # Hint: Work through comparing each value and identify if this is a valid response.
            #icmpReplyPacket.setIsValidResponse(True)
            #pass
            #~~~~~~~~~~UPDATED~~~~~~~~~~~~~~~~~~~~~~~~~~~~finish, ran ok


        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()
            
            #Updated sendEchoRequest Function ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~start 

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                self.setRTT((timeReceived - pingStartTime) * 1000) # ~~~~~added line to set RTT ~~~~~~~~~
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:                          # Time Exceeded
                        print("ICMP Type 11 -- Time Exceeded")
                        if icmpCode == 0:
                            print("Time to Live exceeded in Transit")
                        elif icmpCode == 1:
                            print("Fragment Reassembly Time Exceeded")

                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    Current IP:%s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )
                        
                

                    elif icmpType == 3:                         # Destination Unreachable 
                        print("ICMP Type 3 -- Destination Unreachable")  #reference used for codes https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
                        if icmpCode == 0:
                            print("Net Unreachable")
                        elif icmpCode == 1:
                            print("Host Unreachable")
                        elif icmpCode == 2:
                            print("Protocol Unreachable")
                        elif icmpCode == 3:
                            print("Port Unreachable")
                        elif icmpCode == 4:
                            print("Fragmentation Needed and Don't Fragment was Set")
                        elif icmpCode == 5:
                            print("Source Route Failed")
                        elif icmpCode == 6:
                            print("Destination Network Unknown")
                        elif icmpCode == 7:
                            print("Destination Host Unknown")
                        elif icmpCode == 8:
                            print("Source Host Isolated")
                        elif icmpCode == 9:
                            print("Communication with Destination Network is Administratively Prohibited")
                        elif icmpCode == 10:
                            print("Communication with Destination Host is Administratively Prohibited")
                        elif icmpCode == 11:
                            print("Destination Network Unreachable for Type of Service")
                        elif icmpCode == 12:
                            print("Destination Host Unreachable for Type of Service")
                        elif icmpCode == 13:
                            print("Communication Administratively Prohibited")
                        elif icmpCode == 14:
                            print("Host Precedence Violation")
                        elif icmpCode == 15:
                            print("Precedence cutoff in effect") 
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )

                    elif icmpType == 0:                         # Echo Reply
                        print("ICMP Type 0 ~~ Echo Reply")      # added prints, following 3 lines ~~~~~~~~~~~~~~~~
                        if icmpCode == 0:
                            print("Icmp code is 0")
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        
                        # Get packet values for printResultToConsole()
                        expectedPacketSequenceNumber = self.getPacketSequenceNumber()
                        expectedPacketIdentifier = self.getPacketIdentifier()
                        expectedDataRaw = self.getDataRaw()
                        expected = [expectedPacketSequenceNumber, expectedPacketIdentifier, expectedDataRaw]
                        
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr, expected)
                        self.setRTT(icmpReplyPacket.getRTT())
                        return      # Echo reply is the end and therefore should return

                    else:
                        print("error")
                        self.setPacketLoss()
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        #Updated sendEchoRequest Function ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~finish 

        def printIcmpPacketHeader_hex(self): # no changes to function 
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):  # no changes to function 
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):  # no changes to function 
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        __IcmpSequenceNumber_isValid = False        # 4 declared/updated variables here
        __IcmpIdentifier_isValid = False
        __IcmpData_isValid = False
        __rtt = 0

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        def getIcmpSequenceNumber_isValid(self):            # 4 new echo getters made ~~~~~~~~~~~~~~~~~~~~~~
            return self.__IcmpSequenceNumber_isValid

        def getIcmpIdentifier_isValid(self):
            return self.__IcmpIdentifier_isValid

        def getIcmpData_isValid(self):
            return self.__IcmpData_isValid

        def getRTT(self):
            return self.__rtt

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpSequenceNumber_isValid(self, booleanValue):      # 4 new echo Setters made ~~~~~~~~~~~~~~~~~~~~~~
            self.__IcmpSequenceNumber_isValid = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            self.__IcmpIdentifier_isValid = booleanValue

        def setIcmpData_isValid(self, booleanValue):
            self.__IcmpData_isValid = booleanValue

        def setRTT(self, rtt):
            self.__rtt = rtt
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        
         #~~~~~~~~~~UPDATED~~~~~~~~~~~~~~~~~~~~~~~~~~~~start
        
        def printResultToConsole(self, ttl, timeReceived, addr, expected):  # Added new parameter for comparision with expected values
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            rtt = (timeReceived - timeSent) * 1000
            self.setRTT(rtt)
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      rtt,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                 )
            
            # Print valid or error message for sequence number
            if self.getIcmpSequenceNumber_isValid():
                print("Sequence number is valid")
            else:
                print("Expected sequence number: {}".format(expected[0]))
                print("Actual sequence number: {}".format(self.getIcmpSequenceNumber()))

            # Print valid or error message for packet identifier
            if self.getIcmpIdentifier_isValid():
                print("Packet identifier is valid")
            else:
                print("Expected packet identifer: {}".format(expected[1]))
                print("Actual packet identifer: {}".format(self.getIcmpIdentifier()))

            # Print valid or error message for raw data
            if self.getIcmpData_isValid():
                print("Raw data is valid")
            else:
                print("Expected raw data: {}".format(expected[2]))
                print("Actual raw data: {}".format(self.getIcmpData()))
            
         #~~~~~~~~~~UPDATED~~~~~~~~~~~~~~~~~~~~~~~~~~~~finish 
            

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False               # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    # Citation for sendIcmpEchoRequestfunction:
    # Date: 02/08/2024
    
    # Source URL: https://obkio.com/blog/how-to-measure-packet-loss/#:~:text=Calculate%20the%20packet%20loss%20rate,total%20number%20of%20packets%20transmitted 
    
    #~~~~~~~~~~~~~~~~~~~~~~~UPDATED __sendIcmpEchoRequest function  ~~~~~~~~~~~~~~~~~~~~~~~~START
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") 

        RTT_list = []
        packetsLost = 0
        requests = 4
 
        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()                                                # Build IP

            if icmpPacket.getPacketLoss():
                packetsLost += 1
            RTT_list.append(icmpPacket.getRTT())

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data
            print("{} packets transmitted".format(requests))
            print("{} received".format(requests - packetsLost))
            print("{}% packet loss".format((packetsLost / requests) * 100))
            print("RTT Minimum = {}".format(round(min(RTT_list))))
            print("RTT Maximum = {}".format(round(max(RTT_list))))
            print("RTT Average = {}".format(round(sum(RTT_list) / len(RTT_list))))
        
        
        #~~~~~~~~~~~~~~~~~~~~~~~UPDATED __sendIcmpEchoRequest function  ~~~~~~~~~~~~~~~~~~~~~~~~FINISH
        
        #~~~~~~~~~~~~~~~~~~~~~~~UPDATED CODE RUNS OK ~~~~~~~~~~~~~~~~~~~~~~~~START
        
    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") 
        # Build code for trace route here

        hops = 30
        for i in range(1, hops):
            # Build packet
            print("Hop: ", i)
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setTtl(i)
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()                                                # Build IP 
            # Build IP
    
    #~~~~~~~~~~~~~~~~~~~~~~~UPDATED CODE RUNS OK ~~~~~~~~~~~~~~~~~~~~~~~~FINISH

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    
    #original sendPing function below
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") 
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()


    # Choose one of the following by uncommenting out the line
    #icmpHelperPing.sendPing("209.233.126.254")
    #icmpHelperPing.sendPing("www.google.com")
    #icmpHelperPing.traceRoute("gaia.cs.umass.edu")
    #icmpHelperPing.traceRoute("164.151.129.20")                # this is the main one being used for implementation
    #icmpHelperPing.traceRoute("122.56.99.243")
    #icmpHelperPing.sendPing("122.56.99.243")
    
    #icmpHelperPing.traceRoute("209.233.126.254")               # Continent 1 website
    icmpHelperPing.traceRoute("www.freecodecamp.org")          # Some other interesting website
    #icmpHelperPing.traceRoute("www.google.com")                # Google homepage 
    #icmpHelperPing.traceRoute("8.8.8.8")                       # Google 
    
    # 4 different countries to test ~~~~
    #icmpHelperPing.traceRoute("103.102.221.255")               # IP in Afghanistan 102.38.235.0 Continent 1 website
    #icmpHelperPing.traceRoute("102.38.235.0")                  # IP in Guatemala # Continent 2 website
    #icmpHelperPing.traceRoute("103.152.126.0")                  # IP in Antarctica 
    #icmpHelperPing.traceRoute("101.44.255.0")                  # IP in Ireland

if __name__ == "__main__":
    main()
