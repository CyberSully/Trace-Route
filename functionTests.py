def sendEchoRequest(self):
    # Fetch the ICMP type and code from the received packet
    icmpType, icmpCode = recvPacket[20:22]
    if icmpType == 11:                          # Time Exceeded
        print(f"TTL={self.getTtl()}\tRTT={(timeReceived - pingStartTime) * 1000:.0f} ms\t"
              f"Type={icmpType}\tCode={icmpCode}\t{addr[0]}")
        if icmpCode == 0:  # Destination Network Unreachable
            print("Destination Network Unreachable")
        elif icmpCode == 1:  # Destination Host Unreachable
            print("Destination Host Unreachable")
    elif icmpType == 3:                         # Destination Unreachable
        print(f"TTL={self.getTtl()}\tRTT={(timeReceived - pingStartTime) * 1000:.0f} ms\t"
              f"Type={icmpType}\tCode={icmpCode}\t{addr[0]}")
        if icmpCode == 0:  # Destination Network Unreachable
            print("Destination Network Unreachable")
        elif icmpCode == 1:  # Destination Host Unreachable
            print("Destination Host Unreachable")
    elif icmpType == 0:                         # Echo Reply
        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)
        return      # Echo reply is the end and therefore should return
    else:
        print("Error: Unknown ICMP type")



def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
    # Compare the received ICMP reply packet with the original ping data sent
    # Confirm that the sequence number, packet identifier, and raw data match
    if (icmpReplyPacket.getIcmpSequenceNumber() == self.getPacketSequenceNumber() and
            icmpReplyPacket.getIcmpIdentifier() == self.getPacketIdentifier() and
            icmpReplyPacket.getIcmpData() == self.getDataRaw()):
        icmpReplyPacket.setIsValidResponse(True)
    else:
        icmpReplyPacket.setIsValidResponse(False)
    
    # Add debug messages to show the expected and actual values along with the result of the comparison
    expected_seq = self.getPacketSequenceNumber()
    actual_seq = icmpReplyPacket.getIcmpSequenceNumber()
    expected_id = self.getPacketIdentifier()
    actual_id = icmpReplyPacket.getIcmpIdentifier()
    expected_data = self.getDataRaw()
    actual_data = icmpReplyPacket.getIcmpData()
    print(f"Expected Sequence: {expected_seq}, Actual Sequence: {actual_seq}, Match: {expected_seq == actual_seq}")
    print(f"Expected Identifier: {expected_id}, Actual Identifier: {actual_id}, Match: {expected_id == actual_id}")
    print(f"Expected Data: {expected_data}, Actual Data: {actual_data}, Match: {expected_data == actual_data}")



def printResultToConsole(self, ttl, timeReceived, addr):
    bytes = struct.calcsize("d")
    timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
    rtt = (timeReceived - timeSent) * 1000
    print(f"TTL={ttl}\tRTT={rtt:.0f} ms\tType={self.getIcmpType()}\tCode={self.getIcmpCode()}"
          f"\tIdentifier={self.getIcmpIdentifier()}\tSequence Number={self.getIcmpSequenceNumber()}\t{addr[0]}")

    # Identify if the echo response is valid and report error information details
    if not self.isValidResponse():
        print("ERROR: Invalid response")
        # If the raw data is different, print to the console the expected value and the actual value
        expected_data = self.getDataRaw()
        actual_data = self.getIcmpData()
        if expected_data != actual_data:
            print(f"Expected Data: {expected_data}, Actual Data: {actual_data}")




import socket

ip_address = addr[0]
try:
    hostname = socket.gethostbyaddr(ip_address)[0]
    print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    current IP address: %s [%s]" %
          (
              self.getTtl(),
              (timeReceived - pingStartTime) * 1000,
              icmpType,
              icmpCode,
              hostname,
              ip_address
          )
    )
except socket.herror:
    print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    current IP address: %s" %
          (
              self.getTtl(),
              (timeReceived - pingStartTime) * 1000,
              icmpType,
              icmpCode,
              ip_address
          )
    )
