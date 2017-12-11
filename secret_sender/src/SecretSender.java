import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Random;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.LinkLayerAddress;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

public class SecretSender {
	
	private static final int READ_TIMEOUT = 100; //ms
	private static final int SNAPLEN = 65536; 
	private PcapNetworkInterface nif=null;
	
	private Inet4Address dstIpAddress;
	private Inet4Address srcIpAddress;
	private MacAddress srcMacAddr;
	private MacAddress dstMacAddr;
	private String msgType;	// msg type 0: ICMP Echo Request Message; 1: TCP SYN packet to port 80
	private String message;	//encoded message to be sent; maximum message length is 255

	//constructor
	SecretSender(Inet4Address dstIpAddress, PcapNetworkInterface nif, String msgType, String message ){
		this.dstIpAddress = dstIpAddress;
		this.nif = nif;
		this.msgType = msgType;
		this.message = message;
		findSrcAddr();
	}
	
	//constructor
	SecretSender(Inet4Address dstIpAddress, PcapNetworkInterface nif ){
		this.dstIpAddress = dstIpAddress;
		this.nif = nif;
		findSrcAddr();
	}
	
	//Send the packets for the given message & given message Type
	//@param msgType : message type to be sent
	//@param message : String with length >0 & <255
	void sendMessage(String msgType, String message){
		if (msgType.equals("0")){
			sendICMPPackets(message);
		}else if (msgType.equals("1")){
			sendTCPPackets(message);
		}
	}
	
	//Send the ICMP packets for the given message
	//@param message : String with length >0 & <255
	void sendICMPPackets(String message){
		try {
			PcapHandle sendHandle
			  = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
			int len=message.length();
			int identifier = randInt(1,0xfe);
			for(int i = 0; i < len; i++){
				char c = message.charAt(i);
				IcmpV4CommonPacket.Builder icmpV4CommonBuilder = createICMPEchoPacket(identifier,i+1);
				   
				IpV4Packet.Builder ipV4Builder = createIPv4Packet(identifier, c, i, IpNumber.ICMPV4, icmpV4CommonBuilder);
				Packet p = createEthernetPacket(ipV4Builder);
  
				//send the packet
				sendPacket(sendHandle, p);
			}
			//send the last packet
			IcmpV4CommonPacket.Builder icmpV4CommonBuilder = createICMPEchoPacket(identifier,len+1);
			IpV4Packet.Builder ipV4Builder = createIPv4Packet(identifier, '\0', len, IpNumber.ICMPV4, icmpV4CommonBuilder);
			Packet p = createEthernetPacket(ipV4Builder);
			sendPacket(sendHandle, p);
		} catch (PcapNativeException e) {
			e.printStackTrace();
		}		
	}
	
	//generate a random number between min & max, inclusive
	//@param min : minimum random number value
	//@param max : maximum random number value
	public static int randInt(int min, int max) {
	    Random rand= new Random();
	    int randomNum = rand.nextInt((max - min) + 1) + min;
	    return randomNum;
	}
	
	//Send the TCP packets for the given message
	//@param message : String with length >0 & <255 
	void sendTCPPackets(String message){
		try {
			PcapHandle sendHandle
			  = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
			int len=message.length();
			int identifier = randInt(1,0xfe);
			for(int i = 0; i < len; i++){
				char c = message.charAt(i);
				TcpPacket.Builder tcpBuilder =  createTCPPacket();
				IpV4Packet.Builder ipV4Builder = createIPv4Packet(identifier, c, i, IpNumber.TCP, tcpBuilder);   
				Packet p = createEthernetPacket(ipV4Builder);
				//send the packet
				sendPacket(sendHandle, p);
			}
			//send the last packet
			TcpPacket.Builder tcpBuilder =  createTCPPacket();
			IpV4Packet.Builder ipV4Builder = createIPv4Packet(identifier, '\0', len, IpNumber.TCP, tcpBuilder);   
		
			Packet p = createEthernetPacket(ipV4Builder);
			sendPacket(sendHandle, p);
		} catch (PcapNativeException e) {
			e.printStackTrace();
		}			
	}
	
	//send the packet created to dest IP
	//@param sendHandle : sending handle on the interface
	//@param p : ethernet packet with payload ready to be sent
	void sendPacket(PcapHandle sendHandle, Packet p){
	    try {
	    	System.out.println( "sending packet:"+p);
			sendHandle.sendPacket(p);
		} catch (NotOpenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (PcapNativeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	//Finds the Source MAC address & Source IP address on the given interface
	private void findSrcAddr(){
	     for (LinkLayerAddress addr: nif.getLinkLayerAddresses()) {
	    	 if (addr != null){
	    		 srcMacAddr=MacAddress.getByName(addr.toString(), ":");
	    		 System.out.println( "Source MAC Address: "+ addr);
	    		 break;
	    	 }
	     }
	     for (PcapAddress addr: nif.getAddresses()) {
	    	 if(addr.getAddress().getClass().equals(java.net.Inet4Address.class)){
	    		 try {
					srcIpAddress=(Inet4Address)InetAddress.getByName(addr.getAddress().getHostAddress());
					System.out.println( "Source IP Address: "+ addr.getAddress().getHostAddress());
					return;
				} catch (UnknownHostException e) {
					e.printStackTrace();
				} 
	    	 }
	       }
	}


//Create a TCP packet
TcpPacket.Builder createTCPPacket(){
		byte[] tcpData = new byte[2];
		for (int i = 0; i < tcpData.length; i++) {
			tcpData[i] = (byte)i;
		}
    
		TcpPacket.Builder tcpBuilder = new TcpPacket.Builder();

		tcpBuilder
		.syn(true)
		.dstPort(TcpPort.HTTP)
		.srcPort(TcpPort.TELNET)
		.srcAddr(srcIpAddress)
		.dstAddr(dstIpAddress)
		.correctChecksumAtBuild(true)
		.paddingAtBuild(true)
		.correctLengthAtBuild(true);
    return tcpBuilder;
}

//Create an ICMP Echo packet
//@param id : identification
//@param seq : sequence number
IcmpV4CommonPacket.Builder createICMPEchoPacket(int id, int seq){
    byte[] echoData = new byte[2];
    for (int i = 0; i < echoData.length; i++) {
      echoData[i] = (byte)i;
    }

    IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder();
    echoBuilder
      .identifier((short)id)
      .payloadBuilder(new UnknownPacket.Builder().rawData(echoData));

    echoBuilder.sequenceNumber((short)seq);
    
    IcmpV4CommonPacket.Builder icmpV4CommonBuilder = new IcmpV4CommonPacket.Builder();
    icmpV4CommonBuilder
      .type(IcmpV4Type.ECHO)
      .code(IcmpV4Code.NO_CODE)
      .payloadBuilder(echoBuilder)
      .correctChecksumAtBuild(true)
      ;
    
    return icmpV4CommonBuilder;
}

//Create IPv4 packet
//@param identifier : identification 
//@param c : character to be sent 
//@param fragmentOffset : fragmentation offset for this packet
//@param protocol : payload protocol
//@param payloadBuilder : payload packet builder
IpV4Packet.Builder createIPv4Packet(int identifier, char c, int fragmentOffset, IpNumber protocol, Packet.Builder payloadBuilder){
    IpV4Packet.Builder ipV4Builder = new IpV4Packet.Builder();
    ipV4Builder
        .version(IpVersion.IPV4)
        .tos(IpV4Rfc791Tos.newInstance((byte)0))
        .ttl((byte)64)
        .protocol(protocol)
        .srcAddr(srcIpAddress)
        .dstAddr(dstIpAddress)
        .payloadBuilder(payloadBuilder)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true)
		.identification((short)(identifier|(c<<8)))
		.dontFragmentFlag(true);
    if(fragmentOffset == message.length()){
        ipV4Builder.fragmentOffset((short)(fragmentOffset | (1<<12)));
    }else{
        ipV4Builder.fragmentOffset((short)fragmentOffset);
    }
	ipV4Builder.build();
    return ipV4Builder;
}

//Create Ethernet Packet for a given IPv4 payload builder
//@param payloadBuilder : IPv4 packet builder
//@return : ethernet packet with payload
Packet createEthernetPacket(Packet.Builder payloadBuilder){
    EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
    etherBuilder.dstAddr(MacAddress.getByName("ff:ff:ff:ff:ff:ff", ":"))
                .srcAddr(srcMacAddr)
                .type(EtherType.IPV4)
                .payloadBuilder(payloadBuilder)
                .paddingAtBuild(true);
    Packet p = etherBuilder.build();
    return p;
}

//Create Ethernet Packet for a given IPv4 payload builder
//@param strSrcMacAddress : String Source MAC address
//@param strDstMacAddress : String Destination MAC address
//@param payloadBuilder : IPv4 packet builder
//@return : ethernet packet with payload
Packet createEthernetPacket(String strSrcMacAddress, String strDstMacAddress, Packet.Builder payloadBuilder){
    EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
    etherBuilder.dstAddr(MacAddress.getByName(strDstMacAddress, ":"))
                .srcAddr(MacAddress.getByName(strSrcMacAddress, ":"))
                .type(EtherType.IPV4)
                .payloadBuilder(payloadBuilder)
                .paddingAtBuild(true);
    Packet p = etherBuilder.build();
    return p;
}

//print the program usage on screen & exit
static void usage(){
	System.out.println( "Usage : ./secret_sender <ip_address> <interface> <type> <message>");
	System.out.println( "Arguments:"); 
	System.out.println( "\tip_address : Destination IP address");
	System.out.println( "\tinterface  : Source Ethernet Interface");
	System.out.println( "\ttype       : 0: ICMP Echo Request Message; 1: TCP SYN packet to port 80");
	System.out.println( "\tmessage    : message to be sent in packet");
	System.out.println( "Please run again with correct arguments! Exiting program...");
	System.exit(1);
}

//main function
public static void main(String[] args) throws PcapNativeException {
	Inet4Address destIpAddress=null;
	
	//check if no. of argument is 4
	if (args.length != 4){
		usage();
	}
	//Verify the arguments provided
	String strDstIpAddress = args[0]; // for InetAddress.getByName()
	String interfaceName = args[1]; //source interface name
	String msgType = args[2];	// msg type 0: ICMP Echo Request Message; 1: TCP SYN packet to port 80
	String message = args[3];	//encoded message to be sent; maximum message length is 255
	
	//verify correct format of dest IP address 
	try {
		destIpAddress = (Inet4Address) InetAddress.getByName(strDstIpAddress);
	} catch (UnknownHostException e1) {
		System.out.println( "Error: Invalid IP address provided!");
		usage();
	}
	
	if (!(msgType.equals("0") || msgType.equals("1"))){
		System.out.println( "Error: Invalid \"type\" provided!");
		System.out.println( "Expected: 0 or 1; provided: "+msgType);
		usage();
	}
  
	//find list of available interface
    List<PcapNetworkInterface> allDevs = null;
    try {
      allDevs = Pcaps.findAllDevs();
    } catch (PcapNativeException e) {
    	System.out.println( "Exception occured while fetching the interface list. Exiting...");
    	System.exit(2);
    }

    if (allDevs == null || allDevs.isEmpty()) {
    	System.out.println("No Network interface found. Exiting...");
    	System.exit(3);
    }
    
    PcapNetworkInterface nitf=null;
    for (PcapNetworkInterface nif: allDevs) {
    	if(nif.getName().equals(interfaceName)){
            System.out.println("Found specified interface:"+nif.getName());
            nitf= nif;
            break;
    	}else{
            System.out.println("Found interface:"+nif.getName());
        }
    } 
    if (nitf == null) {
		System.out.println( "Error: Invalid \"interface\" provided!");
		System.out.println( "couldn't find any such interface: "+interfaceName);
		usage();	
    }

    if (message.length()>255){
		System.out.println( "Error: Invalid \"message\" provided!");
		System.out.println( "Expected length of message: 255; provided length: "+message.length());
		usage();   	
    }
    
    SecretSender secretSender = new SecretSender(destIpAddress, nitf, msgType, message);
    secretSender.sendMessage(msgType,message);  
}
}