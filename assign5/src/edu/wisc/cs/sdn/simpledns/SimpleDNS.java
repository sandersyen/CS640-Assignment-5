package edu.wisc.cs.sdn.simpledns;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileNotFoundException;
import java.io.IOException;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.nio.ByteBuffer;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataAddress;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataName;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataString;
import edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord;

public class SimpleDNS 
{
	private static final int LISTEN_PORT = 8053;
	private static final int SEND_PORT = 53;
	private static List<ec2Entry> ec2List = new ArrayList<ec2Entry>();
	
	private static final boolean DEBUG = true;
	
    public static void main(String[] args)
	{
        System.out.println("Hello, DNS!");
        
        // check argument
        String ipString = null;
        String csvString = null;
        if (args.length == 4) {
        	if (args[0].equals("-r") && args[2].equals("-e")) {
        		ipString = args[1];
        		csvString = args[3];        		
        	}
        	else if (args[0].equals("-e") && args[2].equals("-r")) {
        		ipString = args[3];
        		csvString = args[1];  
        	}
        	else {
        		System.out.println("Error: missing or additional arguments");
    			System.out.println("Usage: java edu.wisc.cs.sdn.simpledns.SimpleDNS -r <root server ip> -e <ec2 csv>");
    			System.exit(-1);	
        	}
        }
        else {
			System.out.println("Error: missing or additional arguments");
			System.out.println("Usage: java edu.wisc.cs.sdn.simpledns.SimpleDNS -r <root server ip> -e <ec2 csv>");
			System.exit(-1);
		}
        
        // check IP
        InetAddress rootServerIp = null;
        try {
        	rootServerIp = InetAddress.getByName(ipString);
        }
        catch (UnknownHostException e)
        {
            System.err.println("Error: invalid IP Address");
            System.exit(-1);
        }
        
        readEC2File(csvString);
        
        // handle packet
        try {
        	DatagramSocket socket = new DatagramSocket(LISTEN_PORT);
            DatagramPacket packet = new DatagramPacket(new byte[4096], 4096);
    		while (true) {
    			socket.receive(packet);
    			DNS dnsPacket = DNS.deserialize(packet.getData(), packet.getLength());
    			if (DNS.OPCODE_STANDARD_QUERY != dnsPacket.getOpcode()) {
    				if (DEBUG) {System.out.println("Not a query, drop this packet");}
    				continue;
    			}
    			if (dnsPacket.getQuestions().isEmpty()) {
    				if (DEBUG) {System.out.println("No question, drop this packet");}
    				continue;
    			}
    			DNSQuestion question = dnsPacket.getQuestions().get(0);
    			if (question.getType() != DNS.TYPE_A && question.getType() != DNS.TYPE_AAAA &&
    				question.getType() != DNS.TYPE_NS && question.getType() != DNS.TYPE_CNAME) {
    				if (DEBUG) {System.out.println("Type not match, drop this packet");}
    				continue;
    			}
    			
    			// construct&send reply packet
    			DNS replyDNSPacket = queryResolve(question, rootServerIp, dnsPacket.isRecursionDesired(), socket);
    			replyDNSPacket.setId(dnsPacket.getId());
    			replyDNSPacket.setQuestions(dnsPacket.getQuestions());
    			byte[] replyPacketSerialized = replyDNSPacket.serialize();
    			DatagramPacket replyPacket = new DatagramPacket(replyPacketSerialized, replyPacketSerialized.length);
    			replyPacket.setPort(packet.getPort());
    			replyPacket.setAddress(packet.getAddress());
    			socket.send(replyPacket);
    		}
        	
        } catch (IOException e) {
        	e.printStackTrace();
		}
        
	}
    
    public static void readEC2File(String csv)
    {
        BufferedReader br;
        try {
			br = new BufferedReader(new FileReader(csv));
			while (br.ready()) {
				String line = br.readLine();  // format: 72.44.32.0/19,Virginia
				String[] split = line.split(",");
				String region = split[1];
				String[] split2 = split[0].split("/");
				int ip = ByteBuffer.wrap(InetAddress.getByName(split2[0]).getAddress()).getInt();
				int mask = (~0) << (32 - Integer.parseInt(split2[1]));
				ec2List.add(new ec2Entry(ip, mask, region));
			}
			br.close();
		}
		catch (FileNotFoundException e) {
			System.err.println("Error: file not found");
            System.exit(-1);
		}
		catch (IOException e) {
			System.err.println("Error: read fail");
            System.exit(-1);
		}
    }
    
    
    private static DNS queryResolve(DNSQuestion query, InetAddress rootIP, boolean recur, DatagramSocket sock) throws IOException{
    	DNS replyDNSPkt = null;
		DatagramPacket rcvPkt = new DatagramPacket(new byte[4096], 4096);
		
		// send query to root server
		DNS dnsOutPkt = new DNS();
		dnsOutPkt.setOpcode(DNS.OPCODE_STANDARD_QUERY);
		dnsOutPkt.addQuestion(query);
		dnsOutPkt.setId((short)0x00aa);
		dnsOutPkt.setRecursionDesired(recur);
		dnsOutPkt.setRecursionAvailable(false);
		dnsOutPkt.setQuery(true);
		byte[] dnsOutPktSerialized = dnsOutPkt.serialize();
		DatagramPacket queryPkt = new DatagramPacket(dnsOutPktSerialized, dnsOutPktSerialized.length);
		queryPkt.setAddress(rootIP);
		queryPkt.setPort(SEND_PORT);
		sock.send(queryPkt);
		if (DEBUG) {System.out.println("Send packet to root server!");}
		
		sock.receive(rcvPkt);
		replyDNSPkt = DNS.deserialize(rcvPkt.getData(), rcvPkt.getLength());

		if (!recur) { return replyDNSPkt; }
		
		List <DNSResourceRecord> answers = new ArrayList<DNSResourceRecord>();
		List <DNSResourceRecord> authorities = new ArrayList<DNSResourceRecord>();
		List <DNSResourceRecord> additionals = new ArrayList<DNSResourceRecord>();
		
		while (replyDNSPkt.getRcode() == DNS.RCODE_NO_ERROR) {
			if(replyDNSPkt.getAnswers().isEmpty()){
				// answer not found
				if (DEBUG) {System.out.println("Answer not found, continue sending query");}
				authorities = replyDNSPkt.getAuthorities();
				additionals = replyDNSPkt.getAdditional();
				if (replyDNSPkt.getAuthorities().isEmpty()) break;
				short typecheck = replyDNSPkt.getAuthorities().get(0).getType();
				if ( typecheck != DNS.TYPE_A && typecheck != DNS.TYPE_AAAA &&
					typecheck != DNS.TYPE_NS && typecheck != DNS.TYPE_CNAME) {
					break;
				}
				for (DNSResourceRecord authRecord : replyDNSPkt.getAuthorities()){
					if (authRecord.getType() == DNS.TYPE_NS){
						DNSRdataName authStr = (DNSRdataName) authRecord.getData();
						if (replyDNSPkt.getAdditional().isEmpty()){
							queryPkt.setAddress(InetAddress.getByName(authStr.getName()));
							sock.send(queryPkt);
							sock.receive(rcvPkt);
							replyDNSPkt = DNS.deserialize(rcvPkt.getData(), rcvPkt.getLength());
						} 
						else {
							for (DNSResourceRecord addRecord : replyDNSPkt.getAdditional()){
								if (authStr.getName().contentEquals(addRecord.getName()) && (addRecord.getType() == DNS.TYPE_A || addRecord.getType() == DNS.TYPE_A)){
									DNSRdataAddress addrData = (DNSRdataAddress)addRecord.getData();
									queryPkt.setAddress(addrData.getAddress());
									sock.send(queryPkt);
									sock.receive(rcvPkt);
									replyDNSPkt = DNS.deserialize(rcvPkt.getData(), rcvPkt.getLength());
								}
							}
						}
					}
				}
			} 
			else {
				// found answer 
				if (DEBUG) {System.out.println("Found answer!");}
				for (DNSResourceRecord ansRecord : replyDNSPkt.getAnswers()){
					answers.add(ansRecord);
					if (ansRecord.getType() == DNS.TYPE_CNAME){
						boolean isInAnswers = false;
						for (DNSResourceRecord record : replyDNSPkt.getAnswers()){
							String name = record.getName();
							String data = ((DNSRdataName)ansRecord.getData()).getName();
							if (name.equals(data)) isInAnswers = true;
						}
						if (isInAnswers) continue;
						if (query.getType() == DNS.TYPE_A || query.getType() == DNS.TYPE_AAAA){
							DNSQuestion cnameQuery = new DNSQuestion(((DNSRdataName)ansRecord.getData()).getName(), query.getType());
							DNS resolvedDnsPkt = queryResolve(cnameQuery, rootIP, recur, sock);
							for(DNSResourceRecord resolvedRecord :resolvedDnsPkt.getAnswers()){
								if (!answers.contains(resolvedRecord))
									answers.add(resolvedRecord);
							}
							authorities = resolvedDnsPkt.getAuthorities();
							additionals = resolvedDnsPkt.getAdditional();
						}
					}
				}
				break;
			}
		}
		
		// check ec2 region
		ArrayList<DNSResourceRecord> ec2Records = new ArrayList<DNSResourceRecord>();
		if (query.getType() == DNS.TYPE_A) {
			for (DNSResourceRecord record : answers) {
	            if (record.getType() == DNS.TYPE_A) {
	                DNSRdataAddress recordData = (DNSRdataAddress) (record.getData());
	                InetAddress ipAddr = recordData.getAddress();
	                ec2Entry match = null;
	            	for (ec2Entry entry: ec2List){
	            		int maskedAddr = ByteBuffer.wrap(ipAddr.getAddress()).getInt() & entry.mask;
	            		if ((entry.ip & entry.mask) == maskedAddr) {
	            			match = entry;
	            			break;
	            		}
	            	}
	                if (match != null) {
	                    DNSRdataString text = new DNSRdataString(match.region + "-" + ipAddr.getHostAddress());
	                    DNSResourceRecord newRecord = new DNSResourceRecord(record.getName(), DNS.TYPE_TXT, text);
	                    ec2Records.add(newRecord);
	                }
	            }
	        }
			
	        for(DNSResourceRecord record : ec2Records){
	        	answers.add(record);
	        }
		}
        
		replyDNSPkt.setAuthorities(authorities);
		replyDNSPkt.setAdditional(additionals);
        replyDNSPkt.setAnswers(answers);
        return replyDNSPkt; 
    }
}

class ec2Entry {
	public int ip;
	public int mask;
	public String region;
	
	public ec2Entry(int ip, int mask, String region) {
		this.ip = ip;
		this.mask = mask;
		this.region = region;
	}
}
