JC = javac
JFLAGS = -g

SimpleDNS : edu/wisc/cs/sdn/simpledns/SimpleDNS.java
	$(JC) $(JFLAGS) edu/wisc/cs/sdn/simpledns/SimpleDNS.java

run:
	java edu.wisc.cs.sdn.simpledns.SimpleDNS -r 192.168.0.1 -e ec2.csv  

clean:
	$(RM) -rf ../bin/*