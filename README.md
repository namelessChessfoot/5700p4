# Extra Credit

Extra credit completed! Details will be discussed later


# How to Run it

`make` sets the permission of `rawhttpget`, sets the iptable, and turns off segmentation offload of the net device.

In `MakeFile`, a variable called `device` is defined. The name of the net device on my VM is `enp0s3`. If it is different on the test machine, please update it for me, thank you!

Run `sudo ./rawhttpget [url]` because root privilege is required to create a raw socket.

For example, `sudo ./rawhttpget http://david.choffnes.com/classes/cs5700f22/2MB.log` will download 2MB.log and place it in the same directory.

`sudo ./rawhttpget http://david.choffnes.com/classes/cs5700f22/` will download index.html.

# High Level Approach

Several modules are implemented. They are:

- The main function: `rawhttpget`
- HTTP layer: `MyHttp.py`
- TCP layer: `MyTCP.py`
- A data structure for keeping unACKed TCP packets: `SendBuffer.py`
- IP layer: `MyIP.py`
- The challenge part, Ethernet Layer: `MyChallenge.py`
- Checksum, used for IP and TCP: `checksum.py`

All of them are implemented by Keming Xu. I implemented the checksum first, then IP send, TCP send, IP recv, TCP recv, HTTP, and finally the Ethernet.

## Checksum
In order to make sure my checksum algorithms are correct, I got some valid IP packets from Wireshark to test the algorithms.

## IP and TCP send
Use Wireshark to see whether I correctly send an IP or TCP packet.

## IP and TCP recv
They are strongly related, so they were implemented together.

I decided to use non-block socket to receive to avoid using multithreading (one thread sends and one thread receive).

IP recv receives packets, reassembles them into a complete packet, and put it in a queue.

TCP gives IP recv a short period of time to receive packets and consume packets from IP's queue. TCP packets are put in a buffer and consumed in order with an increasing seq number.

## HTTP
Copy the code from the last project, which was also completed by myself.

## Ethernet
Learnt the process of sending an Ethernet Frame and implemented it!

# Features of Ethernet, IP, TCP, and HTTP

## Ethernet
- Get the name of my net device
- Get the MAC of my net device
- Get the IP of my gateway
- Send ARP requests
- Listen to ARP responses to get the MAC of my gateway
- Send IP packets to my gateway in an Ethernet Frame

## IP
- Disassemble and assemble IP packets
- Checksum

## TCP
- Build connection
- Send HTTP message, FIN, and ACKs
- Handle seq/ack wrap-around
- Checksum
- Tear down
- Keep track of outgoing packets and resend them if receive no ACK
- CWND
- Consume packets in order

## HTTP
- Send Get messages only
- Support chunk encoding
- Handle 200 responses only

# Special Note for the Extra Credit
It works on my VM but not sure whether it could on the test machine. If it does not, please help me to modify `self.take_challenge` in `MyIP.py` to `False` so that it can work without my challenge part. Thank you!


# Challenges
- I did not see too much discussion about the checksum algorighm
- Almost no discussion about the Ethernet Layer
- With segmentation offload, my code works really slow

# For your convenience

In `MyTCP.py`, you could remove the comment on line 232-235, and line 292 so that you can see the progress of downloading. This would help when you use it to download the 50MB file.


# Test

I ran my code several times. 

`sudo ./rawhttpget http://david.choffnes.com/classes/cs5700f22/`
takes less than 1 second on my VM.

`sudo ./rawhttpget http://david.choffnes.com/classes/cs5700f22/2MB.log`
takes around 3 seconds on my VM.

`sudo ./rawhttpget http://david.choffnes.com/classes/cs5700f22/50MB.log`
takes around 70 seconds on my VM.

Correctness has been verified by `md5sum`.


