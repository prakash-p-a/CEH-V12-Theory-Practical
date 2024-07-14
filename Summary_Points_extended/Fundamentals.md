# Basic Networking 

### Objectives
* Understand network basic concepts 

### **This module follows the order:**
1. Introduction
2. IP and MAC Addresses
3. Subnetting
4. TCP, UDP and 3-Way-Handshake
5. Ports & Protocols
6. OSI Model


# 1. Introduction

## So, what the heck is a Network?
A network consists of two or more computers that are linked in order to share resources. Computer networks are the basis of communication in IT. They are used in a huge variety of ways and can include many different types of network. A computer network is a set of computers that are connected together so that they can share information. The earliest examples of computer networks are from the 1960s, but they have come a long way in the half-century since then.

![image](https://github.com/user-attachments/assets/20653416-74a4-4950-b8b2-2dd0b41c095d)

<sub><sup>LAN Network Topology - SOHO / Small Home Network</sup></sub>

**Two very common types of networks include: LAN (Local Area Network) and WAN (Wide Area Network)**

## Topologies
There are many different types of network, which can be used for different purposes and by different types of people and organization. Here are some of the network types that you might come across:

### LAN - Local Area Network

* A LAN is a network that has a logical and physical borders that a computer can broadcast

<p align="center">
<img width="70%" src="![image](https://github.com/user-attachments/assets/9a4f4e95-e409-4aca-82a8-a2e14b4043b9)
" />
</p>

### WAN - Wide Area Network

* WAN is a multiple LANs or additional WANs with routing functionality for interconnectivity.

<p align="center">
<img width="70%" src="![image](https://github.com/user-attachments/assets/08f4d3e0-930b-4f58-92bb-cfb8f4e86a3c)
" />
</p>

### MAN - Metropolitan Area Network 

<p align="center">
<img width="70%" src="![image](https://github.com/user-attachments/assets/71146d62-b95a-4b66-b7c2-6e58f57829cd)
" />
</p>

### Internet
Connecting WANs through WANs until complete the entire world = Internet.

* The protocol which runs the internet is TCP/IP
* As long you're using legitimate IPv4 address or IPv6
<p align="center">
<img width="70%" src="![image](https://github.com/user-attachments/assets/bf86bcef-a4a6-4c30-99c8-4a236ec1fb34)
" />
</p>

### Intranet
If you're using the TCP/IP stack and making your own LAN or WAN = Intranet.

* Intranet is a private network which still runs TCP/IP

<p align="center">
<img width="70%" src="" />
</p>

## Common Terms in Networking
* **IP (internet protocol) address**: the network address of the system across the network, which is also known as the Logical Address).

* **MAC address**: the MAC address or physical address uniquely identifies each host. It is associated with the Network Interface Card (NIC).

* **Open system**: an open system is connected to the network and prepared for communication.

* **Closed system**: a closed system is not connected to the network and so can't be communicated with.

* **Port**: a port is a channel through which data is sent and received.

* **Nodes**: nodes is a term used to refer to any computing devices such as computers that send and receive network packets across the network.

* **Network packets**: the data that is sent to and from the nodes in a network.

* **Routers**: routers are pieces of hardware that manage router packets. They determine which node the information came from and where to send it to. A router has a routing protocol which defines how it communicates with other routers.

* **‍Network address translation (NAT)**: a technique that routers use to provide internet service to more devices using fewer public IPs. A router has a public IP address but devices connected to it are assigned private IPs that others outside of the network can't see.

* **Dynamic host configuration protocol (DHCP)**: assigns dynamic IP addresses to hosts and is maintained by the internet service provider.

* **Internet service providers (ISP)**: companies that provide everyone with their internet connection, both to individuals and to businesses and other organizations.

# 2. IP & MAC Address
## What is an IP Address (Internet Protocol)?
![ip](https://media.fs.com/images/community/upload/wangEditor/201912/24/_1577182449_2uLs0pQcuT.jpg)

An IP address is a unique address that identifies a device on the internet or a local network. IP stands for "Internet Protocol," which is the set of rules governing the format of data sent via the internet or local network.

## Check your local IP address

1. If you are using Linux or MacOS you can open your terminal and type `ifconfig` command
2. For Windows machine you can open up the cmd prompt or powershell, then type `ipconfig /all`

![inet](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/5a56240010acbc33026413ad6b5c6f66e9450413/inet.png)

- inet IPv4: `192.168.64.3`
   - `inet` --> The inet (Internet protocol family) show the local IP address. This is IP version 4 (IPv4) Using 32-bit decimal number.
- inet6 IPv6: `fe80::c83b:ccff:fe0e:1069`

   - `inet6` --> Is a new version of IP (IPv6), using 128 bits hexadecimal value.
- `ether` --> MAC address - unique identifier assigned to a network interface controller (NIC)

## More about the IPv4 decimal value:

``` 
IPv4 = 32 bits range (4 octets of 8 bits, from 0-255 each(4))

11000000.10101000.01000000.00000011   [IPv4 binary]
   192  .   168  .   64   .  3        [IPv4 decimal]
``` 

### The arithmetic behind IPv4:

- One octet have 8 bits:

0 or 1 | 0 or 1 | 0 or 1 | 0 or 1 | 0 or 1 | 0 or 1 | 0 or 1 | 0 or 1 
-|-|-|-|-|-|-|-
8th bit | 7th bit | 6th bit | 5th bit | 4th bit | 3rd bit | 2nd bit | 1st bit
128 (2^7) | 64 (2^6) | 32 (2^5) | 16 (2^4) | 8 (2^3) | 4 (2^2) | 2 (2^1) | 1 (2^0)

Here is how binary octets convert to decimal: The right most bit, or least significant bit, of an octet holds a value of 2^0. The bit just to the left of that holds a value of 2^1. This continues until the left-most bit, or most significant bit, which holds a value of 2^7. So if all binary bits are a one, the decimal equivalent would be 255 as shown here:

```
  1   1   1   1   1   1   1   1
  |   |   |   |   |   |   |   |
(128 +64 +32 +16 +8  +4  +2  +1) --> 255 

Example of octet conversion:
IP Address: 192.168.64.3

To calculate the first octet (192.), from binary format to decimal:

128  64  32  16  8   4   2   1         
 |   |   |   |   |   |   |   |
 1   1   0   0   0   0   0   0          
 |   |   |   |   |   |   |   |
128+ 64+ 0+  0+  0+  0+  0+  0 = 192   ---> final value (firt octet IPv4 in decimal)

```
* Take the IP: `192.168.64.3`
* The first octet `192` in 8-bit binary is `11000000`.
* Only the `8th` and `7th` bit is on and the rest of them (`6th to 1st bit`) is off, meaning the decimal value is the final sum of these values:  `128 + 64 = 192`

⚠️ **Why? Computers see everything in terms of binaryll; on and off.**


## IPv4 and IPv6
![ipv](https://academy.avast.com/hs-fs/hubfs/New_Avast_Academy/IPv4%20vs.%20IPv6%20What%E2%80%99s%20the%20Difference/IPv4-vs-IPv6.png?width=2750&name=IPv4-vs-IPv6.png)

## Private and Public IP Addresses
All IPv4 addresses can be divided into two major groups: **global (or public, external)** - this group can also be called 'WAN addresses' — those that are used on the Internet, and **private (or local, internal) addresses** — those that are used in the local network (LAN).

![priv-pub](https://wiki.teltonika-networks.com/wikibase/images/thumb/a/a7/Sip.png/1100px-Sip.png)

## More about **Private IP** addresses:
Private (internal) addresses are not routed on the Internet and no traffic can be sent to them from the Internet, they only supposed to work within the local network.
Private addresses include IP addresses from the following subnets:

![private-ip](https://66.media.tumblr.com/02a533c1d55ca0ba83e0176168df06ec/tumblr_inline_o4m1taQugo1u4ytoo_1280.jpg)

## NAT - Network Address Translation
NAT stands for network address translation. It’s a way to map multiple local private addresses to a public one before transferring the information. Organizations that want multiple devices to employ a single IP address use NAT, as do most home routers. 

![nat2](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/8275f73b57bdcb982b1d69aa8d213d2bdb384657/nat2.png)

1. **Static NAT**

   When the local address is converted to a public one, this NAT chooses the same one. This means there will be a consistent public IP address associated with that router or NAT device.

2. **Dynamic NAT**

   Instead of choosing the same IP address every time, this NAT goes through a pool of public IP addresses. This results in the router or NAT device getting a different address each time the router translates the local address to a public address.

### ⚠️ IP Addresses operates on **Layer 3 of OSI Model**

*Note: This module will cover OSI model later.*

![osi3](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/b9d7f33be654d299f6618feeacb97fc5fd5bd7d2/OSI_L3.png)

# 3. Subnetting
### Why subnetting?
The way IP addresses are constructed makes it relatively simple for Internet routers to find the right network to route data into. However, in a Class A network (for instance), there could be millions of connected devices, and it could take some time for the data to find the right device. This is why subnetting comes in handy: subnetting narrows down the IP address to usage within a range of devices.

Because an IP address is limited to indicating the network and the device address, IP addresses cannot be used to indicate which subnet an IP packet should go to. Routers within a network use something called a subnet mask to sort data into subnetworks.

> ⚠️ Subnetting is really important for penetration testers and aspiring hackers, eventually you will face several cases involving small or large networks in your future engagements. Understanding the IP address type, range, available hosts is crucial for any network analysis.

## Cheat sheet makes easier for subnetting

![subnetting](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/5ce4b7daa9c2c10ccd44675eadaceae646e487e2/cyber-mentor-subnetting.png)

* CyberMentor Subnetting Sheet: https://twitter.com/thecybermentor/status/1211335431406727169

* Subnetting Cheat sheet alternative: https://nsrc.org/workshops/2009/summer/presentations/day3/subnetting.pdf



## Exercises:
Subnetting comes in handy to awnser basic questions like:
   - Identify the network and broadcast address
   - How many hosts available in the network/hosts range?
   - What masks allow the particular host?


IP range | Subnet | Hosts | Network | Broadcast
-|-|-|-|-
192.168.1.16/28 | 255.255.255.240 | 14 | 192.168.1.16 | 192.168.1.31 
192.168.0.0/22 | ? | ? | ? | ?

- Take the `192.168.0.0/22` IP range listed above
- You can easily figure out the subnet mask by look the cheat sheet, you can see the `252` column. Just replace the value of `x`. You will get `255.255.252.0`
   - Subnet masks can be 0, 128, 192, 224, 240, 248, 252, 254 and 255. 
   - To understand the basics of math behind the bits, check the next figure below:

![bits](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/c1e01e29aedc394f2d75c4ccf57e72606775103a/bits.png)

- The number of hosts is `2^(n) - 2`. 
   - `n = off bits`
   - In this case, is 2^10 = 1024 -> 1024 - 2 = `1022`
- The network portion is the first and lowest possible value.
- The broadcast is the last and highest possible value.

IP range | Subnet | Hosts | Network | Broadcast
-|-|-|-|-
192.168.0.0/22 | 255.255.252.0 | 1022 | 192.168.0.0 | 192.168.3.255



## Other relevant information about  IPs
- **IPv4 Main Address Types**
  - **Unicast** - acted on by a single recipient
  - **Multicast** - acted on by members of a specific group
  - **Broadcast** - acted on by everyone on the network
    - **Limited** - delivered to every system in the domain (255.255.255.255)
    - **Directed** - delivered to all devices on a subnet and use that broadcast address
- **Subnet mask** - determines how many address available on a specific subnet
  - Represented by three methods
    - **Decimal** - 255.240.0.0
    - **Binary** - 11111111.11110000.00000000.00000000
    - **CIDR** - x.x.x.x/12   (where x.x.x.x is an ip address on that range)
  - If all the bits in the host field are 1s, the address is the broadcast
  - If they are all 0s, it's the network address
  - Any other combination indicates an address in the range

# MAC Addresses 

-  MAC (Media Access Control) address is provided by NIC Card'd manufacturer and gives the physical address of a computer.

![macphys](https://i1.wp.com/learntomato.flashrouters.com/wp-content/uploads/MAC-address-hardware.jpg?resize=560%2C315&ssl=1)

The first three bytes of a MAC address were originally known as **OUI’s, or Organizational Unique Identifiers.  Each manufacturer of networking equipment was assigned an OUI, and was free to assign their own numbers in that block.**

```
   OUI     NIC
    |       |
________ ________
00:0c:29:99:98:ca
```
## Checking vendor behind MAC addresse
1. Check your MAC address use the command `ifconfig` (Linux) or `/ipconfig` (Windows)
![mac](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/214242916f8947f09fc15d5bdde6a668fd4a4c1f/mac2.png)

2. Copy and save the **first three bytes** of your address. *(The first three bytes from image above is `00:0c:29`)*

3. Validate the information by performing a **MAC Address Lookup** on the internet. For this example I'm using: https://aruljohn.com/
![mac2](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/c82686452d3e671f9a4d351cd5c02171914dd16d/mac2lookup.png)

4. As you can see the OUI lookup identify a virtual network interface provided by VMware 

*So, to summarize, the **first three bytes** are assigned to a manufacturer of networking equipment and the manufacturer assigns the last three bytes of an address.*

### ⚠️ MAC Addresses operates on Layer 2 of OSI Model
![osil2](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/b9d7f33be654d299f6618feeacb97fc5fd5bd7d2/OSI_L2.png)

# 4. TCP/IP, UDP and 3-Way-Handshake

## Transmission Control Protocol/Internet Protocol (TCP/IP)

* What is TCP used for?

TCP enables data to be transferred between applications and devices on a network. It is designed to break down a message, such as an email, into packets of data to ensure the message reaches its destination successfully and as quickly as possible.

* What does TCP mean?

TCP means Transmission Control Protocol, which is a communications standard for delivering data and messages through networks. TCP is a basic standard that defines the rules of the internet and is a common protocol used to deliver data in digital network communications.

- The TCP/IP model consists of several types of protocols, including:
   - TCP and IP
   - Address Resolution Protocol (ARP)
   - Internet Control Message Protocol (ICMP)
   - Reverse Address Resolution Protocol (RARP)
   - User Datagram Protocol (UDP)

![tcpmod](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/bccff9a7c15aa11636c03686ef344ae2d433f699/tcpmodel.png)

<sub><sup>TCP/IP Model</sup></sub>

TCP is the most commonly used of these protocols and accounts for the most traffic used on a TCP/IP network. **UDP is an alternative to TCP that does not provide error correction, is less reliable, and has less overhead, which makes it ideal for streaming.**

## The User Datagram Protocol (UDP)
Is a lightweight data transport protocol that works on top of IP.
UDP provides a mechanism to detect corrupt data in packets, but it does not attempt to solve other problems that arise with packets, such as lost or out of order packets. That's why UDP is sometimes known as the Unreliable Data Protocol.
UDP is simple but fast, at least in comparison to other protocols that work over IP. It's often used for time-sensitive applications (such as real-time video streaming) where speed is more important than accuracy.

- On Linux and Unix systems you can issue the `lsof` command to see which processes is using UDP ports
![udp](https://cdn.kastatic.org/ka-perseus-images/edbdf593300fc4a51c60a97998c4d01a51ccd3b1.png)

## The TCP format
![tc](https://cdn.kastatic.org/ka-perseus-images/e5fdf560fdb40a1c0b3c3ce96f570e5f00fff161.svg)

## The UDP format
![udp](https://cdn.kastatic.org/ka-perseus-images/9d185d3d44c7ef1e2cd61655e47befb4d383e907.svg)

## TCP Handshake

TCP uses a three-way handshake to establish a reliable connection. The connection is full duplex, and both sides synchronize (SYN) and acknowledge (ACK) each other. The exchange of these four flags is performed in three steps:
1. SYN
2. SYN-ACK
3. ACK 

![3wayhandshake](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/bd38a6a2d83ea02a4715d6cb7fd8e0d74af3bd26/3wayhs.jpg)

The three message mechanism is designed so that two computers that want to pass information back and forth to each other can negotiate the parameters of the connection before transmitting data such as HTTP browser requests.

## More TCP Flags

| Flag | Name           | Function                                                     |
| ---- | -------------- | ------------------------------------------------------------ |
| SYN  | Synchronize    | Set during initial communication.  Negotiating of parameters and sequence numbers |
| ACK  | Acknowledgment | Set as an acknowledgement to the SYN flag.  Always set after initial SYN |
| RST  | Reset          | Forces the termination of a connection (in both directions)  |
| FIN  | Finish         | Ordered close to communications                              |
| PSH  | Push           | Forces the delivery of data without concern for buffering    |
| URG  | Urgent         | Data inside is being sent out of band.  Example is cancelling a message |

## Capturing 3 Way handshakes (Example)

- The figure below shows the 3-way-handshake packets captured by [Wireshark](https://www.wireshark.org/)

![wireshark](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/5213becc28e3f9f46c976d05cd090ffd070ff5d1/wireshark0.png)

# 5. Ports & Protocols
## What is a Port?
In computer networking, a port is a communication endpoint. At the software level, within an operating system, a port is a logical construct that identifies a specific process or a type of network service.

## The most common ports
As a penetration tester or ethical hacker you should be familiar with the common ports and protocols used by popular services.

### <u>Port Numbers</u>

- **Internet Assigned Numbers Authority** (IANA) - maintains Service Name and Transport Protocol Port Number Registry which lists all port number reservations

- Ranges

  - **Well-known ports** - 0 - 1023

  - **Registered ports** - 1024 - 49,151

  - **Dynamic ports** - 49,152 - 65,535

    | Port Number | Protocol | Transport Protocol |
    | ----------- | -------- | ------------------ |
    | 20/21       | FTP      | TCP                |
    | 22          | SSH      | TCP                |
    | 23          | Telnet   | TCP                |
    | 25          | SMTP     | TCP                |
    | 53          | DNS      | TCP/UDP            |
    | 67          | DHCP     | UDP                |
    | 69          | TFTP     | UDP                |
    | 80          | HTTP     | TCP                |
    | 110         | POP3     | TCP                |
    | 135         | RPC      | TCP                |
    | 137-139     | NetBIOS  | TCP/UDP            |
    | 143         | IMAP     | TCP                |
    | 161/162     | SNMP     | UDP                |
    | 389         | LDAP     | TCP/UDP            |
    | 443         | HTTPS    | TCP                |
    | 445         | SMB      | TCP                |
    | 514         | SYSLOG   | UDP                |

  - A service is said to be **listening** for a port when it has that specific port open

  - Once a service has made a connection, the port is in an **established** state

  - **`netstat`** command:

    - Shows open ports on computer
    - **netstat -an** displays connections in numerical form
    - **netstat -b** displays executables tied to the open port (admin only)

# 6. OSI Model
OSI Model is a hypothetical networking framework that uses specific protocols and mechanisms in every layer of it. This model is used to divide the network architecture into seven different layers conceptually. These layers are:

![osi-model](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/3e2dc59e7c341f4d79b2b93bac03fd8378c7ae3a/tcpmo.jpg)

There also involves some security postures and mechanisms that a security professional must know to detect and put the security method effectively in every layer.

## More about the Layers:

## Layer 7 - Application

![l7](https://www.cloudflare.com/img/learning/ddos/glossary/open-systems-interconnection-model-osi/7-application-layer.svg)

- This is the only layer that directly interacts with data from the user. Software applications like web browsers and email clients rely on the application layer to initiate communications. But it should be made clear that client software applications are not part of the application layer; rather the application layer is responsible for the protocols and data manipulation that the software relies on to present meaningful data to the user. Application layer protocols include HTTP as well as SMTP (Simple Mail Transfer Protocol is one of the protocols that enables email communications).

## Layer 6 - Presentation

![l6](https://www.cloudflare.com/img/learning/ddos/glossary/open-systems-interconnection-model-osi/6-presentation-layer.svg)

- This layer is primarily responsible for preparing data so that it can be used by the application layer; in other words, layer 6 makes the data presentable for applications to consume. The presentation layer is responsible for translation, encryption, and compression of data.

## Layer 5 - Session Layer

![l5](https://www.cloudflare.com/img/learning/ddos/glossary/open-systems-interconnection-model-osi/5-session-layer.svg)

- This is the layer responsible for opening and closing communication between the two devices. The time between when the communication is opened and closed is known as the session. The session layer ensures that the session stays open long enough to transfer all the data being exchanged, and then promptly closes the session in order to avoid wasting resources.

## Layer 4 - Transport Layer

![l4](https://www.cloudflare.com/img/learning/ddos/glossary/open-systems-interconnection-model-osi/4-transport-layer.svg)

- Layer 4 is responsible for end-to-end communication between the two devices. This includes taking data from the session layer and breaking it up into chunks called segments before sending it to layer 3. The transport layer on the receiving device is responsible for reassembling the segments into data the session layer can consume.

- The transport layer is also responsible for flow control and error control. Flow control determines an optimal speed of transmission to ensure that a sender with a fast connection doesn’t overwhelm a receiver with a slow connection. The transport layer performs error control on the receiving end by ensuring that the data received is complete, and requesting a retransmission if it isn’t.

## Layer 3 - Network Layer

![l3](https://www.cloudflare.com/img/learning/ddos/glossary/open-systems-interconnection-model-osi/3-network-layer.svg)

- The network layer is responsible for facilitating data transfer between two different networks. If the two devices communicating are on the same network, then the network layer is unnecessary. The network layer breaks up segments from the transport layer into smaller units, called packets, on the sender’s device, and reassembling these packets on the receiving device. The network layer also finds the best physical path for the data to reach its destination; this is known as routing.

## Layer 2 - Data Link Layer

![l2](https://www.cloudflare.com/img/learning/ddos/glossary/open-systems-interconnection-model-osi/2-data-link-layer.svg)

- The data link layer is very similar to the network layer, except the data link layer facilitates data transfer between two devices on the SAME network. The data link layer takes packets from the network layer and breaks them into smaller pieces called frames. Like the network layer, the data link layer is also responsible for flow control and error control in intra-network communication (The transport layer only does flow control and error control for inter-network communications).

## Layer 1 - Physical Layer

![l1](https://www.cloudflare.com/img/learning/ddos/glossary/open-systems-interconnection-model-osi/1-physical-layer.svg)

- This layer includes the physical equipment involved in the data transfer, such as the cables and switches. This is also the layer where the data gets converted into a bit stream, which is a string of 1s and 0s. The physical layer of both devices must also agree on a signal convention so that the 1s can be distinguished from the 0s on both devices.


# Lab Building

### Requirements 
* Windows 10, macOS or any Linux distro
    * At least 8 GB RAM (16GB recommended)

### Objectives
* Understand how virtual machines work
* Learn how to create a basic virtual environment for pentesting purpose

# What does Virtual Machine (VM) means?
For simplicity, think of a virtual machine (VM) as a "computer made of software" which you can use to run any software you'd run on a real, physical computer. Like a physical machine, a virtual machine has its own operating system (Windows, Linux, etc.), storage, networking, configuration settings, and software, and it is fully isolated from other virtual machines running on that host.

![vm](https://miro.medium.com/max/937/1*QgshMdPQ7ZzK1hRbv1ncPQ.jpeg)


**Security benefits** — Because virtual machines run in multiple operating systems, using a guest operating system on a VM allows you to run apps of questionable security and protects your host operating system. VMs also allow for better security forensics, pentesting and are often used to safely study computer viruses, isolating the viruses to avoid risking their host computer.

### Hypervisors
There are two main hypervisor types, referred to as **“Type 1” (or “bare metal”)** and **“Type 2” (or “hosted”)**. 

![hypervisors](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/0143eb15cf424c87ae823109d73df9ebe3faebec/hyper.png)

- **Type 1** hypervisor acts like a lightweight operating system and runs directly on the host’s hardware.
- **Type 2** hypervisor runs as a software layer on an operating system, like other computer programs. 

# 1. VirtualBox Installation

- **This tutorial use [Oracle VM VirtualBox](https://www.virtualbox.org), the most popular free and open-source hosted hypervisor for x86 virtualization, developed by Oracle.**
- There are other options from different vendors to achieve the same result:
    - [VMware Player for Windows (30 day trial)](https://www.vmware.com/products/workstation-player.html)
    - [VMware Fusion for macOS (30 day trial)](https://www.vmware.com/products/fusion.html)
    - [Windows Hyper-V](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/about/)
    - [Linux KVM](https://help.ubuntu.com/community/KVM/Installation)

1. **Make sure your PC support hardware virtualization (Windows)** 
    - Reboot your computer
    - Right when the computer is coming up from the black screen, press Delete, Esc, F1, F2, or F4. Each computer manufacturer uses a different key but it may show a brief message at boot telling you which one to press. If you miss it the first time, reboot and try again. It helps to tap the key about twice a second when the computer is coming up. If you are not able to enter the BIOS via this method, consult your computer’s manual.
    - In the BIOS settings, find the configuration items related to the CPU. These can be in under the headings Processor, Chipset, or Northbridge.
    - Enable virtualization; the setting may be called **VT-x, AMD-V, SVM, or Vanderpool**. Enable Intel VT-d or AMD IOMMU if the options are available.
    - Save your changes and reboot.

> ⚠️  If you are unable to find the Virtualization settings in your BIOS it may mean that your computer does not support it.

2. **Download the latest version of Virtual Box**
    - Go to Oracle Virtual Box website:
        - https://www.virtualbox.org/wiki/Downloads
    - Select your current OS and download the installer
    - ![v](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/944dad38ad3bfc556600c6ca3e08ec83cabd54e5/vbox1.png)
    - Also, scroll down on the same page and download the **VirtualBox Extension Pack**. This extension will allow VirtualBox functionalities like USB support, virtual disk encryption etc.
    - ![v2](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/944dad38ad3bfc556600c6ca3e08ec83cabd54e5/vbox2.png)

3. **Install Virtual Box and Extension Pack**
    - There is no special configuration on the **Virtual Box** installation process, just point, click and install.
    - Once the installation is done, install the **Extension Pack** by double clicking it; The file extension is `.vbox-extpack`. Don't worry about the warning prompts.

## VirtualBox NAT configuration
*The next steps will cover how to create a NAT network on VirtualBox. In simple words Virtual Machines needs a virtual network adapter, to access the internet and segragete your Host IP(main OS) and Guest IP(VM).*

4. **Launch VirtualBox and open the `Preferences` pane** 

![pref1](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/1b0a358d438d859df17db305753ce41c1826e4b0/pref1.png)

5. **Go to the `Network tab` on the left pane, and then click the `green plus button` on the right**

![pref2](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/1b0a358d438d859df17db305753ce41c1826e4b0/pref2.png)

6. **By the default, VirtualBox automatically creates a NatNetwork. Click the `OK` button and save this configuration**

![pref3](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/1b0a358d438d859df17db305753ce41c1826e4b0/pref3.png)


7. **Next part we will download the latest Kali Linux version and boot it up into Virtual box software**



## About Kali Linux 
![kali](https://www.bleepstatic.com/content/hl-images/2019/11/29/kali-header.jpg)

> ⚠️  Kali Linux Tutorial will be covered on the next module [Linux for Hackers].md 

Kali Linux (formerly known as BackTrack Linux) is an open-source, Debian-based Linux distribution aimed at advanced Penetration Testing and Security Auditing. [[+]](https://www.kali.org/docs/introduction/what-is-kali-linux/)

Kali Linux contains several hundred tools targeted towards various information security tasks, such as:
- Penetration Testing
- Security Research
- Computer Forensics
- Reverse Engineering

## Download the latest Kali Linux image
1. **Go to Offensive Security website:**
    - https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/
2. **Download the Kali Linux VirtualBox image, make sure to select the `Virtual Box image (OVA)`**

![kali0](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/163a5fcc5653f6c06fb7e63fbf570e3fd9b5c144/kali0.png)

# 2. Installing Kali Linux on VirtualBox
Once you have installed VirtualBox and downloaded the Kali Linux image, you just need to import it to VirtualBox in order to make it work.

1. **Launch VirtualBox and click the `Import Button` on the top center menu**

![kali1](https://i1.wp.com/itsfoss.com/wp-content/uploads/2019/02/vmbox-import-kali-linux.jpg?w=956&ssl=1)

2. **Next, browse the Kali Linux image (OVA) you just downloaded and choose it to be imported (as you can see in the image below).**

![kali2](https://i2.wp.com/itsfoss.com/wp-content/uploads/2019/02/vmbox-linux-next.jpg?w=954&ssl=1)

3. **Next, you will be shown the settings for the virtual machine you are about to import. So, you can customize them or not – that is your choice based on your hardware capacity.**
    - If you have a computer with 8GB RAM and at least 2 cores available, leave the default settings.
    - If your computer have 16GB RAM or more, I recommend to use 4GB RAM on Kali Linux, to do that, scroll down the configuration list and change the `RAM value` to `4096` MB

![kali3](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/9a53e3ba4ca62c777cf59acc53d211b4c187598e/pref4.png)

4. **You will now see the Kali box listed. So, just hit Start to launch it.**

![kali4](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/5f7c4d496d67f429aff72c1c177028f16dc35379/pref5.png)

5. **Type the default credentials:** username: `kali`, password: `kali`. 
    - Tip: On Linux, you can change the default password of the current user by typing `passwd` on terminal.

![kali5](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/5f7c4d496d67f429aff72c1c177028f16dc35379/kali-log.png)

6. **Done!**

![kali6](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/a8f9a9f928ce6aeb71683cf95cb738b5842d0c04/kali-desk.png)

- ⚠️  **Next module you'll learn some techniques of Kali distro and how to operate on Linux itself.**


# Introduction to Linux 🐧

### Requirements 
* Ubuntu virtual machine (or any disto desktop general-purpose like Manjaro, Fedora etc) (1)
* Kali Linux virtual machine (2)


### Objectives
* Understand the basics of Linux systems
* Perform basic system and network tasks from CLI (command line interface)
* Learn about Kali Linux and pre-installed security tools


**Before jumpstart into Kali Linux tutorial, it is recommended to use a desktop general-purpose distro like [Ubuntu](https://ubuntu.com/download/desktop) or [Manjaro](https://manjaro.org/download/) for learning the basics and get used to, also you can check the [DistroWatch](https://distrowatch.com/) to find a good distro to start with.**
 
1. __**The first part**__ of this tutorial uses **Ubuntu** VM to explain the basics of Linux environment, basic commands and techniques.

2. __**The second part**__ is about **Kali Linux** itself, covering security tools using more advanced techniques.

> **⚠️ Warning:** *Kali is a Linux distribution specifically geared towards professional penetration testers and security specialists, and given its unique nature, **it is NOT recommended to use as a general-purpose Linux desktop for development, web design, gaming, etc.*** 

# Why Linux so Popular?

![linux](https://static0.makeuseofimages.com/wordpress/wp-content/uploads/2015/01/best-linux-distros.jpg)

- Linux Torvalds not only created Linux but also made it available to the world for free. He then invited others to work for the modification of Linux and keep their contributions free. This is the reason why Linux gained an enormous amount of audience among hard-core developers very quickly. Another reason for this amazing amount of popularity is that Linux is extremely popular and favorite operating system among hackers. The main reason is Linux source code is freely available because it is an open source operating system.

- Linux is appealing for the people who wanted to experiment with operating system principles and who needed a **great deal of control over their operating system.**

- **Linux is widely used to run the internet and in all 85% of all the servers are running Linux.** Streams have 1600 games on Linux now, including many mainstream titles.

- Linux is faster than windows and because Windows is a commercial operating system it costs a lot of money while Linux being an open source operating system is free.

- The Linux terminal is superior to use over Window’s command line for developers. You would find many libraries developed natively for Linux. Also according to many developers, Linux helps the, get things done easily.
Linux doesn’t encounter a large number of software updates, but you will also observe much faster software updates so that the problems you might be facing can be eliminated.

# Setting up 🧰
First things first, you should download and deploy two virtual machines: **Ubuntu Linux** and **Kali Linux**. 

The recommended configuration for Ubuntu VM is 2GB to 3GB RAM and at least 4GB of RAM to Kali. **To makes things easier you can leave the default configuration for both machines.**

- [Ubuntu official website](https://ubuntu.com/download/desktop)
- [Kali Linux official website](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/#1572305786534-030ce714-cc3b)

**Note**: If you don't know how to setup your VMs you can check the [previous module on lab building](https://github.com/Samsar4/Ethical-Hacking-Labs/blob/master/0-Core-Knowledge/1-Lab-Building.md) or more specifically a tutorial on [how to setup Ubuntu VM](https://www.makeuseof.com/install-ubuntu-virtualbox/).

# Diving into Ubuntu

At this point you should be familiar with a basic operating system such as Windows and the various programs that are already available on the Windows operating system. Ubuntu is no different, this linux distro is a very straightforward, stable and easy to use OS for newcomers, after the installation you're ready to go and explore.

![ubunut1](https://i0.wp.com/9to5linux.com/wp-content/uploads/2020/08/ubuntu20041.jpg?fit=800%2C600&ssl=1)


**Note**: This tutorial will teach you **how to operate Linux by command line** not the interface. Technically you can do some tasks by using the interface, but I encourange to do as much you can on CLI (command line interface) and this tutorial will guide through this. By this way you can have a granular control to handle the system.

* Fire up your Ubuntu VM and explore by yourself the interface, pre-installed applications and configurations.
![ubuntu2](https://techlatest.b-cdn.net/wp-content/uploads/2020/04/ubuntu-20.04-app-folders-1536x864-1-1024x576.jpg)

## UI vs. CLI
This example will compare the differences between UI(user interface) and CLI(command line interface) by performing a simple task: 
   - create a text file, write some words and save it.

This is just a simple example to grasp the idea behind command line. 

1. First, let's create a text file using the interface. Click on the 6 dotted button on the bottom right **(Show Applications)** and open the **Text Editor application**

![ub1](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/0490dd84d2611a7ed0631a21f851cc244f80ba4d/ub1.png)

2. Write **hello world** on the new file, and then save in your Desktop by giving the name **hello.txt**

![ub2](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/0490dd84d2611a7ed0631a21f851cc244f80ba4d/ub2.png)

3. Now, click again the 6 dotted button to show all applications and open a new **Terminal** window

4. To navigate to your desktop by using the terminal, type `cd Desktop`. Next type `echo hello world > hello2.txt`.
   - `cd` command means change directory. The next command will `echo` the string `hello world` and the symbol `>` tells the system to output results into a new file, the target is usually a filename (`hello2.txt`).

![ub3](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/0490dd84d2611a7ed0631a21f851cc244f80ba4d/ub3.png)

5. As you can see on the image below, the both methods perform the same results.

![ub4](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/0490dd84d2611a7ed0631a21f851cc244f80ba4d/ub4.png)


**Bottom line**, command line is the most powerful way to operate a Linux machine, you can leverage the granular control of Linux systems and do pretty much everything from command line in more robust, fast and efficient way. For example you can rename thousands of files with a simple one-liner command, instead of renaming one by one using UI. You can automate tasks, manage networks etc and do much more using the terminal.

# Linux structure
In Windows, the root begins at the drive letter, usually C:\, which basically means it begins at the hard drive. In Linux however, the root of the filesystem doesn’t correspond with a physical device or location, it’s a logical location of simply “/”. See the graphics below for a visual representation.

To access the root of the filesystem, you can type `cd` to change directory following the destination `/` , representing the begining of the filesystem.
   - `cd /`

```
ubuntu@primary:/home$ cd /
Users  boot  etc   lib    lib64   lost+found  mnt  proc  run   snap  sys  usr
bin    dev   home  lib32  libx32  media       opt  root  sbin  srv   tmp  var
```

To understand the basics of each folder in the Linux file system is for, which will help us to better understand how Linux works in general. Note that not every folder listed here or pictured below necessarily appears in every Linux distro, but most of them do.

![structure](https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/4d8d864d53230f3aa14495d486fd01274a54aec0/linux-structure.png)

# Core commands
The core commands will explore the most important user and system commands.

> ⚠️  Remember that every command have a manual page, you can access on [this website](https://linux.die.net/man/) or directly from terminal by typing: `man <command>`

### `sudo` 
Sudo stands for SuperUser DO and is used to access restricted files and operations. By default, Linux restricts access to certain parts of the system preventing sensitive files from being compromised.

The sudo command temporarily elevates privileges allowing users to complete sensitive tasks without logging in as the root user.

1. **For example, lets try to update the Ubuntu packages without `sudo` command. To do that you can simple issue the `apt-get update` command and hit enter.**

```
purple@purple-vm:~$ apt-get update

Reading package lists... Done
E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)
E: Unable to lock directory /var/lib/apt/lists/
W: Problem unlinking the file /var/cache/apt/pkgcache.bin - RemoveCaches (13: Permission denied)
W: Problem unlinking the file /var/cache/apt/srcpkgcache.bin - RemoveCaches (13: Permission denied)
```
As you can see above we got the **"13:  Permission denied" error**, meaning that we need root privileges to update Ubuntu packages.

2. **Next, issue the command with elevated privileges (root) using `sudo`. The command will be successfully executed.**

```
purple@purple-vm:~$ sudo apt-get update
[sudo] password for purple: 
Hit:1 http://pt.archive.ubuntu.com/ubuntu focal InRelease
Hit:2 http://pt.archive.ubuntu.com/ubuntu focal-updates InRelease                     
Hit:3 http://pt.archive.ubuntu.com/ubuntu focal-backports InRelease                   
Hit:4 https://brave-browser-apt-release.s3.brave.com stable InRelease                 
Hit:5 http://security.ubuntu.com/ubuntu focal-security InRelease                      
Reading package lists... Done
```

Also we have other `apt-get` variants:
   - `apt-get upgrade` ->  simply upgrades/installs the new version of the package available over the old one.
   - `apt-get dist-upgrade` -> This command looks for newer dependencies and prioritizes upgrading them by the possibility of removing the old ones – which could be dangerous. Make sure to read the [official documentation](https://linux.die.net/man/8/apt-get) before issue this command.

3. **You also can switch to root user by using `su`. But is not recommended to operate as root as a security practice. Applications are meant to be run with non-administrative security, so you have to elevate their privileges to modify the underlying system.**

```
purple@purple-vm:~$ sudo su
[sudo] password for purple: 
root@purple-vm:/home/purple# 
```
As you can see, the user purple jumped to root user by using su.

### `pwd`
`pwd` stands for **P**rint **W**orking **D**irectory. It prints the path of the current directory that you are in, starting from the root.

```
purple@purple-vm:~$ pwd
/home/purple/work/code
```
## Linux Permissions 

Linux has three permissions and they can be set for the owner, group or other.

<p align="center">
<img width="90%" src="https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/01260d855800248f380bd6c2b58fe0425067cebf/linux-perms.png" />
</p>

> **r = read** - open a file, view a file.
> **w = write** - edit a file, add or delete files for directories.
> **x = execute** - run a file, execute a program or script, CD to a different directory.

Owner | Group | Other
:--:|:--:|:--:
rwx | rwx | rwx

* Viewing the permissions on Linux command-line:

```console
ls -l
```

```console
-rwxrwxr-x 1 user user 31337 Feb 11 13:13 File
```

### Using `chmod` 
`chmod` *is the command and system call which is used to change the access permissions of file system objects on Unix and Unix-like OS.*

* Clear out the permissions of the **File** to have no read, write and execute permissions on **Other**:<br> *(The flag equals to nothing[o=] deny the permissions)*

```console
ls -l
```

```console
-rwxrwxr-x 1 user user 31337 Feb 11 13:13 File
```

```console
chmod o= File
```

```console
ls -l
```

```console
-rwxrwx--- 1 user user 31337 Feb 11 13:13 File
```

* Giving **read** and **write** permissions to **Group**:

```console
ls -l
```

```console
-rwx---r-- 1 user user 31337 Feb 11 13:13 File
```

```console
chmod g=rw File
```

```console
ls -l
```

```console
-rwxrw-r-- 1 user user 31337 Feb 11 13:13 File
``` 

* Giving **all permissions** to everybody(Owner,Group and Other):

```console
ls -l
```

```console
-rwx---r-- 1 user user 31337 Feb 11 13:13 File
```

```console
chmod a=rwx File
```

```console
ls -l
```

```console
-rwxrwxrwx 1 user user 31337 Feb 11 13:13 File
``` 


## Using `chmod` - oldschool way:
The chmod command will take the octal value and combine them to associate the permissions on three different positions for the Owner, Group and Other/Everyone. This boils down to a simple binary rule: 0 = off | 1 = on.

Octal | Binary | Permissions
:--:|:--:|:--:
0 | 000 | ---
1 | 001 | --x
2 | 010 | -w-
3 | 011 | -wx
4 | 100 | r--
5 | 101 | r-x
6 | 110 | rw-
7 | 111 | rwx

*If you want to give all permissions to a group for example, the number will be 7 (4 + 2 + 1).*

Read | Write | Execute
:--:|:--:|:--:
r-- | -w- | --x
4 | 2 | 1

#### Examples:

* Giving **read, write and execute** permission to everybody:

```console
ls -l
```

```console
-rwx---r-- 1 user user 31337 Feb 11 13:13 File
```

```console
chmod 777 File
```

```console
ls -l
```

```console
-rwxrwxrwx 1 user user 31337 Feb 11 13:13 File
``` 


* Giving all permissions to the **owner**, read and write to **group** and no permissions to **other/everyone**:

```console
ls -l
```

```console
-r-x---r-- 1 user user 31337 Feb 11 13:13 File
```

```console
chmod 760 File
```

```console
ls -l
```

```console
-rwxrw---- 1 user user 31337 Feb 11 13:13 File
```

### Linux - File Ownership using `chown` (change file owner and group)

```console
ls -l
```

```console
-rwxrwxrwx 1 user001 user001 31337 Feb 11 13:13 File
```

```console
sudo chown root File
```

```console
ls -l
```

```console
-rwxrwxrwx 1 root user001 31337 Feb 11 13:13 File
```

*The chown command requires sudo*


### `passwd`

Changes the password of current user 
```console
sudo passwd
```

## Network commands

### `ping`
* Can be handful for DNS checks (up / or down) | is a DNS tool to resolves web addresses to an IP address.
* Test reachability - determine round-trip time, and uses ICMP protocol.

```console
~#: ping www.google.com 

PING www.google.com (172.217.168.164): 56 data bytes
64 bytes from 172.217.168.164: icmp_seq=0 ttl=55 time=25.981 ms
64 bytes from 172.217.168.164: icmp_seq=1 ttl=55 time=25.236 ms
--- www.google.com ping statistics ---
2 packets transmitted, 2 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 25.236/25.608/25.981/0.373 ms
```


### `netstat`
* Network statistics
* Get info on host system TCP / UDP connections and status of all open and listening ports and routing table.

* Who you talking to? 
* Who trying talking to you? 

```console
netstat -a # (show all active connections) (servers)
netstat -n # (hosts)
netstat -b # (Show binaries Windows)
```

### `traceroute`
* Traceroute - how packets get from host to another endpoint. Traceroute is helpful to see what routers are being hit, both internal and external.

* **Take advantage of ICMP Time to Live (TTL) Exceeded error message**
	- The time in TTL refers to hops, not seconds or minutes.
	- TTL=1 is the first router.
	- TTL=2 is the second router, and so on.

<p align="center">
<img width="90%" src="https://2.bp.blogspot.com/-bJD787kOoXg/WxfnpFe4tVI/AAAAAAAAXN4/XTCxg0nFEAQOjtEVcvDzL2N-pK-EbQA2wCLcBGAs/s1600/0.png" />
</p>

* *As shown above, on HOP 2 the TTL exceeded and back to the device A, counting 3 on TTL for the next HOP.*

```console
~#: traceroute google.com

traceroute to google.com (172.217.17.14), 64 hops max, 52 byte packets
 1  192.168.1.1 (192.168.1.1)  4.960 ms  3.928 ms  3.724 ms
 2  10.10.124.254 (10.10.127.254)  11.175 ms  14.938 ms  15.257 ms
 3  10.133.200.17 (10.137.201.17)  13.212 ms  12.581 ms  12.742 ms
 4  10.255.44.86 (10.255.45.86)  16.369 ms  15.100 ms  17.488 ms
 5  71.14.201.214 (71.14.201.214)  13.287 ms  29.262 ms  16.591 ms
 6  79.125.235.68 (79.125.242.68)  22.488 ms
    79.125.235.84 (79.125.242.84)  13.833 ms *
 7  79.125.252.202 (79.125.252.202)  24.147 ms
    108.170.252.241 (108.170.25@.241)  26.352 ms
    79.125.252.202 (79.125.252.202)  23.598 ms
 8  108.170.252.247 (108.170.252.247)  31.187 ms
    79.125.252.199 (79.121.251.191)  22.885 ms
```

### `arp` 
* Address resolution protocol - caches of ip-to-ethernet
* Determine a MAC address based on IP addresses
* Option `-a`: view local ARP table
```console
~#: arp -a

? (192.168.1.3) at 00:11:22:33:44:55 [ether] on enp0s10
? (192.168.1.128) at e8:33:b0:70:2c:71 [ether] on enp0s10
? (192.168.1.4) at 2c:33:5c:a4:2e:8a [ether] on enp0s10
_gateway (192.168.1.1) at 00:31:33:8b:2a:da [ether] on enp0s10
```

### `ifconfig`

* Equivalent to ipconfig for UNIX/Linux OS.

```console
~#: ifconfig
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 00:11:22:33:44:55  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp0s10: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.128  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::acf6:2ae2:ab5c:6316  prefixlen 64  scopeid 0x20<link>
        ether aa:bb:cc:dd:ee:ff  txqueuelen 1000  (Ethernet)
        RX packets 156651  bytes 29382856 (28.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 76400  bytes 23111524 (22.0 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

### `iwconfig`
similar to ifconfig, but is dedicated to the wireless network interface.

```console
~#: iwconfig
lo        no wireless extensions.

enp0s10   no wireless extensions.

wlp3s0b1  IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=19 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Encryption key:off
          Power Management:off
          
docker0   no wireless extensions.
```

### `ip addr`
show / manipulate routing, network devices, interfaces and tunnels.

Show all the ip configuration, mac address, ipv6 etc.

```console
~#: ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.111/24 brd 192.168.1.255 scope global dynamic noprefixroute enp0s10
       valid_lft 4761sec preferred_lft 4761sec
    inet6 fe80::acf6:2ae2:ab5c:6316 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```

### `nslookup`

* Query Internet name servers interactively; check if the DNS server is working

```console
nslookup www.certifiedhacker.com

output:
Server:         192.168.1.1
Address:        192.168.1.1#53

Non-authoritative answer:
www.certifiedhacker.com canonical name = certifiedhacker.com.
Name:   certifiedhacker.com
Address: 162.241.216.11 inslookup www.certifiedhacker.com
Server:         192.168.1.1
Address:        192.168.1.1#53

Non-authoritative answer:
www.certifiedhacker.com canonical name = certifiedhacker.com.
Name:   certifiedhacker.com
Address: 162.241.216.11

```

### `dig` 
* DNS lookup tool - Functions like nslookup, but allows for further functionality.

```console
dig www.certifiedhacker.com

output:
; <<>> DiG 9.11.14-3-Debian <<>> certifiedhacker.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15708
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 2048
; COOKIE: 71bd915b07b3fd08757c9ad65e5d6f3e549d5187359e97cb (good)
;; QUESTION SECTION:
;certifiedhacker.com.           IN      A

;; ANSWER SECTION:
certifiedhacker.com.    14400   IN      A       162.241.216.11

;; Query time: 419 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Mon Mar 02 15:40:29 EST 2020
;; MSG SIZE  rcvd: 92

```

### `netcat`
TCP/IP swiss army knife; you can make any type of connection and see the results from a command line. With nc you can connect to anything on any port number or you can make your system listen on a port number. Can be an agressive tool for recon.

<p align="center">
<img src="https://www.researchgate.net/publication/329745450/figure/fig3/AS:705181092179978@1545139682702/Remote-Command-and-Control-example-through-Netcat.ppm" />
</p>

* "Read" or "Write" to the network
	- Open a port and send or receive some traffic
	- Listen on a port number
	- Transfer data
	- Scan ports and send data to be a port
* Become a backdoor
	- Run a shell from a remote device

### `stat` 
stat can return the status of an entire file system, the status of the first hard disk and so on.

<p align="center">
<img width="88%" src="https://www.howtoforge.com/images/command-tutorial/big/stat-basic.png" />
</p>

- Archive attribute - **Windows** - if something is created or changed

### `tcpdump`
* Tcpdump is a data-network packet analyzer computer program that runs under a command line interface. It allows the user to display TCP/IP and other packets being transmitted or received over a network to which the computer is attached. Distributed under the BSD license, tcpdump is free software

<p align="center">
<img width="90%" src="https://packetflows.com/wp-content/uploads/2017/05/tcpdump_i.png" />
</p>

## Network Scanners
**Useful for collect and inventory the hosts on a network, and is useful for reconnaissance of your system.**

### `nmap`
The Best way to query a system to check if they have open ports, services, system versions, service versions etc.


```console
nmap -v -A -T5 scanme.nmap.org 

...
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)
|   2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)
|   256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)
|_  256 33:fa:91:0f:e0:e1:7b:1f:6d:05:a2:b0:f1:54:41:56 (ED25519)
80/tcp    open  http       Apache httpd 2.4.7 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 156515DA3C0F7DC6B2493BD5CE43F795
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Go ahead and ScanMe!
9929/tcp  open  nping-echo Nping echo
31337/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```

# [in progress]

to do notes 

1) Ubuntu - basics
    - about Linux
    - how to operate
    - basic commands

2) Kali - advanced
    - about Kali
    - security tools
    - advanced commands

3) Bonus part
    - tmux, vim.
    - cool commands like terminal weather, neofetch
---
