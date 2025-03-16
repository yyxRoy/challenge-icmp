---
###
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is "draft-<yourname>-<workgroup>-<name>.md".
#
# For initial setup, you only need to edit the first block of fields.
# Only "title" needs to be changed; delete "abbrev" if your title is short.
# Any other content can be edited, but be careful not to introduce errors.
# Some fields will be set automatically during setup if they are unchanged.
#
# Don't include "-00" or "-latest" in the filename.
# Labels in the form draft-<yourname>-<workgroup>-<name>-latest are used by
# the tools to refer to the current version; see "docname" for example.
#
# This template uses kramdown-rfc: https://github.com/cabo/kramdown-rfc
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
###
title: "Enhancing ICMP Error Message Authentication Using Challenge-Confirm Mechanism"
abbrev: "challenge-icmpv4"
category: info

docname: draft-xu-intarea-challenge-icmpv4-00
submissiontype: IETF 
number:
date:
consensus:
v: 3
area: AREA
workgroup: Internet Area Working Group
keyword:
 - off-path attack
 - challenge
 - fragmentation
venue:

author:
 -
    fullname: Ke Xu
    organization: Tsinghua University & Zhongguancun Laboratory 
    country: China
    city: Beijing
    email: xuke@tsinghua.edu.cn
 -
    fullname: Xuewei Feng
    organization: Tsinghua University
    country: China
    city: Beijing
    email: fengxw06@126.com
 -
    fullname: Yuxiang Yang
    organization: Tsinghua University
    country: China
    city: Beijing
    email: yangyx22@mails.tsinghua.edu.cn
 -
    fullname: Qi Li
    organization: Tsinghua University & Zhongguancun Laboratory 
    country: China
    city: Beijing
    email: qli01@tsinghua.edu.cn



normative:
  RFC792: https://datatracker.ietf.org/doc/rfc792/
  RFC1122: https://datatracker.ietf.org/doc/rfc1122/
  RFC2119: https://datatracker.ietf.org/doc/rfc2119/
  RFC2780: https://datatracker.ietf.org/doc/rfc2780/
  RFC4086: https://datatracker.ietf.org/doc/rfc4086/
  RFC9293: https://datatracker.ietf.org/doc/rfc9293/
  CCS2020IPID:
    title: "Off-path TCP exploits of the mixed IPID assignment"
    date: 2020
    seriesinfo: "ACM Conference on Computer and Communications Security (CCS)"
    author:
      - ins: X. Feng
      - ins: C. Fu
      - ins: Q. Li
      - ins: K. Sun
      - ins: K. Xu

  NDSS2022MTU:
    title: "PMTUD is not Panacea: Revisiting IP Fragmentation Attacks against TCP"
    date: 2022
    seriesinfo: "Network and Distributed System Security Symposium (NDSS)"
    author:
      - ins: X. Feng
      - ins: Q. Li
      - ins: K. Sun
      - ins: K. Xu
      - ins: B. Liu
      - ins: X. Zheng
      - ins: Q. Yang
      - ins: H. Duan
      - ins: Z. Qian

  USENIXSECURITY2023ICMP:
    title: "Off-Path Network Traffic Manipulation via Revitalized ICMP Redirect Attacks"
    date: 2023
    seriesinfo: "USENIX Security Symposium (Security)"
    author:
      - ins: X. Feng
      - ins: Q. Li
      - ins: K. Sun
      - ins: Z. Qian
      - ins: C. Fu
      - ins: G. Zhao
      - ins: X. Kuang
      - ins: K. Xu
  
  SP2023MITM:
    title: "Man-in-the-middle attacks without rogue AP: When WPAs meet ICMP redirects"
    date: 2023
    seriesinfo: "IEEE Symposium on Security and Privacy (SP)"
    author:
      - ins: X. Feng
      - ins: Q. Li
      - ins: K. Sun
      - ins: Y. Yang
      - ins: K. Xu

informative:
  RFC5927: https://datatracker.ietf.org/doc/rfc5927/


--- abstract

The Internet Control Message Protocol (ICMP) plays a crucial role in network diagnostics and error reporting. However, it is a challenge to verify the legitimacy of a received ICMP error message, particularly when the ICMP error message is embedded with stateless protocol data. As a result, adversaries can forge ICMP error messages, leading to potential exploitation and off-path attacks. This document proposes a novel method to enhance ICMP authentication by introducing a challenge-confirm mechanism. This mechanism embeds random numbers in the IP options field to strengthen the authentication of ICMP error messages. By doing so, it mitigates the risks associated with forged messages, improves the overall robustness of the protocol, and enhances network security. The proposed solution includes details on the challenge-confirm mechanism, random number generation and management, and integration with IP options. Additionally, it discusses security and deployment considerations to ensure its practical implementation.


--- middle

# Introduction
The Internet Control Message Protocol (ICMP) {{RFC792}} is an integral part of network operations, providing essential feedback on transmission issues such as unreachable destinations or packet fragmentation requirements. Despite its importance, ICMP is susceptible to various attacks, particularly the forgery of error messages by off-path attackers. Notably, off-path attackers can forge ICMP error messages embedded with stateless protocol data, making it difficult for receivers to verify their legitimacy. Unlike stateful protocols such as TCP, where embedded connection-related details (e.g., sequence numbers) in the ICMP error messages can be checked by the receiver against an ongoing connection {{RFC5927}}, stateless protocol data lacks inherent mechanisms for verification. Consequently, the receiver may erroneously accept the forged message, enabling off-path attackers to manipulate network behavior. For example, in an MTU manipulation attack, forged ICMP Packet Too Big messages with stateless protocols (e.g., UDP, ICMP Echo Reply) force hosts to reduce their PMTU, degrading throughput and harming latency-sensitive applications. This can also induce TCP segment fragmentation {{NDSS2022MTU}} and enabling IP ID-based TCP session hijacking {{CCS2020IPID}}. Moreover, forged ICMP Redirect messages embedded with stateless protocol data can be used to trick victims into modifying their routing, facilitating off-path traffic interception, modification, and credential theft {{USENIXSECURITY2023ICMP}}, {{SP2023MITM}}.

To enhance ICMP error message authentication, this document presents a novel method by introducing a challenge-confirm mechanism. This mechanism embeds random challenges within the IP options field. Particularly, when a receiver gets an ICMP error message embedded with a stateless protocol payload (like a UDP/ICMP payload) for the first time, it ignores the message and sends a subsequent (UDP/ICMP) packet (i.e., a challenge packet) on the established network session to the destination, embedding a randomly generated number in the IP options field. If the prior ignored ICMP error message was legitimate, this new packet will trigger another ICMP error message containing the randomly generated number, allowing the receiver to verify authenticity and respond correctly. This challenge-confirm mechanism strengthens ICMP security by effectively mitigating off-path forged error messages, making it more resistant to forgery and various attacks, thereby enhancing the overall robustness of the network protocol. It requires minimal changes to the TCP/IP protocol suite, involving only updates to the ICMP error message verification code on end hosts while remaining backward compatible and without modifying intermediate routing devices.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}.  TCP terminology should be interpreted as described in {{RFC9293}}.


# Problem Statement

Current ICMP specifications have limitations that enable off-path attackers to forge ICMP error messages embedded with stateless protocol data, compromising network security and reliability. The key issues are as follows:

## Source-Based Blocking Ineffectiveness

Certain ICMP error messages, like the "Fragmentation Needed" messages, can originate from any intermediate router along the packet's path. Given this wide range of possible sources, legitimate messages can come from numerous locations. As a result, source-based blocking is rendered ineffective because it becomes difficult to distinguish between legitimate and forged messages based on the source address alone.

## Authentication Evasion based on Embedded Packet State

Although ICMP requires including as much of the original (offending) packet as possible in error messages without exceeding the appropriate MTU limits, the stateful or stateless nature of the embedded packet protocol directly impacts the authentication difficulty and security strength of ICMP error messages. According to ICMP specifications {{RFC792}}, {{RFC1122}}, error messages should include at least the first 28 octets of the original packet to aid in identifying the affected process and verifying legitimacy.

### Stateful Embedded Packets (e.g., TCP)

When off-path attackers embed stateful protocol packets, such as TCP segments, in forged ICMP error messages, the receiver has some means of verification. The TCP protocol uses sequence numbers, acknowledgment numbers, and ports to establish and maintain a connection state between communicating parties. This connection-specific information is difficult for off-path attackers to accurately guess. Receivers can check if the connection-related details in the embedded TCP header match the TCP connection state they maintain. For example, they can verify if the sequence number in the TCP segment embedded in the ICMP error message aligns with the expected sequence number for an ongoing TCP connection. This way, they can make an informed judgment about the authenticity of the ICMP error message.

### Stateless Embedded Packets (e.g., UDP, ICMPv6)

In contrast to stateful TCP packets, when off-path attackers embed stateless protocol packets, like UDP or ICMP packets, in forged ICMP error messages, receivers face significant challenges in authenticating the messages. UDP and ICMP are stateless protocols by design. The source end does not keep track of any session-state information, and each message is independent. This means that the UDP or ICMP headers embedded in ICMP error messages lack crucial state information, such as sequence numbers, that could be used for context-based verification. Beyond basic protocol-format checks, receivers have few reliable ways to determine the authenticity of the ICMP error message based on the embedded stateless packet header. This lack of state-based verification severely weakens the authentication of ICMP error messages, enabling attackers to easily bypass authentication and use forged error messages for malicious purposes. 

These vulnerabilities enable off-path attackers to manipulate network behavior, exploit protocol weaknesses, and potentially disrupt communication without being detected or mitigated by existing security measures.


# Proposed Solution

## Challenge-Confirm Mechanism

To counteract the vulnerabilities in ICMP error messages validation, this document presents a Challenge-Confirm Mechanism aimed at validating the authenticity of ICMP error messages. 

The message flow of the challenge - confirm mechanism is depicted in Figure 1:

~~~
  Host                                                 Sender
  -----                                                    -------
  1. Reception of ICMP Error Message <----- ICMP Error Message
                                      (Stateless Embedded Payload)

  2. IGNORING

  3. ISSUING CHALLENGE PKT -----------> Reception of CHALLENGE PKT
     (IP_Options=Random_X)

  4. RECV NEW ICMP ERROR <----------------- ICMP Error Message
                                           (IP_Options=Random_X)

  5. Verification 
     (IP_Options=Random_X)
     (Verification Success)
~~~
                        Figure 1: Challenge-Confirm Message Flow


The operation of this mechanism is as follows:

1. **Receiving an ICMP Error Message**: When a host receives an ICMP error message containing a stateless protocol payload (like UDP or ICMP), it cannot be certain of the message's authenticity due to the issues previously mentioned. The receiving host, based on the existing ICMP design, lacks the means to verify whether the message is from legitimate senders or the message is forged by off-path attackers.

2. **Ignoring the ICMP Error Message**: The host ignores and discard the received ICMP error message.

3. **Issuing a Challenge**: To authenticate the received ICMP error message, the receiving host first ignores the received ICMP message and then sends a subsequent UDP or ICMP packet (i.e., a challenge packet) on the established session to the original sender. This packet embeds a randomly generated number within the IP options field. The choice of the IP options field allows for the seamless addition of authentication-related data without modifying the fundamental structure of the ICMP message, ensuring compatibility with the existing network setup. This random number serves as a unique identifier for this particular authentication attempt.

4. **Response to Challenge**: If the original ICMP error message was legitimate, the sender will again respond by sending another new ICMP error message. This response message will carry the same random number within its IP options field. For instance, a legitimate router that generated the initial ICMP error message in the normal course of packet-handling will, upon receiving the challenge packet, extract the random number and incorporate it into its response ICMP error message as a proof of authenticity. While the off-path attackers will not be able to catch the challenge packet and it is hard for them to respond with a new ICMP error message with the right number.

5. **Verification**: The receiving host then checks for the presence and correctness of the random number in the response. If the random number in the response matches the one it initially sent, the original ICMP error message is confirmed as authentic. This verification step acts as a crucial defense against forged ICMP error messages. If the numbers do not match or the random number is absent, the receiving host can infer that the original message may be forged. In such a case, it can take appropriate actions, such as discarding the message, logging the event for security analysis, or notifying the network administrator.



## Protocol State Machine

To effectively manage the challenge-confirm process, hosts implementing this specification need to maintain a state machine. The state machine, as shown in Figure 2, defines the operational states and state transitions for handling ICMP error messages and conducting challenge - confirm exchanges.

~~~
                      +-----------------+
                      |   Idle State    |
                      +-------+---------+
                              |  
                              | Receive ICMP Error
                              | (stateless embedded payload)
                              |
                      +-----------------+
                      |  ICMP Received  |
                      +-----------------+
                              |
                              |Send Subsequent Packet
                              v  
                      +-------+---------+
                      |  Challenge Sent |
                      +-------+---------+
                       _____/ | \________________
                      /       |                  \
         (Valid Response)   (Invalid Response)  (Timeout)
                    /          |                   \
                   v           |                    v
        +--------+-------+     +-----------+---------+
        |Process & Accept|     |   Discard & Log     |
        +--------+-------+     +-----------+---------+
                  |            |                     |
                  +------------+---------------------+
                              |
                              v  
                      +-------+---------+
                      |   Idle State    |
                      +-----------------+       

                  Figure 2: Protocol State Machine
~~~

In the Idle State, the host is in a standby mode, waiting for ICMP error messages. Once it receives an ICMP error message with a stateless embedded payload, it enters the ICMP Received tate and wait for a subsequent packet. Once a subsequent packet with challenge is sent, it enters  the Challenge Sent state. If a valid response (with the correct random number) is received within the predefined timeout period, the host transitions to the Process & Accept state. Here, it acknowledges the original ICMP error message as genuine and processes it accordingly. If the response is invalid (either the random number is incorrect or there are other discrepancies) or a timeout occurs, the host moves to the Discard & Log state. In this state, it discards the original ICMP error message, considering it potentially forged, and logs the event. This log can be used later for security audits and to identify potential attack patterns. After either accepting or discarding the message, the host returns to the Idle State, prepared to handle new ICMP error messages. This state-machine-based approach provides a structured and reliable way to manage the authentication process for ICMP error messages. 

## Random Number Generation and Management

- **Generation**: The receiver generates a high-entropy random number (minimum 128 bits) using a secure pseudorandom number generator (PRNG) to ensure unpredictability and resistance to guessing attacks.

- **Management**: Each challenge utilizes a unique random number to prevent replay attacks. The receiver maintains a cache of pending challenges, each associated with an expiration timer to manage resources effectively and avoid indefinite waiting periods.

## Integration with IP Options

To support the Challenge-Confirm mechanism, this document defines a new Challenge-Confirm Option. The challenge packet for a received ICMP error message containing a stateless protocol payload includes the following option (as shown in Figure 3) in the IP header. Similarly, the ICMP error message triggered in response to this challenge packet should also include the same option in the header of the embedded challenge packet (as shown in Figure 4).

~~~
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Option Type  |  Opt Data Len |          Reserved             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   Challenge Nonce (128 bits)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|             Stateless Protocol Data (UDP/ICMP packet)         |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure 3: The Challenge Packet Header with Random Number in IP Options

The fields in Challenge-Confirm Option are defined as follows:

*   **Option Type**: 8-bit identifier for the challenge-confirm option. The final value requires IANA assignment.
*   **Opt Data Len**: 8-bit unsigned integer specifying the length of the option data field in bytes.
*   **Reserved**: 16-bit field reserved for future use. MUST be set to zero on transmission and ignored on reception.
*   **Challenge Nonce**: 128-bit random number generated according to {{RFC4086}} requirements.

~~~
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             unused                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Version |  IHL  | Type of Service  |       Total Length       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Identification         | Flags |   Fragment Offset     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Time to Live    |  Protocol  |      Header Checksum        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Source Address                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Destination Address                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Option Type  |  Opt Data Len  |         Reserved            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |               Challenge Nonce (128 bits)                      |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Stateless Protocol Data (UDP/ICMP packet)             |
   |                     (Variable Length)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure 4: New ICMP Error Responding to the Challenge Packet

# Security Considerations

The proposed enhancements aim to bolster ICMP security by addressing specific vulnerabilities related to message authentication. Key security aspects include:

- **Authentication Strength**: Utilizing high-entropy random numbers ensures that challenges are unpredictable and resistant to forgery, effectively preventing unauthorized ICMP error message spoofing.

- **Replay Attack Mitigation**: Assigning unique random numbers to each challenge and implementing expiration timers mitigates the risk of replay attacks, where attackers attempt to reuse valid challenges to authenticate malicious messages.

- **Denial of Service (DoS) Prevention**: To prevent potential DoS attacks, where adversaries flood a host with fake challenges, rate limiting and challenge frequency controls are implemented. These measures ensure that the system can handle legitimate challenges without being overwhelmed by malicious traffic.

- **Backward Compatibility**: The proposed mechanism maintains backward compatibility by requiring updates solely to the ICMP error message verification on end hosts. Intermediate routing devices remain unaffected, ensuring seamless integration with existing network infrastructure.


# IANA Considerations

The Challenge-Confirm Option Type should be assigned in IANA's "IPv4 Option Type field" registry {{RFC2780}}.

This draft requests the following IP Option Type assignments from the IP Option Numbers registry in the Internet Protocol (IP) Parameters registry group (https://www.iana.org/assignments/ip-parameters).

| Copy  | Class | Number | Value | Name        | Reference    |
| ----- | ----- | ------ | ----- | ----------- | ------------ |
| TBD   | TBD   | TBD    | TBD   |  TBD        | This draft   | 



--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank the IETF community, particularly members of the INT-AREA working groups, for their valuable feedback and insights during the development of this proposal.
