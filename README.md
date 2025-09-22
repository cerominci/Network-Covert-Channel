#  Covert Storage Channel that exploits Protocol Field Manipulation using Question - Class field in DNS

## *Project Overview*
This project implements a Covert Storage Channel (CSC) by exploiting Protocol Field Manipulation using the DNS Question-Class field.

### What is a Covert Channel?

A covert channel bypasses normal security controls and uses unintended system features to transfer information secretly. It is often used to exfiltrate data and is a key concern in cybersecurity.

### Method Used in This Project

- **Protocol Field Manipulation (PFM)**: Data is embedded into specific protocol fields, such as the DNS Question-Class field, which is not commonly monitored.

- **DNS Question-Class Field**: Encodes binary information by altering values (e.g., IN, CS, CH, HS).

By leveraging unused or uncommon DNS class values, the project achieves a covert communication channel with high capacity while maintaining operational stealth.

## *Implementation*

### Encoding Rule:

The sender encodes 2 bits of data into the DNS Question-Class field using predefined mappings:
- `00` → IN (1)
- `01` → CH (3)
- `10` → HS (4)
- `11` → CS (2)

### Communication Flow:

#### Sender:
Generates a binary message (128 bits).
Encodes the message into DNS packets by manipulating the Question-Class field.
Sends the packets to the receiver.

#### Receiver:
Captures DNS packets and extracts the Question-Class field values.
Decodes the binary message based on the predefined mappings.
Reconstructs the original message.

## *Parameter Constraints*

### Sender Parameters:
```python
send(self, interface, log_file_name, destIP, dnsPort, domainToQuery, enc00, enc01, enc10, enc11)
```

- `interface`: Network interface to send packets.
- `log_file_name`: Logs the sent binary message.
- `destIP`: Destination IP address for DNS queries.
- `dnsPort`: Port number for DNS communication (default is 53).
- `domainToQuery`: Domain name used in DNS queries.
- `enc00, enc01, enc10, enc11`: Custom values for encoding binary pairs.


### Receiver Parameters:
```python 
receive(self, interface, dnsPort, log_file_name, srcIP, dec1, dec2, dec3, dec4)
```

- `interface`    : Network interface to capture packets.
- `dnsPort`       : Port number to filter DNS packets (default is 53).
- `log_file_name`  : Logs the received binary message.
- `srcIP`          : Source IP address of the sender.
- `dec1, dec2, dec3, dec4`: Custom mappings for decoding DNS Question-Class values.

## *Covert Channel Capacity Measurement*

The covert channel capacity is calculated as follows:

- Generate a binary message of length 128 bits.
- Start a timer before sending the first packet.
- Stop the timer after sending the last packet.
- Calculate elapsed time and covert channel capacity:

```python
print(f"CC capacity: {128 / (t1-t0)}")
```
#### Covert Channel Capacity: 
Average Capacity ~ 16

## *Usage*
After starting the containers, firstly run
```bash
make receive
```
and then,
```bash
make send
```
Binary message will be successfully sent to the receiver side. 
To compare the sent and received messages to see whether the covert channel communication is a success, run
```bash
make compare
```
