## Overview
This project demonstrates how a buffer overrun/overflow vulnerability in an Internet of Things (IoT) device can be exploited to recover a secret keyphrase. Determining the keyphrase is accomplished by sending crafted commands of varying lenghts over a TCP connection, and analyzing the responses. Once the keyphrase is recovered, the attacker can generate valid message authentication codes (HMACs), allowing them to impersonate legitimate users and execute further attacks.

## Features
- **TCP communication**: Establish a connection with the IoT device and exchange commands
- **HMAC authentication** - Generate message authentication codes to communicate with the device
- **Buffer overflow analysis** - Identifies the inp
- **Automated keyphrase recovery**: Uses the
- 

## How the IoT Device Work
The IoT device receives commands over a TCP connection using the following format:

'<user>;<command>;<hec_hmac>\n'

Where:
- 'user' is the sender's identifier.
- 'command' is the command to execute.
- 'hex_hmac' is the hexademical representation of the HMAC used to authenticate the message.
- '\n' terminates the message.

The HMAC is generated using a message in the following format:

'ClientCmd|<user>|<command>'

The user and command correspond to the values in the original request. The HMAC is computed using a secret key shared with authorized users.

The IoT device uses the HMAC to verify the message authenticity before executing commands. However, its input-handling implementation contains a buffer overflow vulnerability that undermines this authentication mechanism.

## IoT Vulnerability: Buffer Overflow

IoT Insecurity: Buffer Overrun
An Internet-of-Things (IoT) device has a minor vulnerability called **Buffer Overrun** that will be exploited. It is given some prior information, such as key length, message formats and how does the device handle 
requests. I noticed that the device does not check the length of the command at all. Additionally, the keyphrase is inserted into the code and defined before the input array. According to a memory dump given in the 
task, the local variables are laid out in the call-stack memory in reverse order, meaning that it is possible to overwrite the keyphrase by supplying a long enough command. This sounds possible, because the length of the 
command is not checked. 

Idea of the program
The program does two things:
  1. Finds how many characters does the command need to overwrite everything before reaching the keyphrase memory slot.
  2. After that with that information, the program cracks the passphrase

How is the buffer overrun vulnerability exploited:
  After finding the characters amound required to overwrite everything begore reaching the keyphrase, and we know the length of the key as well, we can exploit that vulnerability to find the keyphrase of the device.
  This is accomplished by following the next steps:

  1. Generate a message that is that long that will overwrite the keyphrase without the last character.
  2. Then we generate a key with the characters that are used to overwrite the big portion of the phrase and place a random character from the ASCII lists.
  3. Then we authenticate the message using that key and send it to the IoT device. - if the device responses with invalid HMAC, the key is incorrect, if it responses with Authentication successfull, then the
     random character is in the memory and it is part of the keyphrase.
  4. We save the character that we found, and continue to the next character of the passphrase, going from right to left.
  5. We loop the steps till we get the whole password.

Kapani:
  While making the program, my logic was solid. I tried the program but it did not work at first, because any ASCII character did not matched the last character that was not overwritten. After while I noticed that the server
  creates a string, so the program adds a null terminator '\0' at the end, and it overwrites the last character of the passkey. I figured out that I could just use '0' as the part of the key, and a key may be for example 
  'aaaaaaaaaaaa\0aaaaa' and it will be valid, because the device knows that the length of the key is 20, so it does not stop at the first null terminator.

TOTAL TILE: ~ 15 hours
