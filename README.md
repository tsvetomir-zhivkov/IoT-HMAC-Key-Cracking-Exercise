# A cracking tool designed to recover a secret key used for HMAC-based message authentication by exploiting a buffer overrun vulnarability in a IoT device.

## Overview
This project demonstrates how a buffer overrun vulnarability in an Internet of Things (IoT) device can be exploited to recover a secret keyphrase. Once recovered, the key can be used to authenticate messages sent to the IoT device, potentially allowing an attacker to impersonate legitimate users and carry out further attacks. 

> [!IMPORTANT]
> The project was developed as part of a university course and targets a course-specific IoT device. This project can serve as a foundation for a larger project.


## Technologies
* `C/C++`
* `TCP sockets`
* `Message authentication`

## IoT Device
The IoT device receives commands over a TCP connection using the following message format:

`<user>;<command>;<hex_hmac>\n`

Where:
* `user` identifies the sender of the command (e.g., 002510).
* `command` specifies the command to be executed by the device.
* `hex_hmac` contains the hexademical representation of the HMAC used to authenticate the message.
* `\n` indicates the end of the message.

The HMAC is generated using the _SHA256_ cryptographic hash function and a secret key known only to the device and authorized users. The HMAC is computed from the following message:

`ClientCmd|<user>|<command>`

The IoT device authenticates the message using the HMAC before executing the specified command.

## Iot Vulnerability: Buffer Overrun
The buffer overrun vulnerability arises from the insufficient input validation in the device. Additionally, the secret key is stored in a memory region adjacent to the input buffer, allowing an attacker to recover it by exploiting the vulnerability.

## Vulnerability Exploitation
Initially, the keyphrase is overwritten with the character `a` by overflowing the input buffer with a string of a specified length. In each subsequent iteration, the command length is decreased until the device no longer accepts it. This process determines the number of cahracters needed to overwrite the keyphrase without affecting the momery beyond it.



Thereafter



## Video

