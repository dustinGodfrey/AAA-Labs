

# Phase 1: Certificates and PKI with OpenSSL

## Step 1: Generate a Private Key for Certificate Authority

```bash
openssl genrsa -out ca.key 2048
```

 Generates a private key for Certificate Authority
 
- openssl - OpenSSL toolkit
- genrsa - Generate an RSA private key
- -out ca.key - save the output (private key) to a file called ca.key
- 2048 - The key length in bits - 2048 is secure and common for PKI

I now have a private key that can be used to sign certificates


## Step 2: Create a Self-Signed Certificate for the Certificate Authority

```bash
openssl req -new -x509 -key ca.key -out ca.crt -days 365 -subj "/CN=DustinRootCA"
```

Creates a self-signed certificate for the Root Certificate Authority using the private key from step 1

- req - Request a certificate or generate a certificate signing request (CSR)
- -new - Generate a new certificate request or cert
- -x509 - Output a self-signed X.509 certificate instead of a CSR
- -key ca.key - Use the private key we created
- -out ca.crt - Save the self-signed cert to ca.crt
- -days 365 - Set the certificate to be valid for 1 year
- -subj "/CN=DustinRootCA" - subject field: Common Name (CN) for the certificate


## Step 3: Create a Certificate Signing Request (CSR) for a Client or Server Cert

```bash
openssl genrsa -out user.key 2048
```

Generate the private key for the client/server/user who is requesting a certificate

The first key we created `ca.key` is the Root CA's private key. It is used to sign a cert and should never be shared. This key, `user.key` is an end entity's private key (user or server) and is used to request a certificate so it can have its own

```bash
openssl req -new -key user.key -out user.csr -subj "/CN=client.local"
```

Uses the private key just created `user.key` to create a digitally signed request `user.csr`

This request includes: Public Key + Identity Info
Will be handed to the CA for signing


## Step 4: Sign the CSR with Root CA

```bash
openssl x509 -req -in user.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out user.crt -days 365
```

- x509 - Output a signed X.509 certificate 
- -req - Treat input as a CSR
- -in user.csr - The CSR to be signed
- -CA ca.crt - The Root CA certificate
- -CAkey ca.key - The Root CA private key (to sign cert)
- -CAcreateserial - Creates a serial number file (ca.srl) if it does not exist
- -out user.crt - Output file, signed certificate

Inspect the cert data with:
```bash
openssl x509 -in user.crt -text -noout
```


## Cheat Sheet

`openssl req -new -x509`
- Make a self-signed CA cert

`openssl req -new`
- Make a CSR for a user/server cert

`openssl x509 -req`
- Sign a CSR with your CA


## Step 5: Simulate a Digital Signature Process

Create a file to sign:
```bash
echo "Security token for API authentication rotation" > message.txt
```

Sign the file with the private key:
```bash
openssl dgst -sha256 -sign user.key -out message.sig message.txt
```

- Hashes the contents of messages.txt with SHA-256
- Encrypts the hash with user.key (user private key)
- Save the results to message.sig (user digital signature)

Verify the signature with the public key:
```bash
openssl dgst -sha256 -verify <(openssl x509 -in user.crt -pubkey -noout) -signature message.sig message.txt
```

>[!note] `<(openssl x509 -in dustin_pubkey.crt -pubkey -noout)` uses the concept of substitution to create a temporary file, instead of pulling out the public key to another file then running the verify command on that
- `openssl dgst -sha256`
	- Calculate a digest of a file
	- You will hash the file, then verify that this hash matches the one that was signed with the private key
- `-verify`
	- Tells OpenSSL to verify a digital signature using a public key
	- Must be in PEM format
	- Key in inside of user.crt, not in a PEM file
- `openssl x509 -in user.crt -pubkey -noout`
	- -in user.crt: reads the certificate
	- -pubkey: extract the public key from the certificate
	- -noout: Don't print the cert details, just the key
- `-signature message.sig`
	- Tells openssl "Here is the digital signature file"
	- Openssl will decrypt this file using the public key and extract the original has
- `message.txt`
	- Original data that was signed
	- Openssl will:
		- Hash message.txt with SHA256
		- Compare this has to the decrypted hash from the signature


## Simulation of Confidential Message Exchange

Generate a key pair for the recipient

```bash
openssl genrsa -out recipient.key 2048
openssl rsa -in recipient.key -pubout -out recipient.pub
```

Creates:
- recipient.key - Private key (for them)
- recipient.pub - Public key (shared with me)

Create a message as the sender
```bash
echo "Privileged access credentials for database administrators" > secret_message.txt
```

Encrypt the message using the recipient's public key
```bash
openssl pkeyutl -encrypt -inkey recipient.pub -pubin -in secret_message.txt -out encrypted.bin
```

- Takes the plaintext secret_message.txt
- Encrypts it with recipient.pub (public key)
- Saves binary ciphertext as encrypted.bin
	- Only recipient.key can decrypt this now

Recipient decrypts using their private key
```bash
openssl pkeyutl -decrypt -inkey recipient.key -in encrypted.bin
```


### To let someone send me an encrypted message

Share: dustin_pubkey.crt
- Contains public key
- They use it to encrypt a message to me
- Only I can decrypt it (with user.key)

### To let someone verify my identity / signature

Share: ca.crt
- User.crt was signed by my CA
- They use ca.crt to verify:
	- That user.crt is legitimate
	- That is was issued by a trusted CA (me)



# Phase 2: Simulate 802.1x + EAP Auth Flow


### Setting up RADIUS server


Install the FreeRadius Server on Ubuntu Server VM

```bash
sudo apt update && sudo apt install freeradius -y
```


### Enable and Configure EAP in FreeRadius

Switch to root to navigate and edit FreeRadius
```bash
sudo -i
```

**Need to copy certs from Phase 1 to the Ubuntu Server VM 
	ca.crt, dustin_pubkey.crt, dustin.key**
	rename to:
	**ca.crt, server.crt, server.key**
	only for server-side use to avoid confusion


> [!tip] **From Scratch :**
>- On server: create a Private CA
>- On server: Generate private key, CSR, and sign
>- On server: configure mods-enabled/eap (below)
>- On supplicant: copy ca.crt from server to supplicant

Add to directory:
`/etc/freeradius/3.0/certs`

Set permissions to user `freerad` can access certs
```bash
chown freerad:freerad /etc/freeradius/3.0/certs/*

chmod 640 /etc/freeradius/3.0/certs/*.crt

chmod 600 /etc/freeradius/3.0/certs/*.key
```

Navigate to the EAP config
```bash
sudo nano /etc/freeradius/3.0/mods-enabled-eap
```

Find and Edit:
```bash
tls-config tls-common{
```
	private_key_file = path/to/key
	certificate_file = path/to/cert
	ca_file = path/to/ca

Comment out:
	`private_key_password`


### Start FreeRADIUS in Debug Mode

**Most important step while configuring. Starts FreeRADIUS in foreground debug mode, showing detailed logs, cert loading, EAP negotiation, and errors**

```bash
freeradius -X
```

*If you get the error: Failed binding to auth address * port 1812 bound to server default: address already in use*

*You can pipe the output to a file with `freeradius -X | tee radius_debug.log*

```bash
sudo systemctl stop freeradius.service
freeradius -X
```

*Ready to proceed when no errors and "Ready to process requests"*

**Keep FreeRADIUS running and open another shell**

> [!info] From here on, choose which EAP type you want to work with and move to that section 


## EAP-TTLS Lab

### Add a test EAP User

 EAP-TTLS
	- Secure tunnel with only server-side cert
	- Client uses password inside
	- Cert Requirements - Server cert only

Edit the FreeRADIUS users file:
```bash
nano /etc/freeradius/3.0/users
```

Scroll to test user 'bob' and add this test user underneath:
```bash
dustin Cleartext-Password := "testpass"
```


### Test with a Supplicant

*On kali machine*
```bash
sudo apt install freeradius-utils
```

Create a config file (eapol.conf) in your home directory:
```ini
network={
    key_mgmt=WPA-EAP
    eap=TTLS
    identity="dustin"
    password="testpass"
    phase2="auth=PAP"
    ca_cert="/home/attacker/pki/ca.crt"

}
```

>[!important] For PEAP and TTLS, we use password authentication. Therefore, the identity and password for these must match the user created under `/etc/freeradius/3.0/users

On FreeRADIUS server, add supplicant(kali) IP address to:
```bash
sudo nano /etc/freeradius/3.0/clients.conf
```

This tells the FreeRADIUS server who is allowed to send RADIUS packets to the server
```ini
client kali {
    ipaddr = 192.168.8.11
    secret = testing123
}
```

	sudo systemctl restart freeradius
	sudo systemctl stop freeradius


On Supplicant (kali), run:
```bash
sudo eapol_test -c eapol.conf -a 192.168.8.227 -p 1812 -s testing123
```
*where ip is server ip*
and watch the output on the FreeRADIUS server `freeradius -X`

<p align="center"> <img src="https://i.imgur.com/IqVm5bY.png" width="75%" alt="image1"/></p>
<p align="center"> <img src="https://i.imgur.com/htW9c37.png" width="75%" alt="image2"/></p>
### EAP-TLS Authentication Result (Supplicant)

Key indicators of success:
- EAP-Success received
- PMK derived from EAPOL
- No MPPE key mismatches


if successful, continue:


### Results of EAPOL test

eapol_test simulates a WPA/WPA2-Enterprise client (supplicant) initiating an 802.1x EAP authentication to a RADIUS server.

-  Allows you to test EAP types like PEAP, TTLS, EAP-TLS, etc without needing a wireless AP or real supplicant


1. eapol_test reads the eapol.conf on the kali supplicant

2. conf provides identity, password, key management, EAP type (TTLS), phase2, and the ca.crt

3. Connection initiated to RADIUS Server (ubuntu) using UDP 1812 as RADIUS default. A fake EAPOL-Start packet is sent to start the process

4. TLS Handshake Starts
	1. TLS v1.2 handshake begins
	2. The CA cert at /home/attacker/pki/ca.crt is used to verify the RADIUS server's certificate ( a copy of the server CA cert (ca.crt) was sent to the supplicant for trust of anything that is signed by that CA)
	3. On success: Cert is valid and signed by the trusted CA. A secure TLS tunnel is now established between client and RADIUS

5. Inner Authentication Started (Inside TLS Tunnel)
	1. EAP-TTLS allows the actual user/password authentication to occur inside this encrypted tunnel
	2. auth=PAP:
		1. username `dustin` and password `testpass` are sent in cleartext, but within an encrypted tunnel
	3. These credentials are checked against the `users` file

6. Server Accepts Credentials
	1. FreeRADIUS verifies the creds

7. Session Complete

### EAP-TTLS Flow

> [!abstract] Supplicant <> `EAPOL` <> Authenticator <>`RADIUS` <> FreeRADIUS

1. Supplicant connects to network
	-  The device is physically or wirelessly connected but not yet authenticated 

2. EAPOL exchange begins
	- Supplicant sends EAP-START over EAPOL to the authenticator

3. Authenticator forwards EAP to RADIUS server
	- Authenticator does EAP pass-through - wrapping EAP inside RADIUS over UDP

4. RADIUS Server sends server certificate to supplicant
	- Server sends its X.509 certificate to supplicant
	- Supplicant checks this against a trusted CA in its cert store (this cert needs to be pre-installed or copied over. not delivered during handshake)

5. TLS tunnel is established (but only 1-way auth here)
	- Only the server is authenticated via cert (supplicant is authenticated via the handshake)
	- This creates a secure TLS tunnel between the supplicant and RADIUS server

6. Inner authentication occurs
	- Inside the tunnel, supplicant sends credentials - often:
		- Username + password
		- or MSCHAPv2, PAP, or another supported method
	- These inner credentials are protected by the encrypted tunnel

7. RADIUS server validates credentials
	- If valid, it sends back Access-Accept

8. Authenticator opens the port
	- Now the supplicant is allowed access to the LAN or WiFi

## EAP-TLS Lab

>[!important] Need to have root CA (ca.key & ca.crt) certs on the RADIUS server under `/etc/freeradius/3.0/certs`


### Generate Client Key and Cert on FreeRADIUS Server

```bash

cd /etc/freeradius/3.0/certs

openssl genrsa -out client.key 2048
```

### Generate CSR and Sign with Root CA on FreeRADIUS Server

```bash

openssl req -new -key client.key -out client.csr -subj "/CN=client.local"

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

### Copy Required Files to Client

Copies the new client public and private key as well as the root ca cert
```bash
scp /etc/freeradius/3.0/certs/client.crt attacker@192.168.8.11:~/pki/

scp /etc/freeradius/3.0/certs/client.key attacker@192.168.8.11:~/pki/

scp /etc/freeradius/3.0/certs/ca.crt     attacker@192.168.8.11:~/pki/

```

### Create a EAP-TLS Config on Client

```bash
nano /home/attacker/pki/eapol_tls.conf
```

```ini
network={
    key_mgmt=WPA-EAP
    eap=TLS
    identity="client.local"
    ca_cert="/home/attacker/pki/ca.crt"
    client_cert="/home/attacker/pki/client.crt"
    private_key="/home/attacker/pki/client.key"
}

```
> [!important] Identity must match the Common Name from the cert creation above


### Running EAPOL_Test

```bash
sudo eapol_test -c eapol_tls.conf -a 192.168.8.227 -p 1812 -s testing123
```


### EAP-TLS Flow

> [!abstract] Supplicant <> `EAPOL` <> Authenticator <>`RADIUS` <> FreeRADIUS

1. Supplicant connects to network
	- The device is physically or wirelessly connected but not yet authenticated

2. EAPOL exchange begins
	- Supplicant sends `EAP-Start` over EAPOL to the authenticator

3. Authenticator forwards EAP to RADIUS server
	- Authenticator performs EAP pass-through, encapsulating EAP messages inside RADIUS packets (UDP/1812)

4. RADIUS server sends server certificate to supplicant
	 - FreeRADIUS presents its X.509 certificate
	 - Supplicant verifies this certificate using a pre-installed trusted CA

5. Supplicant sends its client certificate
	- Supplicant responds with its own X.509 certificate
	- Server verifies the client cert against its trusted CA and ensures it was signed by that authority

6. Mutual TLS authentication occurs
	- Both sides prove possession of their respective private keys
		- *Exchange of Certificates*:
			- Server sends server.crt to client
			- Client sends client.crt to server

			- During the handshake, the TLS protocol asks each party to digitally sign a piece of data
			- The other side uses the sender's public key to verify that signature
	- No usernames or passwords are used - authentication is certificate-based
	- A secure TLS tunnel is established using both parties' public/private key pairs

7. RADIUS server validates client certificate
	- If the certificate is valid and trusted, FreeRADIUS sends back `Access-Accept`

8. Authenticator opens the port
	- Supplicant is granted full network access


## PEAP (MSCHAPv2) Lab


> [!info] Make sure to have the Root CA cert (ca.crt) on the supplicant machine:


### Create PEAP Configuration File on Client

```bash
nano eapol_peap.conf
```

```ini
network={
	key_mgmt=WPA-EAP
	eap=PEAP
	identity="dustin"
	password="testpass"
	ca_cert="/home/attacker/pki/ca.crt"
	phase1="peaplabel=0"
	phase2="auth=MSCHAPV2"
}
```
>[!important] For PEAP and TTLS, we use password authentication. Therefore, the identity and password for these must match the user created under `/etc/freeradius/3.0/users`

phase1 = The outer TLS tunnel setup  - "Set up an encrypted tunnel using the servers's certificate"

phase2 = How the user authenticates inside the tunnel - "Authenticate the user inside the TLS tunnel using MSCHAPv2"


### Run the EAPOL_TEST

```bash
sudo eapol_test -c eapol_peap.conf -a 192.168.8.227 -p 1812 testing123
```


### EAP-PEAP Flow

> [!abstract] Supplicant <> `EAPOL` <> Authenticator <> `RADIUS` <> FreeRADIUS

1. Supplicant connects to the network
	- Device connects to the LAN or WiFi, but is not authenticated

2. EAPOL handshake begins
	- Supplicant sends `EAP-Start` to the Authenticator

3. Authenticator forwards EAP to RADIUS
	- It encapsulates EAP messages in a RADIUS packet and forwards them to FreeRADIUS

4. Server certificate send
	- FreeRADIUS sends its X.509 server certificate to the supplicant
	- Supplicant verifies this using a pre-installed trusted CA certificate (ca.crt)

5. TLS tunnel established (1-way auth)
	- Only the server is authenticated using its cert
	- A secure TLS tunnel is created for inner authentication

6. Inner authenticator begins
	- Inside the tunnel, the supplicant sends:
		- identity = dustin
			- can set `anonymous_identity` in the `eapol.config` on client to hide username during tunnel auth
		- password = testpass 
		- Using MSCHAPv2 as the inner auth protocol
	- These match an entry in the RADIUS `users` file

7. RADIUS validates user credentials
	- If username + password are correct, per the `users` file, RADIUS sends `Access-Accept`

8. Authenticator opens the port
	- The supplicant is now granted network access



## Capturing Authentication Handshake with Wireshark


### Required for this lab:
- `ca.crt` - Root Certificate Authority
- `dustin.key` - Sender Key (Signing Key)
- `dustin_pubkey.crt` - Sender pub cert (Signing Cert)
- `capture_message` - Message to send
- `recipient.pub` - Receiver's public key
- `recipient.key` - Receiver's private key

### Generate a Message

```bash
echo "Security policy update approved by the Information Security Office" > capture_message.txt
```

### Digitally Sign the Message - Creating message Integrity and Authenticity

```bash
openssl dgst -sha256 -sign dustin.key -out capture_message.sig capture_message.txt
```

*This creates a digital signature – capture_message.sig – by hashing the message with SHA-256 and encrypting the hash using private key*

### Verify the Digital Signature
###### Perform on Kali - acting as the recipient for the test

```bash
openssl dgst -sha256 -verify <(openssl x509 -in dustin_pubkey.crt -pubkey -noout) -signature capture_message.sig capture_message.txt
```

>[!note] `<(openssl x509 -in dustin_pubkey.crt -pubkey -noout)` uses the concept of substitution to create a temporary file, instead of pulling out the public key to another file then running the verify command on that
*Uses corresponding public key to verify signature*


### Start Wireshark Capture on Kali

Apply the following filter to Wireshark:
	`radius || eap || tls`


### Trigger EAP-TLS Authentication from Kali

```bash
sudo eapol_test -c eapol_tls.conf -a 192.168.8.227 -p 1812 -s testing123
```

### Stop Capture and Review Packets


<p align="center"> <img src="https://i.imgur.com/M59f1V2.png" width="75%" alt="image1"/></p>

###### Packet 1:
- Supplicant sends Access-Request to the RADIUS server
	- Begins 802.1x/EAP authentication

###### Packet 2:
- RADIUS server responds with an Access-Challenge.
- This includes an EAP-MD5 Challenge
	- This is not for the final negotiation. It is a small test to validate basic communication before moving to the handshake
	- Includes the value to be hashed in the packet

###### Packet 3:
- The supplicant tells the server "I do not support MD5, I want to use EAP-TLS instead"
	- This is done through Response: Nak, Desired Auth Type: TLS EAP

###### Packet 4:
- The server now responds, accepting the use of TLS EAP, and sends the flag to start the handshake process.
- Start flag = 0xa0

###### Packet 5:
- The supplicant now responds to the server with a "Client Hello"
- Also includes TLS version, cipher suites, and extensions

###### Packet 6:
- The server responds with 4 segments, which are TLS Fragmentations, spread across multiple packets
- Server responds with Fragment #1
- The fragmentations are then reassembled in Packet 10
	- Packet 10 contains:
		- Server Hello
		- Server Certificates
			- Proves identity of the server
		- Server Key Exchange
			- Used for ephemeral key exchange
		- Certificate Request
			- *Server is not explicitly requesting a client certificate, which only happens in EAP-TLS*
		- Server Hello Done
			- Marks the end of the server's portion of the handshake

###### Packet 7:
- Supplicant listens for fragments

###### Packet 8:
- Server continues the packets.
- Fragment #2

###### Packet 9:
- Supplicant continues to listen for fragments

###### Packet 10:
- Server finalizes the segments.
- Fragment #3 and #4
- Now the full Server Hello is finished, including:
	- Server Hello
	- Server Certificates
	- Server Key Exchange
	- Certificate Request to the Supplicant
	- Server Hello Done to finish handshake

###### Packet 11: *Wireshark Packet 12*
- The supplicant begins to send its TLS credentials to the server
- These are fragmented over the next 2 frames.

###### Packet 12: *Wireshark Packet 13*
- Server listens for fragments from the supplicant

###### Packet 13: *Wireshark Packet 14*
- Supplicant finalizes the segments
-  Reassembled:
	- Client Certificate
		- Proves client identity
	- Client Key Exchange
		- Contains the premaster secret encrypted with the server's public key
	- Certificate Verify - *Very Crucial Step*
		- Cryptographic proof that the client possesses the private key for the cert it presented
	- Change Cipher Spec
		- Tells the server "I am switching to encrypted traffic now"
	- Encrypted Handshake Message
		- Final handshake message, now encrypted with the session key

###### Packet 14: *Wireshark Packet 15*
- Server accepts the Cipher Change
- Server responds with Encrypted Handshake Message

###### Packet 15: *Wireshark Packet 16*
- This is a quiet frame from the Supplicant
- Waiting on the server to Accept them
- Supplicant does send a Length Included: False and a More Fragments: False to let the server know that it is finished sending data

###### Packet 16: *Wireshark Packet 17*
- Mutual Authentication is Successful
- The server finally sends the Access-Accept flag
- Success (3)





