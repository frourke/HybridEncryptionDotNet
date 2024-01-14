# HybridEncryptionDotNet
Sample .net8 application to implement the encryption process of a [hybrid cryptosystem](https://en.wikipedia.org/wiki/Hybrid_cryptosystem).

The sample can be run on Windows, Linux and MacOS.

The following settings are used.

|Item|Value|
|---|---|
|Text encoding|UTF8|
|Cipher|AES|
|Mode|GSM|
|AES Key size|256 bit|
|AES Nonce size|96 bit|
|AES Tag size|128 bit|
|RSA key size|2048 bit|

## Encryption

The encryption process is as follows:

1.  Securely obtains RSA Public Key (Key Encryption Key or KEK) in pem format.
2.  Generate a new AES symmetric key (Data Encryption Key or DEK), nonce and tag for the data encapsulation scheme. This AES key will be discarded when the session terminates. To ensure security, please do not persist this AES key for reuse.
3.  Generate a nonce for data encapsulation scheme. The nonce will be discarded once the session terminates. To ensure security, please do not persist this nonce for reuse.
4.  Encrypt the message under the data encapsulation scheme, using the AES symmetric key (DEK) and nonce just generated.
5.  Encrypt the AES symmetric key under the key encapsulation scheme, using RSA public key (KEK).
6.  Builds the encrypted file payload in the specified format.

For this sample the file payload is in the following format.

*base64RsaEncryptedAesKey*__|__*base64Nonce*__|__*base64Tag*__|__*base64AesEncryptedData*

## Command line
.\xPlatformEncrypt.exe publicKey=C:\temp\publickey\myPublicKey.pem file=C:\temp\data\mydata_19042023.csv

## Debugging
Update the debug configuration in launch.json with the desired pem and data file.

![image](https://github.com/frourke/HybridEncryptionDotNet/assets/15794624/cffa32bb-0bab-463b-a798-382f351639db)
