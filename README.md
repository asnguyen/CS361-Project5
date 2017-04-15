UTEID: asn579
FIRSTNAME: Anthony
LASTNAME: Nguyen
CSACCOUNT: anthony
EMAIL: asnguyen@utexas.edu

[Program 5]
[Description]
There is one file that makes up AES.java program. Withen that code, the AES 
encryption process in broken up into its 4 parts. THe is a method for subByte,
rowShift, mixColumn(that was taken from Dr. Young's code), and addRoundKey. Each
method has an inverse pair that is use for the AES decryption. The key expansion
method was take from http://www.samiam.org/key-schedule.html pseudocode about the 
256 key expansion. To compile the program you simply use javac AES.java to run the 
program you run java AES [option] [key] [textfile]. The two options are e for 
encrypting and d for decrypting.

[Finish]

I finished most of the assignment. The encryption works and and the decryption 
works as well together

[Test Case 1]

[Command line]
java AES e testkey.txt testcase1.txt
java AES d testkey.txt testcase1.enc.de

[Timing Information]
Encrypting took 4462 milliseconds
Decrypting took 3610 milliseconds

[Filenames]
Encryption
	input: testkey.txt testcase1.txt
	output: expanded_key.txt testcase1.enc
Decryption
	input: testkey.txt testcase1.enc
	output expanded_key.txt testcase1.enc.dec



[Test Case 2]

[Command line]
java AES e key2.txt testcase2.txt
java AES d key2.txt testcase2.enc.de

[Timing Information]
Encrypting took 207 milliseconds
Decrypting took 191 milliseconds

[Filenames]
Encryption
	input: key2.txt testcase2.txt
	output: expanded_key.txt testcase2.enc
Decryption
	input: key2.txt testcase2.enc
	output expanded_key.txt testcase2.enc.dec




[Test Case 3]

[Command line]
java AES e key3.txt testcase3.txt
java AES d key3.txt testcase3.enc.de

[Timing Information]
Encrypting took 85 milliseconds
Decrypting took 82 milliseconds

[Filenames]
Encryption
	input: key3.txt testcase3.txt
	output: expanded_key.txt testcase3.enc
Decryption
	input: key3.txt testcase3.enc
	output expanded_key.txt testcase3.enc.dec


[Test Case 4]

[Command line]
java AES e key4.txt testcase4.txt
java AES d key4.txt testcase4.enc.de

[Timing Information]
Encrypting took 2090 milliseconds
Decrypting took 1953 milliseconds

[Filenames]
Encryption
	input: key4.txt testcase4.txt
	output: expanded_key.txt testcase4.enc
Decryption
	input: key4.txt testcase4.enc
	output expanded_key.txt testcase4.enc.dec


