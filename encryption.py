#usr/bin/env python3

import os, sys, time
from subprocess  import call
from os import listdir
from os.path import isfile, join
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import struct
import tkinter
from tkinter import filedialog
from tkinter import messagebox
import webbrowser


#Using Colored Output Text For Better Look!!
red 	= "\033[1;31m" 		#Bright Red With Bold
green 	= "\033[1;32m" 		#Bright Green With Bold
white 	= "\033[1;37m" 		#White
blue 	= "\033[1;34m" 		#Bright Blue With Bold

space 	= " "				#To print Spaces
namep 	= {}				

parent 	= tkinter.Tk()		#Tkinter parent Object
parent.overrideredirect(1) 	#Avoid it appearing and then disappearing quickly
parent.withdraw() 			#Don't Wanna See to Windows Withdrawing the Parent frame Window()
cwd 	= os.getcwd()		#Get Working Directory
"""
							Refer:  https://docs.python.org/3/library/tkinter.html
									https://docs.python.org/3/library/tk.html
									http://tcl.tk/man/tcl8.6/TkCmd/contents.htm
									https://tkdocs.com/tutorial/index.html
"""


#Clear Screen Function to clean Terminal Window
def clear():
	_ = call(('clear' if os.name =='posix' else 'cls'), shell=True)



#Check if File/Directory is Hidden
def ishide(filepath): 		
	name = os.path.basename(os.path.abspath(filepath))
	return True if name.startswith('.') else False 

# Accept only Integer value
def integer(message):
	while True:
		try :
			takeint = int(input(message+" "))
		except ValueError:
			print ("Not an Integer/Number.")
		else :
			return takeint  

#Print Beautiful * until count !
def aesterisk(count):
	i = 0
	for i in range(count):
		print("*", end = "")


"""
	These Function Lists the Files/Directory.
	Prompts the user Whether to Work in Current Directory or Not (Not Then ask the path to a Directory)
	
	After Enetering Correct Directory It Lists the Files/Folders Within it 
	And Stores the name of Files/Folders in a Dictionary which we created before(namep{})
	
	End: Return Correct Path.
		 if empty or operation cancelled by User then Exit

"""

def listit(context):

	cwd = os.getcwd()

	#Ask user 
	#messagebox.askyesno("title", "Query ") returns Boolean 
	ans = messagebox.askyesno("Confirm Action","Would you like  to "+context+" a file from Current Directory: ("+cwd+")?")
	

	if ans is not True:
		print ("Select a Folder to Enter.")

		while(True):
			"""
				filedialog opens a file Dialog box
				function filediaolg.askdirectory //Specifies it to return only Directory Path
				Format:
						filedialog.askdirectory(title, parent(window), initialdir..)\
				refer:  https://docs.python.org/3/library/dialog.html
						https://pythonspot.com/tk-file-dialogs/

			"""

			cwd = filedialog.askdirectory(title='Select a folder', parent=parent, initialdir = (os.environ["HOME"] if os.name == 'posix' else os.environ['HOMEPATH']) )
			
			
			if cwd == () or cwd == "":
				messagebox.askokcancel("No Folder was Selected.", "Operation cancelled by User.\nNow Exiting...")
				print (f"{red}You had Selected the Option to change Directory/Open Folder to {context} your Data," )
				print ("But you Did not select a folder to work with.")
				print (f"{blue}Bye! See You Again.{white}")
				exit()		#Exit when cancelled

			#Check Functionality, not needed tk does it works correctly but still , 
			#If u don't want to use a liitle bit of gui then helpfull
			if os.path.isdir(cwd) :
				if os.path.exists(cwd):
					os.chdir(cwd)	
					cwd = os.getcwd()	
					print("Entered : ",cwd)
					break
				else:
					print (cwd, " points to an Invalid Path.")
			else:
				print (f"{red}Directory doesn't exist!")
	else :					
		print ("Entered: ",cwd)

	# Now Listing of Files/Folders within it(cwd)
		
	subdf = os.listdir(cwd)
	print (f"{blue}ID List of Files\\Folder:"+space*42+"Type"+space*40+"Attributes\033[0;32m")
	
	t = ["File", "Folder   "]
	i = j = m = 0
	
	for i in range(len(subdf)):
		namep[i] = subdf[i]
		concate  = ""+str(i)+" "+subdf[i]
		ll       = len(concate)

		if os.path.isfile(os.path.join(cwd, subdf[i])):
			append = 5
			j 	   = 0
		else:
			j 	   = 1
			append = 0

		if ll <  24:
			m = 40+(24-ll)
		elif ll == 24:
			m = 40
		elif ll>24 & ll<44:
			m = (40+24)-ll
		else :
			m=0
		print (f"{i}. {namep[i]}"+space*m+"",t[j]+space*(36+append),end = "")
		print ("Hidden" if ishide(subdf[i]) else "" )
	return cwd 			


"""	
	Return Correct Key of a File Only.
"""

def getd_fkey(context ,cdir):
	print(f"\n{blue}Now its your time to select a File to {context}.")
	print(f"Above is the list of content in the Selected Directory, the above list has an ID for a file/Directory.\n")
	key = None
	helpme = 0 
	while True:
		key = integer(f"{blue}Enter ID of file to {context}{white}")
		if key < 0:
			print (f"{red}Negative ID not Allowed")
			print ("Try Again...\n")
		elif key > len(namep)-1:
			print (f"{red}Invalid ID Selected")
			print ("Enter Valid ID")
		else :
			path = os.path.join(cdir,namep[key])
			if os.path.isdir(path):
				helpme += 1
				print (f"{blue}\nHey that is not a {green}File.")
				print (f"{blue}Thats a Folder.")
				print ("Select a File")
				if helpme > 5:
					print("")
					aesterisk(30)
					print ("\nSeems like you are having a problem.")
					print ("Maybe I was not able to explain you something well.")
					print ("Opening help information on a Browser. ")
					url  = "https://www.differencebetween.com/difference-between-file-and-vs-folder/" #Good Source !!!
					webbrowser.open_new_tab(url)
					helpme -= 3
			else :
				print (f"{blue}Selected {green}",namep[key]," File.")
				return key

#simple function to return output filename 
def namefile(context, file):

	if context == "Encrypt":
		return file+".enc" 
	elif context == "Decrypt":				
		end = file[-4:]							# Grab last 4 str of file, Because we know that we had added extension ".enc" size :4
												# Substring
		if end == ".enc":						# If file ext is .enc which we had created remove .enc and return 
			return file[:-4:]					# Else add.dec and return
		else :
			return file+".dec"


"""
	Get the Checksum of a file
	Used  Hashlib 
	refer : https://docs.python.org/3/library/hashlib.html
"""
def getchecksum(cwd, file):
	hashsum = hashlib.sha256()									# Create hashlib Object

	with open(os.path.join(cwd,file), 'rb') as fl:
		for byte_block in iter(lambda: fl.read(64*1024),b""):	#iterate every block in chunk of size(here:64*1024) better for large files.
			hashsum.update(byte_block)							# for every block read in chunk update the hashlib object
	bytelike = hashsum.hexdigest().encode("utf-8")				# Digest the block and then create a byte object 
	return bytelike												# Return hashsum in bytes (Here We used SHA-256 hash it Exactly Returns 64 Bytes)


def getpass(limit =  10):
	tries = 0
	while tries < limit:
		pass1 = tkinter.simpledialog.askstring("Password", "Enter password:", show='*')
		pass2 = input(f"{blue}Confirm Your Password : {green}")
			
		if pass1 == pass2:
			if pass1 == "" or pass2 == "" or pass1 == None or pass2 == None:
				tries += 1
				print (f"{red}Empty password not allowed")
			elif len(pass1) < 8:
				tries += 1
				print (f"{red}Password Minimal length Allowed is 8.")
				print ("It is recommended that you create password of length more than 12.")
				print ("Better create a big passphrase!")
			else:
				break

		else :
			tries += 1  								
			print (f"{red}Password's Don't Match.")
			print (f"Try Again!!{green}")
		print (f"{green}Tries Left : {red}",(limit-tries))

	if tries >= limit :												
		print (f"{red}You weren't able to enter your password Corectly.")
		print ("Sorry Try Again !!!")
		print (f"{green}Now Exiting{white}")
		exit()
	else :
		return pass2

		
	
"""
	encryptfile(path, in_file, o_file, chunksize = 64*1024 ):

	path: path to Directory to Encrypt Data.
	in_file: name of the file in path(above)
	o_file: The Output file to write to. 
	chunksize: 
		These is Size in bytes (1kb = 1024 Bytes ) here : 64 kb

	
	1.Ask Password/Passphrase

	2.Key Derivation Function to generate a Secure key. More Precisely PBKDF
			PBKDF2(Password Based Key Derivation Function 2)
			Read More : 
						https://en.wikipedia.org/wiki/Key_derivation_function
						https://en.wikipedia.org/wiki/PBKDF2

		Why Use a PBKDF2,Why not simply Encrypt Data with the password/passphrase? etc
			Main reason password Streching and reduce Brute Force Attack(Cost of it).

		Read More about PBKDF2 :
						https://www.ietf.org/rfc/rfc2898.txt 				//Standard
						Section 5: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf 
						https://www.pbkdf2.com/
						https://cryptobook.nakov.com/mac-and-key-derivation/pbkdf2

	3.AES 256-bit Mode:CBC (Cipher Block Chain) for Encryption
		Why chose AES ? 				//your views may varry
			It is Considered to be Not Broken till now and is most secured and widely used in private sector and Security?
			perhaps, it would take billions of years using current computing technology to brute force an AES higher-level encryption cipher
		AES-256 CBC? 
			In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted.
			This way, each ciphertext block depends on all plaintext blocks processed up to that point.
			To make each message unique, an initialization vector must be used in the first block.
			Surface:
				The AES encryption algorithm goes through multiple rounds of encryption. It can even go through 9, 11, or 13 rounds of this.
					Each round involves the same steps below.

						Divide the data into blocks.
						Key expansion.
						Add the round key.
						Substitute/replacement of the bytes.
						Shift the rows.
						Mix the columns.
						Add a round key again.
						Do it all over again.
				After the last round, the algorithm will go through one additional round. In this set, the algorithm will do steps 1 to 7 except step 6.

				It alters the 6th step because it would not do much at this point. Remember it's already gone through this process multiple times.

				So, a repeat of step 6 would be redundant. The amount of processing power it would take to mix the columns again just isn't worth it as it will no longer significantly alter the data.

				At this point, the data will have already gone through the following rounds:

				128-bit key: 10 rounds
				192-bit key: 12 rounds
				256-bit key: 14 rounds
		I'm really Not a Crpto Guy, but overview is enough to uderstand.
		And the fact that python has libraries to do these operations Algorithm,Maths And rest is Easy!!!
	
	Read More : 
				https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
				https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
				https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
				Deep :
					https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

"""

def encryptfile(path, in_file, o_file, chunksize = 64*1024 ):
	 
	print ("Create Password \n")
	password = getpass()
	print ("Remember Your Password: ",password)
	print ("\nIf you loose your password, then there is no possible way to recover your Data!!")
	print ("Same password will be required to Decrypt these file.")
	print ("We Cannot help you if u forget your password.")

	iterate = 100000 										#iterations to performs for PBKDF2
	salt 	= get_random_bytes(16)							#Use random Salt 
			
	"""
			PBKDF2(password, salt, dkLen=16, count=1000, prf=None, hmac_hash_module=None)
    		Derive one or more keys from a password (or passphrase).\

    		password (string or byte string):
        		The secret password to generate the key from.
     		salt (string or byte string):
        		A (byte) string to use for better protection from dictionary attacks.
        		This value does not need to be kept secret, but it should be randomly
        		chosen for each derivation. It is recommended to use at least 16 bytes.
     		dkLen (integer):
        		The cumulative length of the keys to produce.
        	count (integer):
        	        The number of iterations to carry out. The higher the value, the slower
        	        and the more secure the function becomes.
        	    
        	        You should find the maximum number of iterations that keeps the
        	        key derivation still acceptable on the slowest hardware you must support.
        	    
        	        **it is recommended to use at least 1000000 (1 million) iterations**.
	"""
	key 	 = PBKDF2(password, salt, 32, count=iterate)	

	iv 		 = get_random_bytes(16) 					#AES-256 requires Initialization Vector of 16 bytes. Using random IV
	cipher 	 = AES.new(key, AES.MODE_CBC, iv)         	#AES Object
	checksum = getchecksum(path,in_file)				#Get Checksum of originally Supplied File(return is 64 byte )
	filesize = os.path.getsize(in_file)					#Get File Size

	"""
		When we go under Decryption process we will require same values to Decrypt the file Correctly
		my implementation may be different than the Practical case Scenario
		You may not want to store additional info (salt, checksum, filesize) in output file 
		It totally Depends on Use Case 
		My Implementation is not very practical in But it is Correct!
	"""
	with open(os.path.join(path,in_file), 'rb') as fi:
		with open(os.path.join(o_file), 'wb') as fo:
			fo.write(struct.pack('<Q', filesize))		#Write File Size to Output File using Struct it will be helpful to calculate the size back
			fo.write(checksum)							#Then Write Checksum Of Original File to output File 
			fo.write(salt)								#Write salt
			fo.write(iv)								#Write IV
			
			while True:
				chunk = fi.read(chunksize)				#read File in Chunks (Greater the Chunk Size it would be helpfull for very jumbo files)
				if len(chunk) == 0:
					break
				elif len(chunk)%16 != 0:				#In CBC Mode we require  data to be size of 16 Block Size and it should be padded if empty
					chunk = pad(chunk, 16)				#We Pad Data of last block if it is not exactly the size of Block size 
														#You may run print(AES.block_size) after importing AES to know block size
				fo.write(cipher.encrypt(chunk))			#Encrypt the data and store to output file

	print (f"Sucessfully Encrypted File : {in_file} and Stored the Encrypted file at {os.path.join(path,o_file)}")
	print ("Please Don't Modify the content of Encrypted file It will lead to Unsuccesful Decryption!!")
	print ("please Remember Your Password Corectly,  Without it you won't be able to Decrypt the data file, Correctly")
	print ('\n')
	print ("Delete the Original File Because Encrypted File is generated.")
	print ("Should We Delete Original File ? ")
	ask = messagebox.askokcancel('Delete Original File', 'Do you want to Delete the Original File ? ', parent=parent)
	if ask :
		os.remove(os.path.join(path, in_file))
		print ("Deleted the Original file.")
	print ("\nThanks For Using \U0001f600.")

"""

"""
def decryptfile(path, in_file, o_file, forced = False, chunksize = 64*1024 ):
	iterate 	 = 100000
	password 	 = getpass()
	with open(os.path.join(path, in_file), 'rb') as fi:
		origsize = struct.unpack('<Q', fi.read(struct.calcsize('Q')))[0]	#since we had used struct to write size, knowing the exact byte size of the written value is helpfull
		checksum = fi.read(64).decode("utf-8")								#read next 64 bytes that will be our check sum
		salt 	 = fi.read(16)												#as we had stored salt of 16 bytes read it
		iv 		 = fi.read(16)												#next 16 bytes is salt
		key 	 = PBKDF2(password, salt, 32, count=iterate)				#derive key from salt and password provided by user
		cipher   = AES.new(key, AES.MODE_CBC, iv)							#create AES Object

		with open(os.path.join(path, o_file), 'wb') as fo:					#Binary Mode File Write Acces "wb"

			while True:
				chunk = fi.read(chunksize)									#read in chunks
				if len(chunk) == 0:	
					break 
				fo.write(cipher.decrypt(chunk))								#decrypt and store in new file
			fo.truncate(origsize)											#because we had padded the end chunk truncate the file from end to remove unnecessary bytes of data at end
	"""
		So a Succesfull Decryption will genearate an original file
		so at end we compare the hash of original file which we had store in encrypted file now we read at first,
		to the hash of generated output file(o_file which was created)

		if both hashes are same means we have obtained the original file which was earlier Encrypted
		else you know 
	"""

	if forced :
		print ("Not verifying the output file/content was Original or not!")
		print ("Output file stored at : ", (path+os.sep()+o_file))
		print ("")
		print (f"Exiting...{white}")
		exit()
	return checksum


"""
	Main Function !!!!!!
"""	 
def main():

	clear()
	#
	print(""" 
		\033[1;31m\t\t\t.###.....##.\033[1;31m..##########.
		\033[1;31m\t\t\t.####....##.\033[1;31m......##.....
		\033[1;31m\t\t\t.##.##...##.\033[1;31m......##.....
		\033[1;31m\t\t\t.##..##..##.\033[1;31m......##.....
		\033[1;31m\t\t\t.##...##.##.\033[1;31m......##.....
		\033[1;31m\t\t\t.##....####.\033[1;31m.##...##.....
		\033[1;31m\t\t\t.##.....###.\033[1;31m.#######.....
		\033[m========================================================================
		\033[1;32mCreated By \033[1;31mAnoni \U0001F60A	
		\033[32mChannel: \033[1;31mhttps://www.youtube.com/channel/UC4nAAguI5U3c7UVSDnZ7stg/about \033[m\n""")
	#My LOGO ! 
		

	choice = input(f"{blue}Please Select One of the following\n1.{green} Encrypt Data \n{blue}2.{red} Decrypt Data\n{blue}Choice:{white}")
	temp = choice
	choice = choice[:1]
	try :
		choice = int(choice)
	except ValueError:
		choice = temp

	print(f"{green}")	
	if choice == 1:
		context = "Encrypt"
		cwd 	= listit(context)
		id 		= getd_fkey(context, cwd)
		file 	= namep[id]
		outfile = namefile(context, file)
		encryptfile(cwd, file, outfile)

	elif choice == 2:
		context	="Decrypt"
		cwd 	=listit(context)
		id 		= getd_fkey(context, cwd)
		file 	= namep[id]
		outfile = namefile(context, file)
		tries	= 0
		while True:
			checksum = decryptfile(cwd, file, outfile)
			validatechecksum = getchecksum(cwd, outfile).decode("utf-8")
			if checksum == validatechecksum:
				print(f"{blue}\nDecryption was Sucesfull!!")
				print(f"Thanks for using.{white}  \U0001f600\n\n")
				os.remove(os.path.join(cwd, file))
				break
			else :
				tries += 1
				print (f"{red}\nDecryption was not Succesfull!!")
				print ("\nEither password is Incorrect \n\t\tOR")
				print (f"The file( {file} )you provided us to Decrypt has been Tamperred or Modified.")
				print ("Try Again !!!")
				print ("Attempts: ",tries)
				os.remove(os.path.join(cwd, outfile))
				time.sleep(1)

				if tries>5:
					print (f"{red}\nYour Attempts to Decrypt the Encrypted file limit has been reached")
					aesterisk(12)
					print (" Caution " , end="")
					aesterisk(12)
					print (f"\n\n\t\t\t{green}Notice :")
					print (f"\n{red}1. Firstly, we Don't store your password with us.")
					print ("\tThese totally means that there is no possible option to recover your password.")
					print ("\tYou were instructed to Remember your password while Encrypting you file.")
					print ("\tWe Cannot help u in these case.")
					print ("\tIf you lost you password, it means you lost the data totally!")
					print ("\tHey!! Try to Remember the password or even make few Guesses!! ")
					print ("\n2.File u provided us is to Decrypt is not the Encrypted file made by these program!!")
					print ("\tThink how can we Decrypt the file Which we did not Encrypt.")
					print ("\n3. The file you gave us is Tempered/changed/Modified.")
					print ("\tModifing an Encrypted Data file leads to corruption of file.")
					print ("\tWhile Decrypting the file output will be wrong becaause file data was changed and it will lead to Unsuccesful Decryption.")
					print ("\tIt is not Possible to Decrypt the file which was modified or corrupted")
					print ("\n\nDecrypting Forcefully:")
					print ("Decryption of Data total Depends on the Passphrase you provide and the Encrypted Data provided by you to Decrypt")
					print ("In Case, Any of the Above Conditions are True,")
					print ("Forcefully Decrypting the file will give you a corrupted or may give you the original file if and only if the password is True.")
					print ("What we do ?")
					print ("We simply skip the check of verifying the output file is Original or Not,")
					print ("And we give you the output of data while Decrypting!!")
					time.sleep(5)
					decryptfile(cwd, file, outfile, forced = True)

	else:
		
		aesterisk(24)
		if(choice.isnumeric()):
			print("\n\nInvalid Choice.")
			print("Current Available Options are 1 & 2\n")
			aesterisk(24)
		else:
			print ("\n\nInvalid Choice")
			print (f"{choice} is not a Number\n")
			aesterisk(24)
			print ("\nTry Again!!")
			print ("Now Exiting....")
			print (f"Bye!!{white}")

if __name__ ==  '__main__':
	main()
