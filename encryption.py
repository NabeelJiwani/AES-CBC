#usr/bin/env python3

import re
import maskpass
from os.path import isfile, isdir
from sys import exit
from main import AES_CBC

#Colored Output Text Code for shell Output
red 	= "\033[1;31m" 		#Bright Red With Bold
green 	= "\033[1;32m" 		#Bright Green With Bold
white 	= "\033[1;37m" 		#White
blue 	= "\033[1;34m" 		#Bright Blue With Bold

def getpass(isnew=False, tries = 3):
	while True:
		passwd   = maskpass.askpass(mask='*')
		password = maskpass.askpass(prompt="Re-Enter Password: ", mask='*')
		if passwd == password:
			if isnew:
				print(f"""{green}\t\tPassword Should:\n
					1. At least one number.
					2. At least one UpperCase and one LowerCase Character.
					3. At least one Special Symbol.
					4. Be between 8 to 20 Character long.
					""")
				reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,20}$"
				pat = re.compile(reg)
				match = re.search(pat, passwd)
				if not match:
					print(f"{red}Password should follow the above listed conventions.")
					print("Invalid Password!")
				else :
					print(f"{blue}Please remember your password.")
					print("Otherwise, No possible way for Recovery.")
					return passwd
			else:
				return passwd
		else :
			tries -= 1
			if tries == 0:
				print("Tries Over.")
				print("Exiting Now.")
				exit(3)
			print("Re-typed Password doesn't Match.")
			print("Try Again.\n")

def DelFileIn():
	delfilein= input("\nDelete the Original File(Y/N): ")[:1].lower()
	if delfilein == 'y':
		return True
	else:
		return False


def main():
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
		\033[m\n""")
	
		
	print(f"{blue}Enter Your Choice:")
	print("0 - Quit")
	print("1 - Encrypt File.")
	print("2 - Decrypt File.")
	
	while True:
		try:
			choice = int(input(f"{green}Your Choice: "))
		except ValueError:
			print(f"{red}Please Enter Number, According to your choice.")
			continue
		if choice == 0:
			print(f"{white}See You Again.")
			exit(0)
		elif choice == 2 or choice == 1:
			break
		else:
			print(f"{red}Invalid Option")
	
	filein = input(f"{blue}\nFile Location: ")
	if not isfile(filein):
		print(f"{red}File Not Found.")
		print(f"Exiting Now..{white}")
		exit(2)

	print("\nHit Enter, If same as Input File Directory.")
	outpath = input("Output File Path(Directory Location): ")
	if outpath == "":
		outpath = None
	elif not isdir(outpath):
		print(f"{red}Not a Valid Directory Location.")
		print(f"Exiting Now...{white}")
		exit(2)

	if choice == 1:
		print(f"{blue}\nPlease Create Password.")
		passwd = getpass(isnew=True)
		enc = AES_CBC(passwd)
		delfilein = DelFileIn()
		enc.EncryptFile(filein, outpath, log=True, DelFileIn=delfilein)
	elif choice == 2:
		delfilein = DelFileIn()
		tries = 3
		while True:
			if tries == 0:
				print(f"{red}\nTries Over. Last Choice.")
				forced = input("Would you like to ForceFully Decrypt the File(Y/N): ")[:1].lower()
				if forced == 'y':
					forced = True
					dec.DecryptFile(filein, outpath, Forced=forced)
					exit(3)
				else:
					print("\nTries Over!")
					print(f"Exiting Now..{white}")
					exit(4)

			print("\nPlease Enter Correct Password.")
			passwd = getpass()
			dec = AES_CBC(passwd)
			succes = dec.DecryptFile(filein, outpath, DelFileIn=delfilein)
			if succes:
				break
			
if __name__ == '__main__':
	main()
	print(f"{green}\nThanks For Using !")
	print(f"Have a Great Day.{white}")
