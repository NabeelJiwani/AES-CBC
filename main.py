import hashlib
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA3_256
from Crypto.Util.Padding import pad
from os.path import isfile, dirname, join, basename, abspath, isdir, getsize
from os import remove

red 	= "\033[1;31m" 		
green 	= "\033[1;32m" 		
white 	= "\033[1;37m" 		
blue 	= "\033[1;34m"

class AES_CBC():
    BS = AES.block_size                                                                                    
    def __init__(self, password:str):
        assert isinstance(password, str), "Password should be instance of <class 'str'>"
        self.__password = password 
        self._salt       = get_random_bytes(AES_CBC.BS)
        self.saltlen     = AES_CBC.BS
        self._key        = PBKDF2(self.__password, self._salt, 32, count=100000, hmac_hash_module=SHA3_256)   #Defaulting
        self._iv         = get_random_bytes(AES_CBC.BS)
        self._chunksize  = 64*1024
    
    def genkey(self, salt:bytes, count=100000 ):
        assert isinstance(salt, bytes), "Salt should be instance of <class 'bytes'>."
        self._salt    = salt
        self.saltlen  = len(salt)
        self._key     = PBKDF2(self.__password, self._salt, 32, count=count, hmac_hash_module=SHA3_256)      
    
    def updateiv(self, iv:bytes, br=True):

        if len(iv) == AES_CBC.BS:
            try:
                assert isinstance(iv, bytes)
            except AssertionError:
                if br:
                    raise Exception("IV should be instance of <class 'bytes'>.")
                else:
                    self._iv = get_random_bytes(AES_CBC.BS)
            else:
                self._iv = iv
        else:
            if br:
                raise Exception("IV Should be of length: "+AES_CBC.BS)
            else:
                self._iv = get_random_bytes(AES_CBC.BS)

    def updatechunksize(self, chunksize:int):
        assert isinstance(chunksize, int), "ChunkSize should be instance of <class 'int'>"
        self._chunksize = chunksize
    
    
    def genhash(self, file):
        hash = hashlib.sha3_256()
        with open(file, 'rb') as fi:
            for byte_block in iter(lambda: fi.read(self._chunksize),b""):	
                hash.update(byte_block)
        hashinbytes = hash.hexdigest().encode("utf-8")
        return hashinbytes

    def comparehash(self,checksum, file):
        fhash = self.genhash(file).decode("utf-8")
        if checksum == fhash:
            return True
        return False


    def EncryptFile(self, FileIn:str, OutPath=None, log=True, DelFileIn=True):
        if isfile(FileIn):
            FileOut = join(dirname(FileIn), (basename(FileIn)+".enc"))

            if OutPath is not None:
                if isdir(OutPath):
                    FileOut = join(OutPath, (basename(FileIn)+".enc"))
                else:
                    print(f"{red}\nDefaulting Output Path to {dirname(abspath(FileIn))} {white}")

            #Encryption 
            checksum = self.genhash(FileIn)
            filesize = getsize(FileIn)
            cipher   = AES.new(self._key, AES.MODE_CBC, self._iv )
            with open(FileIn, 'rb') as fi:
                with open(FileOut, 'wb') as fo:
                    fo.write(struct.pack('<Q', filesize))
                    fo.write(checksum)
                    fo.write(struct.pack('<Q',self.saltlen))
                    fo.write(self._salt)
                    fo.write(self._iv)

                    while(True):
                        chunk = fi.read(self._chunksize)
                        if len(chunk) == 0:
                            break
                        elif len(chunk)%AES_CBC.BS != 0:
                            chunk = pad(chunk, AES_CBC.BS)
                        fo.write(cipher.encrypt(chunk))

            if log:
                print(f"{green}"+"*"*75)
                print("\t\t\tEncryption Succesfull.\n")
                print("Input File Name: \t"+basename(FileIn))
                print("Output File Directory:\t"+dirname(abspath(FileOut)))
                print("Output File Name: \t"+basename(FileOut))
                print("Encrypted File Position: "+abspath(FileOut))
                print("Thanks For Using!!! ")
                print("*"*75+f"{white}")
                if DelFileIn:
                    print(f"\n{blue}Deleting Original File...")
                    remove(FileIn)
                    DelFileIn = False 
                    print(f"{FileIn} Succesfully Deleted. {white}")
            if DelFileIn:
                remove(FileIn)
        else:
            raise FileNotFoundError("File Does Not Exists.")

    def DecryptFile(self, FileIn:str, OutPath=None, count=100000, log=True, DelFileIn=True, Forced=False):
        if isfile(FileIn):

            FileOut = join(dirname(FileIn), (basename(FileIn)[:-4]))

            if OutPath is not None:
                if isdir(OutPath):
                    FileOut = join(OutPath, (basename(FileIn)[:-4]))
                else:
                    print(f"{red}Defaulting Output Path to {dirname(abspath(FileIn))} {white}")

            #Decryption
            with open(FileIn, 'rb') as fi:
                filesize = struct.unpack('<Q', fi.read(struct.calcsize('Q')))[0]
                checksum = fi.read(64).decode("utf-8")
                self.saltlen = struct.unpack('<Q', fi.read(struct.calcsize('Q')))[0]
                self._salt 	 = fi.read(self.saltlen)
                self.genkey(self._salt, count=count)
                self._iv     = fi.read(AES_CBC.BS)
                cipher       = AES.new(self._key, AES.MODE_CBC, self._iv)

                with open(FileOut, 'wb') as fo:
                    while True:
                        chunk = fi.read(self._chunksize)
                        if len(chunk) == 0:
                            break
                        fo.write(cipher.decrypt(chunk))
                    fo.truncate(filesize)
            
            if Forced:
                if log:
                    print(f"{red}\nForced Decryption Succesfull.{white}")
            else:
                check = self.comparehash(checksum, FileOut)
                if log:
                    if check:
                        print(f"{green}"+"*"*75)
                        print("Decrytion Succesfull.")
                        print("Output File: "+abspath(FileOut))
                        print("*"*75+f"{white}")
                        if DelFileIn:
                            print(f"{blue}\nDeleting Original File.")
                            remove(FileIn)
                            DelFileIn = False
                            print(f"{FileIn} deleted Succesfully.{white}")
                        return True
                    else:
                        print(f"{red}\nDecryption Failed.{white}")
                        remove(FileOut)
                        DelFileIn = False
                        return False
                else:
                    if check:
                        if DelFileIn:
                            remove(FileIn)
                        return True
                    else:
                        remove(FileOut)
                        return False
        else:
            raise FileNotFoundError("File does Not Exists.")
            
                  

