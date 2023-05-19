# Define script version
XIPLOC_VERSION = "1.0"

try:
  try:
    # Import 3rd party modules [cryptography, pyzipper]
    import pyzipper
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.fernet import Fernet
    
    # Import default modules
    import shutil
    import string
    import random
    import os
    import base64
    import json
    import argparse
    import time
    import pathlib
  except ModuleNotFoundError:
    # Handle error if modules are missing and exit
    print("FATAL: The xiploc application is not built correctly. Please reinstall/rebuild. Please ensure installation of [cryptography, pyzipper] modules if running from source.")
    exit(1)
  
  '''Class to handle locking/encrypting of folders'''
  class FolderLockHandler():
    
    def __init__(self, folderIn, folderOut, folderName):
      # Initialize required variables
      self.__folderIn = folderIn
      self.__folderOut = folderOut
      self.__folderName = folderName
    
    # Function to create a password locked zip archive
    def _makeEncrypt(self, password, path, zipOut, cipher):
      # Create AES encrypted zip with STORED compression
      with pyzipper.AESZipFile(zipOut+"PRETEMP.zip", 'w', compression=pyzipper.ZIP_STORED, encryption=pyzipper.WZ_AES) as zf:
        # Set archive password
        zf.setpassword(password)
        # Iterate through files, directories and subdirectories and write them to archive as is
        for file_path in path.rglob("*"):
          zf.write(file_path, arcname=file_path.relative_to(path))
          
      # Encrypt generated zip file using fernet 
      with open(zipOut+"PRETEMP.zip", "rb") as fin, open(zipOut, "wb") as fout:
        while True:
          block = fin.read(524288) # read only a fraction of size to manage memory on big files 
          if not block:
            break
          output = cipher.encrypt(block)
          fout.write(output)
          
      # delete un-encrypted temp zip file 
      os.remove(zipOut+"PRETEMP.zip")
    
    # Function to split any file into equally sized chunks with randomized filenames
    def _splitFile(self, fileLoc, chunkSize, chunkDir = "./"):
      # Open file to split
      fileR = open(fileLoc, "rb")
      
      # Store chunk count and chunk name data order in integer variable and dictionary respectively
      chunkNameData = {}
      chunk = 0
       
      # Read chunk of file of specified size 
      byte = fileR.read(chunkSize)
      while byte:
       
          # Generate random alphanumeric name for file 
          fileN = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
          chunkNameData[str(chunk)] = fileN
          fileN = chunkDir + fileN
          # Write chunk to file 
          fileT = open(fileN, "wb")
          fileT.write(byte)
          fileT.close()
           
          # Read next chunk of data
          byte = fileR.read(chunkSize)
       
          # Increase chunk count by one 
          chunk += 1
          
      # Return chunk filename data 
      return chunkNameData
    
    
    # Main function of class to begin encrypting folders
    def startLock(self, corePassword):
      # Try to create working DIRs and pass if they exist 
      try:
        os.mkdir(self.__folderOut + "XipLoc/")
      except FileExistsError:
        pass
      
      try:
        os.mkdir(self.__folderOut + "XipLoc/._temp/")
      except FileExistsError:
        pass
      
      # Try to create a final folder for storage of encrypted chunks and exit if it already exists as files may overlap
      try:
        os.mkdir(self.__folderOut + "XipLoc/" + self.__folderName + "/")
      except FileExistsError:
        print("A folder with the name {} already exists in output directory. Please rename TARGET folder or change OUTPUT folder. If you believe that the folder does not contain other encrypted data or was previously aborted during encryption, please delete the folder and retry.".format(self.__folderName))
        exit(1)
      
      # Create pathlib object as required by zip encryption function
      path = pathlib.Path(self.__folderIn)
      
      # Create a random salt for password based encryption
      CRYPTO_SALT = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
      
      # Use cryptography to generate an encryption key using user's password and salt
      kdf = PBKDF2HMAC( algorithm = hashes.SHA256 , length = 32 , salt = CRYPTO_SALT.encode() , iterations = 100000 , backend = default_backend() )
      coreKey = base64.urlsafe_b64encode(kdf.derive(corePassword))
      cipher = Fernet(coreKey)
      
      # Create a random 256 character password for encrypting the archive and call zip function to create encrypted archive
      coreZipPass = ''.join(random.choices(string.ascii_letters + string.digits + "@#%^:&<>_*[]()!?,;.+=/~`|", k=256)).encode()
      self._makeEncrypt(coreZipPass, path, self.__folderOut + "XipLoc/._temp/exiploc.zip", cipher)
      
      # Divide size of final archive to create 128/129 chunks of file and call file splitting function and save chunk name dictionary to variable
      chunkSize = (os.stat(self.__folderOut + "XipLoc/._temp/exiploc.zip").st_size) // 128
      chunkNameData = self._splitFile(self.__folderOut + "XipLoc/._temp/exiploc.zip", chunkSize, self.__folderOut + "XipLoc/" + self.__folderName + "/")
    
      # Remove temporary working directory
      shutil.rmtree(self.__folderOut + "XipLoc/._temp/")
      
      # Create a dictionary format for the unlocking data file with the required information
      unlockFileData = {
        "FolderName": self.__folderName,
        "ChunkSize": chunkSize,
        "CoreZipPass": coreZipPass.decode(),
        "ChunkNameData": chunkNameData
      }
      
      # convert data file to string
      finalFile = json.dumps(unlockFileData)
      # encrypt the json string 
      finalFile = cipher.encrypt(finalFile.encode())
      # Write the encrypted string to a file with the same name as the salt used with the password
      with open(self.__folderOut + "XipLoc/" + self.__folderName + "/" + CRYPTO_SALT, "wb") as metafile:
        metafile.write(finalFile)
        
      # Remove the un-encrypted version of the original folder
      shutil.rmtree(self.__folderIn)
      # Return the absolute path of the unlocking file for user reference
      return os.path.abspath(self.__folderOut + "XipLoc/" + self.__folderName + "/" + CRYPTO_SALT)
  
  
  
  '''Class to handle decrypting and unlocking of a locked folder.'''
  class FolderUnlockHandler():
    def __init__(self, unlockFile, corePassword, cryptoSalt, outputFolder):
      # Initialize required variables
      self.__unlockFile = unlockFile
      self.__corePassword = corePassword
      self.__cryptoSalt = cryptoSalt
      self.__outputFolder = outputFolder
      self.__unlockFileData = None
      self.__chunkLoc = os.path.abspath(self.__unlockFile).replace("\\", "/")[:-20]
      
      # Generate key from user password and salt
      kdf = PBKDF2HMAC( algorithm = hashes.SHA256 , length = 32 , salt = self.__cryptoSalt.encode() , iterations = 100000 , backend = default_backend() )
      coreKey = base64.urlsafe_b64encode(kdf.derive(self.__corePassword))
      self.__Cipher = Fernet(coreKey)
      
      # Attempt to open and decrypt unlock data file
      try:
        with open(self.__unlockFile, 'rb') as UFO:
          rawData = UFO.read()
          rawData = self.__Cipher.decrypt(rawData).decode()
          self.__unlockFileData = json.loads(rawData)
      except Exception as error:
        print(f"FATAL: Failed to extract information from unlock data file. Could be corrupted/incorrect file or incorrect password. [E: {error}]")
        exit(1)
      
      # Abort process if output folder already exists and isn't empty
      if os.path.isdir(self.__outputFolder + self.__unlockFileData["FolderName"]) and os.listdir(self.__outputFolder + self.__unlockFileData["FolderName"]):
        print("A folder [{}] already exists and is not empty. Please move it to ensure that no other data is messed with during decryption.".format(self.__outputFolder + self.__unlockFileData["FolderName"]))
        exit(1)
        
      # Create output directory 
      os.mkdir(self.__outputFolder + self.__unlockFileData["FolderName"])
      self.__outputFolder = self.__outputFolder + self.__unlockFileData["FolderName"] + "/"
  
    def _joinFile(self, fileLoc):
      # Open single file to rebuild from chunks
      fileM = open(fileLoc, "wb")
       
      chunk = 0
       
      # Piece the file together using all chunks
      while chunk <= 128:
          fileName = self.__chunkLoc + self.__unlockFileData["ChunkNameData"][str(chunk)] # Get chunk names in order from datafile
          fileTemp = open(fileName, "rb")
       
          byte = fileTemp.read(self.__unlockFileData["ChunkSize"])
          fileM.write(byte)
          fileTemp.close()
          os.remove(fileName) # Remove chunk
       
          chunk += 1
       
      fileM.close()
  
  
    # Function to decrypt single binary encrypted zip
    def _decryptL2(self, inFile, outFile):
      with open(inFile, "rb") as fin, open(outFile, "wb") as fout:
        while True:
          block = fin.read(699148)
          if not block:
            break
          output = self.__Cipher.decrypt(block) # Decrypt a block
          fout.write(output)
          
      os.remove(inFile) # Remove binary encrypted zip
  
    # Function to extract password protected zip
    def _decryptL1(self, inFile):
      with pyzipper.AESZipFile(inFile, 'r', compression=pyzipper.ZIP_STORED, encryption=pyzipper.WZ_AES) as extracted_zip:
        extracted_zip.extractall(self.__outputFolder, pwd=self.__unlockFileData["CoreZipPass"].encode())
        
      os.remove(inFile) # Remove password protected zip
      
    def startUnlock(self):
      # Call decryption functions in order
      self._joinFile(self.__outputFolder + "dxiploc.zipPRETEMP.zip")
      self._decryptL2(self.__outputFolder + "dxiploc.zipPRETEMP.zip", self.__outputFolder + "dxiploc.zip")
      self._decryptL1(self.__outputFolder + "dxiploc.zip")
      
      # Remove chunk working directory and return path of extracted files
      shutil.rmtree(self.__chunkLoc)
      return os.path.abspath(self.__outputFolder)
  
  # Main program execution instructions
  if __name__ == '__main__':
    
    # Define details for argparse
    args = argparse.ArgumentParser(prog='xiploc', description='[Mirada XipLoc] Lock & Encrypt Folders.', epilog=f'Version {XIPLOC_VERSION} | Written by zukashix')
  
    # Add arguments to argparse and parse arguments 
    args.add_argument('-L', '--lock', help='Lock a folder (usage: xiploc -L <folder_name>)')
    args.add_argument('-U', '--unlock', help='Unlock a folder (usage: xiploc -U <unlock_file_name>)')
    args = args.parse_args()
    
    # Check if arguments passed are valid 
    if (args.lock == None and args.unlock == None) or (args.lock != None and args.unlock != None):
      print("Invalid arguments. No arguments passed or both lock/unlock arguments passed. Please use only lock/unlock at a time. See xiploc --help for information.")
      exit(1)
      
    # Enquire user for an output folder to work in 
    outputFolder = str(input("Enter path to directory where the script will place encrypted data: ")).strip().replace("\\", "/")
    
    # Make checks and corrections required in output folder path 
    if not outputFolder.endswith("/"):
      outputFolder += "/"
      
    # Check if output folder exists or not 
    if not os.path.isdir(outputFolder):
      print("The specified OUTPUT folder could not be found. Please check the input for any mistakes.")
      exit(1)
      
    # Define action to perform through arguments 
    if args.lock == None:
      LOCKFOLDER = args.unlock
      TARGET = 'unlock'
    else:
      LOCKFOLDER = args.lock
      TARGET = 'lock'
      
    # Make corrections in target path 
    LOCKFOLDER = LOCKFOLDER.strip().replace("\\", "/")
      
    # If action is set to lock then begin encrypting
    if TARGET == 'lock':
      if not LOCKFOLDER.endswith("/"):
        LOCKFOLDER += "/"
      
      # Check if target folder exists 
      if not os.path.isdir(LOCKFOLDER):
        print("The specified TARGET folder could not be found. Please check the input for any mistakes.")
        exit(1)
        
      # Extract folder name from folder path
      if len(LOCKFOLDER.split("/")) == 2:
        LFNAME = LOCKFOLDER.split("/")[0]
      else:
        LFNAME = LOCKFOLDER.split("/")[len(LOCKFOLDER) - 2]
      
      # Enquire user to create an encryption password to generate key with 
      corePassword = str(input("Create Encryption Password: ")).encode()
      print("This action may take time depending on folder size and number of files. Please be patient.")
      print("Starting encryption...")
      startTimeCD = time.time() # starting time
      
      # Create folder lock handler object and start lock 
      Locker = FolderLockHandler(LOCKFOLDER, outputFolder, LFNAME)
      metapath = Locker.startLock(corePassword)
      endTimeCD = time.time() # ending time
      
      # Print unlocking data file path for user reference
      print(f"Folder encryption success. Please note the path of the unlock file needed to decrypt the folder.\n{metapath}")
      print("Time Elapsed: {} seconds.".format(endTimeCD-startTimeCD))
      exit(0)
      
      
    # If action is set to unlock then begin decrypting
    if TARGET == "unlock":
      # Check if unlock file exists or not 
      if not os.path.isfile(LOCKFOLDER):
        print("The specified unlock file does not exist. Please check the input for any mistakes")
        exit(1)
        
      # Obtain salt from filename
      LFSplit = LOCKFOLDER.split("/")
      LFSALT = LFSplit[len(LFSplit) - 1]
        
      # Enquire user about the encrpytion password required to decrypt the unlock file
      corePassword = str(input("Enter Your Encryption Password: ")).encode()
      print("This action may take time depending on folder size and number of files. Please be patient.")
      print("Starting decryption...")
      startTimeCD = time.time() # starting time
      
      # Create folder unlock handler object and start decryption
      Unlocker = FolderUnlockHandler(LOCKFOLDER, corePassword, LFSALT, outputFolder)
      finalpath = Unlocker.startUnlock()
      
      endTimeCD = time.time() # ending time
      
      # Print decrypted folder path
      print("Folder decryption success. Restored files in [{}]".format(finalpath))
      print("Time Elapsed: {} seconds.".format(endTimeCD-startTimeCD))
      exit(0)

except KeyboardInterrupt:
  print("WARNING: Program aborted. Quitting.")
  exit(1)
  
except Exception as error:
  print(f"FATAL: UNKNOWN ERROR: {error}")
  exit(1)
  

"""XipLoc by zukashix"""
