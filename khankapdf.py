import re
import hashlib
from colorama import Fore, Back, Style
from colorama import init

init(autoreset=True)

def khankapdf_pdf_check(filecontent3):
    if (filecontent3[:5] == "%PDF-"):
        return True
    else :
        return False
    
    
    
    
def khankapdf_pdf_static(filecontent2,filename2):
    if (khankapdf_pdf_check(filecontent2)):
        print("[+] Pdf file magic value checked")    
    else :
        print("[!] Error : File format is not correct")
        return
    BUF_SIZE = 65536
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256() 
    with open(filename2, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
    print("[+] PDF Version : " + filecontent2[5:8])
    print("[+] MD5 : {0}".format(md5.hexdigest()))
    print("[+] SHA1 : {0}".format(sha1.hexdigest()))
    print("[+] SHA256 : {0}".format(sha256.hexdigest()))
    findobj = re.findall(r"\d+ \d+ obj",filecontent2)
    print ("[+] Number of Objects : " + str(len(findobj)))
    findobj = re.findall(r"\/Page",filecontent2)
    print ("[+] Number of Pages : " + str(len(findobj)))
    findobj = re.findall(r"\/Filter",filecontent2)
    print ("[+] Number of Filters : " + str(len(findobj)))
    findobj = re.findall(r"\/JS",filecontent2)
    findobj2 = re.findall(r"\/JavaScript",filecontent2)    
    if ( len(findobj + findobj2) > 0 ):
        print (Fore.RED + "[+] Number of /JavaScript /JS : " + str(len(findobj + findobj2)))
    else :
        print ("[+] Number of /JavaScript /JS : " + str(len(findobj + findobj2)))
    findobj = re.findall(r"\/AA",filecontent2)
    if ( len(findobj) > 0  ):
        print (Fore.RED + "[+] Number of /AA : " + str(len(findobj)))
    else :
        print ("[+] Number of /AA : " + str(len(findobj))) 
    findobj = re.findall(r"\/OpenAction",filecontent2)
    if ( len(findobj) > 0  ):
        print (Fore.RED + "[+] Number of /OpenAction : " + str(len(findobj)))
    else :
        print ("[+] Number of /OpenAction : " + str(len(findobj)))
    findobj = re.findall(r"\/Encrypt",filecontent2)
    if ( len(findobj) > 0  ):
        print (Fore.RED + "[+] Number of /Encrypt : " + str(len(findobj)))
    else :
        print ("[+] Number of /Encrypt : " + str(len(findobj)))
    findobj = re.findall(r"\/RichMedia",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of Embeded Flash /RichMedia : " + str(len(findobj)))
    else :    
        print ("[+] Number of Embeded Flash /RichMedia : " + str(len(findobj)))
    findobj = re.findall(r"\/Launch",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /Launch : " + str(len(findobj)))
    else :    
        print ("[+] Number of /Launch : " + str(len(findobj)))
    findobj = re.findall(r"\/EmbeddedFile",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /EmbeddedFile : " + str(len(findobj)))
    else :    
        print ("[+] Number of /EmbeddedFile : " + str(len(findobj)))
    findobj = re.findall(r"\/URI",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /URL : " + str(len(findobj)))
    else :    
        print ("[+] Number of /URL : " + str(len(findobj)))
    findobj = re.findall(r"\/SubmitForm",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /SubmitForm : " + str(len(findobj)))
    else :    
        print ("[+] Number of /SubmitForm : " + str(len(findobj)))
    findobj = re.findall(r"\/ASCIIHexDecode",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /ASCIIHexDecode : " + str(len(findobj)))
    else :    
        print ("[+] Number of /ASCIIHexDecode : " + str(len(findobj)))
    findobj = re.findall(r"\/ASCII85Decode",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /ASCII85Decode : " + str(len(findobj)))
    else :    
        print ("[+] Number of /ASCII85Decode : " + str(len(findobj)))
    findobj = re.findall(r"\/LZWDecode",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /LZWDecode : " + str(len(findobj)))
    else :    
        print ("[+] Number of /LZWDecode : " + str(len(findobj)))
    findobj = re.findall(r"\/RunLengthDecode",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /RunLengthDecode : " + str(len(findobj)))
    else :    
        print ("[+] Number of /RunLengthDecode : " + str(len(findobj)))
    findobj = re.findall(r"\/CCITTFaxDecode",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /CCITTFaxDecode : " + str(len(findobj)))
    else :    
        print ("[+] Number of /CCITTFaxDecode : " + str(len(findobj)))
    findobj = re.findall(r"\/DCTDecode",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /DCTDecode : " + str(len(findobj)))
    else :    
        print ("[+] Number of /DCTDecode : " + str(len(findobj)))
    findobj = re.findall(r"\/SubFileDecode",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /SubFileDecode : " + str(len(findobj)))
    else :    
        print ("[+] Number of /SubFileDecode : " + str(len(findobj)))
    findobj = re.findall(r"\/FlateDecode",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /FlateDecode : " + str(len(findobj)))
    else :    
        print ("[+] Number of /FlateDecode : " + str(len(findobj)))
    findobj = re.findall(r"\/GIFDecode",filecontent2)
    if ( len(findobj) > 0  ):   
        print (Fore.RED + "[+] Number of /GIFDecode : " + str(len(findobj)))
    else :    
        print ("[+] Number of /GIFDecode : " + str(len(findobj)))
    findobj = re.findall(r"\/PNGDecode",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /PNGDecode : " + str(len(findobj)))
    else :    
        print ("[+] Number of /PNGDecode : " + str(len(findobj)))
    findobj = re.findall(r"\/Crypt",filecontent2)
    if ( len(findobj) > 0  ):    
        print (Fore.RED + "[+] Number of /Crypt : " + str(len(findobj)))
    else :    
        print ("[+] Number of /Crypt : " + str(len(findobj)))