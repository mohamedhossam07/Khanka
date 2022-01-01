import hashlib
import os
import zipfile


def khankaword_word_check(filecontent3):
    magicnumber = ''
    for i in filecontent3[:4] :
        magicnumber = magicnumber + format(ord(i), "x")
    if (magicnumber == "504b34" ):
        return True
    else :
        return False
    

def khankaword_word_static(filecontent2,filename2):
    if (khankaword_word_check(filecontent2)):
        print("[+] Word file magic value checked")    
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
    print("[+] MD5 : {0}".format(md5.hexdigest()))
    print("[+] SHA1 : {0}".format(sha1.hexdigest()))
    print("[+] SHA256 : {0}".format(sha256.hexdigest()))
    print("[+] Word File Parsing started")
    docx = zipfile.ZipFile(filename2)
    content = docx.namelist()
    count = 1
    for i in content :
        print("    " + str(count) + "- " + i)
        count = count + 1
        
        
        
def khankaword_word_extract(filecontent2,filename2,param4):
    try:
        docx = zipfile.ZipFile(filename2)
    except :
        print("[!] Error Loading the file")
        return
    content = docx.namelist()
    count = 1
    filenameextract = ''
    for i in content :
    
        if (int(param4) == int(count) ) :
            filenameextract = i
        count = count + 1
    fileextractedname = filenameextract.split("/")[-1]
    print("[+} Extracting file : " + fileextractedname)
    vba_file = open(filenameextract.split("/")[-1], "wb")
    data = docx.read(filenameextract)
    vba_file.write(data)
    vba_file.close()
