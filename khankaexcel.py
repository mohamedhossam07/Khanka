import hashlib
import os
import zipfile
import re
from colorama import Fore, Back, Style
from colorama import init

init(autoreset=True)

def khankaexcel_excel_check(filecontent3):
    magicnumber = ''
    for i in filecontent3[:4] :
        magicnumber = magicnumber + format(ord(i), "x")
    if (magicnumber == "504b34" ):
        return True
    else :
        return False
    

def khankaexcel_excel_static(filecontent2,filename2):
    if (khankaexcel_excel_check(filecontent2)):
        print("[+] Excel file magic value checked")    
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
    print("[+] Excel File Parsing started")    
    docx = zipfile.ZipFile(filename2)
    content = docx.namelist()
    count = 1
    for i in content :
        print("    " + str(count) + "- " + i)
        count = count + 1
    fileextractedname = "xl/workbook.xml"
    print("[+} Extracting file : " + fileextractedname)
    data = docx.read(fileextractedname)
    sheetlist = re.findall(r"<sheets>.*</sheets>",str(data))
    sheets = re.findall(r'name=.*?/>',str(sheetlist[0]))
    count = 1
    for sheetinfo in sheets :
        sheetname = re.findall(r'"(.*?)"',str(sheetinfo))
        sheetstate = re.findall(r'state=\"hidden\"',str(sheetinfo))
        print("    " + str(count) + "- " + sheetname[0])
        if (len(sheetstate) >= 1):
            print (Fore.RED + "     [+] '"+sheetname[0]+ "' is hidden sheet!")
        count = count + 1
    
def khankaexcel_excel_extract(filecontent2,filename2,param4):
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
    print (data)
    #vba_file.write(data)
    #vba_file.close()
