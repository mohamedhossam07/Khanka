import sys
import khankapdf
import khankaword
import khankaexcel

def usage():
    print ("Example : python khanka.py help")
    print ("Example : python khanka.py funhelp <function_name>")
    print ("Example : python khanka.py <file_type> <function> <file_name>")
    
    
def funhelp(param2):
    if ( param2 == "pdf_static" ):
        print("pdf_static : Khanka will perform static analysis on the pdf file. ")
    elif ( param2 == "excel_static" ):
        print("excel_static : Khanka will perform static analysis on the excel file. ")
    else :
        print("[!] Error : Function not found")

def globalhelp():
    print ("Example : python khanka.py <file_type> <function> <file_name>")
    print ("File Types : excel, word, pdf, js, vbs")
    print ("function : Word : word_static, word_extract")
    print ("function : PDF : pdf_static")
    print ("function : Excel : excel_static, excel_func, excel_extract")
    print ("function : Javascript : js_static, js_deobf, js_beautify")
    print ("function : vbs : vbs_static, vbs_deobf")


def main():
    
    print( "     )                            ")
    print( "  ( /(    )               )       ")
    print( "  )\())( /(    )       ( /(    )  ")
    print( "|((_)\ )\())( /(  (    )\())( /(  ")
    print( "|_ ((_|(_)\ )(_)) )\ )((_)\ )(_)) ")
    print( "| |/ /| |(_|(_)_ _(_/(| |(_|(_)_  ")
    print( "  ' < | ' \/ _` | ' \)) / // _` | ")
    print( " _|\_\|_||_\__,_|_||_||_\_\\__,_| ")
    print("")
    print("Document Malwares Analyzer")
    print("")
    
    try:
        param1 = sys.argv[1]
        if (param1 == "help"):
            globalhelp()
            return
        param2 = sys.argv[2]
        if (param1 == "funhelp"):
            funhelp(param2)
            return
        
        try:
            param3 = sys.argv[3]
            filehandle = open(param3,errors="ignore")
            filecontent = filehandle.read()
            if ( param1 == "excel") :
                if ( param2 == "excel_static" ) :
                    khankaexcel.khankaexcel_excel_static(filecontent,param3)
                elif ( param2 == "excel_func" ) :
                    print("[+] Under Development!")
                elif ( param2 == "excel_extract" ) :
                    param4 = sys.argv[4]
                    khankaexcel.khankaexcel_excel_extract(filecontent,param3,param4)
                else :
                    print("[+] Under Development!")
            elif ( param1 == "pdf") :
                if ( param2 == "pdf_static" ) :
                    print ("[+] Statically analyzing pdf file : " + param3 + " started !" )
                    khankapdf.khankapdf_pdf_static(filecontent,param3)
                    return
                else :
                    print("[+] Under Development!")
            elif ( param1 == "word") :
                if ( param2 == "word_static" ) :
                    khankaword.khankaword_word_static(filecontent,param3)
                elif ( param2 == "word_extract" ) :
                    param4 = sys.argv[4]
                    khankaword.khankaword_word_extract(filecontent,param3,param4)
                else :
                    print("[+] Under Development!")
            elif ( param1 == "js") :
                if ( param2 == "js_static" ) :
                    print("[+] Under Development!")
                elif ( param2 == "js_deobf" ) :
                    print("[+] Under Development!")
                elif ( param2 == "js_beautify" ) :
                    print("[+] Under Development!")
                else :
                    print("[+] Under Development!")
            elif ( param1 == "vbs") :
                if ( param2 == "vbs_deobf" ) :
                    print("[+] Under Development!")
                elif ( param2 == "vbs_static" ) :
                    print("[+] Under Development!")
                else :
                    print("[+] Under Development!")
            else :
                usage()
                return
            
        except Exception as e:
            print(e)
            usage()
            return
        
    except Exception as e:
        print(e)
        usage()
        return

main() 