
from typing import TextIO
import os
import sys
import argparse
from termcolor import colored
import socket
import struct


try:
    import shodan
except ImportError:
    print( colored( "Shodan library not found. Please install it prior to running script", 'red' ) )
    sys.exit( 1 )

os.system( 'clear' )

SHODAN_API_KEY: str  = ''
SEARCH_PATTERN: str = 'port:"445" "SMB Version: 1" os:"Windows"'
MatchesTemporaryList = [] ; CVETemporaryList = ['Scan for CVE ms17_010 EthernalBlue..',' ']; outputfile = ''
SearchCVE: bool = False ; Verbose: bool = False
resultofscan: str = ' '

def banner():
    banner = """
  _______ _______ _______  ______ _______ _     _ _______  ______
  |______ |______ |_____| |_____/ |       |_____| |______ |_____/
  ______| |______ |     | |    \_ |_____  |     | |______ |    \_
                                                                --> V. 0.1
                                                     + 🇨 🇻 🇪  2020-0796
                                                      Exploit Win10 SMB3.1
        --=[ Created by ..:: Hworange Rival ::... ]=-- 

        """
    return banner

def ScanCVE(indirizzoip:str):
    hytempstr = indirizzoip.split("|")
    testoprimoipsenzaporta = hytempstr[0].split(":")
    Scan_System_CVE(testoprimoipsenzaporta[0] )
   # print('Service on '+ hytempstr[0] + '  --> vulnerable CVE-00---')
   # CVETemporaryList.append( 'Service on '+ hytempstr[0] + '  --> vulnerable CVE-00---' )

def Scan_Shd_Api(SeachCVE, WriteOutput):
    if SHODAN_API_KEY == '': print( colored( 'Please set your Shodan APIKEY in the SHODAN_API_KEY parameter on Main file.py!. Exiting...','red' )); sys.exit( 1 )
    else:
        api = shodan.Shodan( SHODAN_API_KEY )
        print( " " ); print( colored( "Shodan API Key loaded: %s" % SHODAN_API_KEY, 'blue' ) )
        print( ' ' ); print( "...Searching Match with pattern: %s" % SEARCH_PATTERN ) ; print( ' ' )
        try:
            results = api.search( SEARCH_PATTERN )  # Search Option
            print( 'Result found: %s' % colored( results['total'], 'yellow' ) ); print( ' ' )
            for result in results['matches']:
                IP = result['ip_str'] ; PORT = format( result['port'] )
                ISP = format( result['isp'] ) ; ORG = format( result['org'] )
                DOM = format( result['domains'] ) ; DATA = format( result['data'] )
                print( 'IP: %s' % IP ) ; print( 'Port: %s' % PORT )
                print( 'ISP: %s' % ISP ) ; print( 'Organization: %s' % ORG )
                print( 'Domain: %s' % DOM ) ; print( ' ' )

                MatchesTemporaryList.append(
                    IP + ':' + PORT + '|Isp: ' + ISP + ' |Organiz.: ' + ORG + ' |Domain: ' + DOM )
                if Verbose == True:
                    print( 'Data: %s' % DATA )
                    MatchesTemporaryList.append( ' ' ); MatchesTemporaryList.append( '|Other Data: ' + DATA )
                    MatchesTemporaryList.append( ' ' ); MatchesTemporaryList.append( ' ' )
        except shodan.APIError as error:
            print( colored( 'Error: {}'.format( error ), 'red' ) ); print( colored( 'Work Completed! - 100%', 'green' ) )
        if not SearchCVE: print( 'CVE Search not Enabled...' )
        else:
            print( colored( 'Scanning Targets for CVE... ', 'yellow' ) )
            for result in MatchesTemporaryList:
                if result != ' ': ScanCVE( result)
        if WriteOutput == '': print( 'Cached result - No Output File...' ); sys.exit( 1 )
        else:
         if not SearchCVE:  MatchesTemporaryList.extend( CVETemporaryList )

         textfile: TextIO = open( WriteOutput, "w" )
         for element in MatchesTemporaryList:
               textfile.write( element + "\n" )
         print( 'Printed Output File on Path: ' + os.path.abspath(WriteOutput)); sys.exit( 1 )

def ZoomEye_Api(SeachCVE, WriteOutput):
    print('ZoomEye Search API work in progress... for now use -s Shodan!')

def CheckSMBCompression(indirizzoip:str):
    smb_payload = "000000b2fe534d4240000100000000000000210010000000000000000000000000000000fffe00000000000000000000000000000000000000000000000000000000000024000500010000007f000000aa9952d87063ea118a76005056b886b0700000000200000002021002000302031103000001002600000000000100200001006c6110bcde71a04e50810ffac0769c32c4c011cf86e26deb2ba923cd79cbbf7c0000"
    # Adding comperssion negotiation context
    smb_payload += "0300" + \
                   "0a00" + \
                   "00000000" + \
                   "0100" + \
                   "0000" + \
                   "00000000" + \
                   "0100"  # Compression type

    s = socket.socket ( 2, 1 )
    s.connect ( (indirizzoip, 445) )
    s.send ( bytes.fromhex ( smb_payload ) )
    buff_res = s.recv ( 4096 )

    smb_version = struct.unpack ( "<H", buff_res[72:74] )[0]
    print ( "SMB Version: " + hex ( smb_version ) )
    if buff_res.endswith ( b"\x00" * 4 + b"\x00" * 2 + b"\x01\x00" ):
        print ( "IP: " + indirizzoip + " SMBv3: Compression (LZNT1) supported." )
    else:
        print ( "IP: " + indirizzoip + " SMBv3: Compression (LZNT1) NOT supported." )
    s.close ()

def Scan_System_CVE(indirizzoip:str):

  try:
    pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
    sock = socket.socket( socket.AF_INET )
    sock.settimeout( 3 )
    sock.connect( (indirizzoip, 445) )
    sock.send( pkt )
    nb, = struct.unpack( ">I", sock.recv( 4 ) )
    res = sock.recv( nb )
    if not res[68:70] == b"\x11\x03" or not res[70:72] == b"\x02\x00":
        resultofscan =  'IP: ' + indirizzoip + 'is Not vulnerable.'
    else:
        resultofscan =  'IP: ' + indirizzoip + 'is Vulnerable.'
  except struct.error:
        resultofscan = 'IP: '  + indirizzoip + ' Error Received buffer < 4 bytes.... '
  except socket.timeout:
        resultofscan = 'IP: ' + indirizzoip + ' Error Socket Timeout.... '
  except:
        print('IP: ' + indirizzoip + ' Other Scan Error')
  finally:
      if resultofscan.__contains__("is Vulnerable."):
          print(colored(resultofscan,"green") )
      else:
          print(colored(resultofscan,"red") )


#CheckSMBCompression ( indirizzoip )


if __name__ == "__main__":
    print( banner() )
    parser = argparse.ArgumentParser( description="Description: Search Target on Shodan throught Shodan API, after scan for CVE Vulnerability.. ;D ",
                                      usage="\n\npython Scanner.py -s SMB\npython Scanner.py -s SMB -o listip.txt\npython Scanner.py -c -s SMB -o listip.txt\nUse -v [Verbose] Option for get more data from Shodan.", )
    sgroup = parser.add_argument_group( "Shodan CVE Scanner", "Options for Shodan CVE Scanner:" )
    sgroup.add_argument( '--shodan', '-s', dest='shodan', type=str,
                         help='Search Words for Shodan Search' )
    sgroup.add_argument( '--zoomeye', '-z', dest='zoomeye', type=str,
                         help='Search Words for ZoomEye Search' )

    sgroup.add_argument( '--cve', '-c', dest='cve', action='count', default=0,
                         help='Scan Found Targets for CVE Vulnerability' )
    sgroup.add_argument( '--outfile', '-o', dest='file', required=False, type=str, help='Save output of sarch on file' )
    sgroup.add_argument( '--verbose', '-v', dest='verbose', action='count',
                         default=0 ,help='Show more data from search' )
    sgroup.add_argument( '--version', action='version', version='%(prog)s 2.0' )
    options = parser.parse_args()

    if options.verbose: Verbose = True
    if options.cve: SearchCVE = True
    if options.shodan:
        if options.file:
            outputfile = options.file
            SEARCH_PATTERN = options.shodan
            Scan_Shd_Api( False, outputfile )
        else:
            SEARCH_PATTERN = options.shodan
            Scan_Shd_Api( False, '' )
    if options.zoomeye:
        if options.file:
            outputfile = options.file
            SEARCH_PATTERN = options.zoomeye
            ZoomEye_Api( False, outputfile )
        else:
            SEARCH_PATTERN = options.zoomeye
            ZoomEye_Api( False, '' )
    if not options.shodan:
        if not options.zoomeye:
           parser.print_help(); sys.exit( 1 )
