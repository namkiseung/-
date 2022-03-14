import frida
import sys
import colorama
from colorama import Fore, Back, Style
import random
import argparse
import textwrap

 
def on_message(message, data):
    print(message)
 
def print_logo():
    logo = '''Search String in Memory \n   Ver 1.1.1 (by. kiseung.nam)'''
    bad_colors = ['BLACK', 'WHITE', 'LIGHTBLACK_EX', 'MAGENTA', 'BLUE', 'RESET']
    codes = vars(colorama.Fore)
    colors = [codes[color] for color in codes if color not in bad_colors]
    colored_chars = [random.choice(colors) + char for char in logo]
 
    print(''.join(colored_chars))
 
def MENU():
    parser = argparse.ArgumentParser(
        prog='memscan',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("")
    )
 
    parser.add_argument('app_name', action='store_false', help='the process that you will be injecting to')
    parser.add_argument('-d', '--device', help='device id to connect')
    parser.add_argument('-p', '--pid', help='attach with pid')
    parser.add_argument('-s', '--srch', help='enter search strings directly')
    args = parser.parse_args()
    return args
 
def run_script(search):
    script_code = """
    String.prototype.adddot = function() {
        var result = "";
        for (var i=0; i<this.length; i++) {
            result += this.charAt(i) + '.';
        }
        return result.trim();
    }
    String.prototype.hexEncode = function() {
        var result = "";
        for (var i=0; i<this.length; i++) {
            result += this.charCodeAt(i).toString(16) + ' ';
        }
        return result.trim();
    }
    String.prototype.hexEncode_Uni = function() {
        var result = "";
        for (var i=0; i<this.length; i++) {
            result += this.charCodeAt(i).toString(16) + ' 00 ';
        }
        return result.trim();
    }
    var keyword = '%(search)s';
    var keyword_uni = keyword.adddot();
    var pattern = keyword.hexEncode();
    var pattern_Uni = keyword.hexEncode_Uni();
    var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
    var ranges2 = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
    var range;
    var match_str = 0;
    var match_uni = 0;
    console.log('[*] Searching pattern...');
    console.log('     -> ' + pattern);
    console.log('     -> ' + pattern_Uni);
    console.log('');
    function search() {
        range = ranges.pop();
        if(!range){
            search_Uni();
            return;
        }
        Memory.scan(range.base, range.size, pattern, {
            onMatch: function(address, size){
                console.log('\x1b[33m[!] Pattern found at: ' + address.toString() + '\x1b[32m');
                match_str++;
                var addr = address - 32;
                var buf = Memory.readByteArray(ptr(addr), 96);
                console.log(hexdump(buf, {
                    offset: 0,
                    length: 96,
                    header: true,
                    ansi: false
                }).replace(keyword, '\x1b[31m' + keyword + '\x1b[32m').replace(pattern, '\x1b[31m' + pattern + '\x1b[32m'));
                console.log('');
            },
            onError: function(reason){
                //console.log('[!] There was an error scanning memory');
            },
            onComplete: function(){
                search();
            }
        });
    }
    search();
    function search_Uni() {
        range = ranges2.pop();
        if(!range){
            console.log('\x1b[33m[*] Pattern matches (str): ' + match_str);
            console.log('[*] Pattern matches (uni): ' + match_uni + '\x1b[32m');
            //console.log('[*] Done. Press Ctrl + C to exit program.');
            console.log('[!] Press <Enter> at any time to detach from instrumented program.');
            return;
        }
        Memory.scan(range.base, range.size, pattern_Uni, {
            onMatch: function(address, size){
                console.log('\x1b[33m[!] Pattern found at: ' + address.toString() + '\x1b[32m');
                match_uni++;
                var addr = address - 32;
                var buf = Memory.readByteArray(ptr(addr), 96);
                console.log(hexdump(buf, {
                    offset: 0,
                    length: 96,
                    header: true,
                    ansi: false
                }).replace(keyword_uni, '\x1b[31m' + keyword_uni + '\x1b[32m').replace(pattern_Uni, '\x1b[31m' + pattern_Uni + '\x1b[32m'));
                console.log('');
            },
            onError: function(reason){
                //console.log('[!] There was an error scanning memory');
            },
            onComplete: function(){
                search_Uni();
            }
        });
    }
    """ % { 'search': search }
    return script_code
 
if __name__ == '__main__':
    colorama.init()
    print_logo()
    arguments = MENU()
 
    APP_NAME = arguments.app_name
    print("#log: {}".format(APP_NAME))
    DEVICE = arguments.device
    print("#log: {}".format(DEVICE))
    PID = arguments.pid
    print("#log: {}".format(PID))
    SRCH = arguments.srch
 
    print(Fore.CYAN)
 
    try:
        session = None
        try:
            if DEVICE and not PID:
                print('[*] Attached to target via DEVICE (%s)' % APP_NAME)
                session = frida.get_device(DEVICE, timeout=10).attach(APP_NAME)
            elif not DEVICE and PID:
                print('[*] Attached to target with PID (%s)' % PID)
                session = frida.attach(int(PID))
            elif DEVICE and PID:
                print('[*] Attached to target via DEVICE with PID (%s)' % PID)
                session = frida.get_device(DEVICE, timeout=10).attach(int(PID))
            else:
                print('[*] Attached to target (%s)' % APP_NAME)
                session = frida.attach(APP_NAME)
        except Exception as e:
            print("#error log: {}".format(e))
            print("Can't connect to App. Have you connected the device?")
            sys.exit(0)
 
        if SRCH:
            search = SRCH
            print('[>] Search Keyword: ' + search)
        else:
            search = input('[>] Search Keyword: ')
            # print('[>] Search Keyword: ')
            # search = input()
 
        print('')
 
        script = session.create_script(run_script(search))
        script.on('message', on_message)
        script.load()
        sys.stdin.readline()
        # print('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
        session.detach()
 
    except KeyboardInterrupt:
        sys.exit(0)
 


#출처: https://namkisec.tistory.com/entry/Frida로-메모리덤프 [사생활._.]
