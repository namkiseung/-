import requests, argparse, sys, textwrap

'''
Cookie sessionid=w5efh7f7enahe7oquitba;

'''
URL="https://www.naver.com/api/pay/inouts/?dates="
querystr="/api/pay/inouts/?dates="
headers = {'X-Requested-With': 'XMLHttpRequest'} 
cookies = {'sessionid': "str(sys.argv[1])"} #expired mins...

def MENU():
    parser = argparse.ArgumentParser(
        prog='select_transaction',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("")
    ) 
    parser.add_argument('app_name', action='store_false', help='the process that you will be injecting to')
    parser.add_argument('-s', '--session', help='session to connect')
    parser.add_argument('-d', '--date', help='attach with date')    
    args = parser.parse_args()
    return args
    
if __name__ == '__main__':
    arguments = MENU()	
    APP_NAME = arguments.app_name
    cookies['sessionid']=arguments.session
    for y in range(1,2):
        for x in range(1,12):
            res = requests.get(URL+"202{}.%200{}.".format(y,x), headers=headers, cookies=cookies)
            print(res.text)
            
'''
성공 응답 값
HTTP/1.1 200 OK
Pragma: no-cache
Cache-Control: no-store
Access-Control-Allow: *
Content-Type: application/json;charset=UTF-8
Content-Length: 
Connection: close
Server:  

{
  "dataHeader" : {
    "category" : "API",
    "resultCode" : "200",
    "resultMessage" : "정상",
    "processFlag" : "",
    "processCode" : "",
    "processMessage" : "정상",
    "processTime" : 10,
    "successCode" : "0"
  },
  "dataBody" : {
    "msg" : "정상적으로 처리되었습니다.",
    "acKndCd" : "A",
    "delimiter" : "  ",
    "length" : "00000",
    "errF" : "0"
  }
}

'''

'''
adb shell pidof com.xxx.xxx
adb shell pidof com.xxx.xxx
adb logcat --pid {}
'''
