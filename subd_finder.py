from multiprocessing import Pool
import requests
import argparse
import signal

class Sub_Domain_Finder():
    def __init__(self,target,wordlist,output_file,blacklist,threads,header,cookie,user_agent,proxy):
        self.target = target
        self.wordlist = wordlist
        self.output_file = output_file
        self.blacklist = blacklist
        self.threads = threads
        self.header = header
        self.cookie = cookie
        self.user_agent = user_agent
        self.proxy = proxy

        self.url = self.check_url()
        self.set_processes()

    def check_url(self):
        check = self.target[-1]
        if check == "/": 
            return self.target
        else:
            fixed_url = self.target + "/"
            return fixed_url

    def set_processes(self):
        print("Finding Sub_Domains:")

        if args.b:
            print("Blacklisted Status Code: " + self.blacklist)

        if args.o:
            file_write = open(self.output_file,"w")
            file_write.close()

        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        pool = Pool(processes=int(self.threads))
        signal.signal(signal.SIGINT, original_sigint_handler)

        lines = []
        with open(self.wordlist,'r') as wordlist_file:
            for each_word in wordlist_file:
                lines.append(each_word.rstrip())

        try:
            start = pool.map_async(self.subd_finder,lines)
        except KeyboardInterrupt:
            pool.terminate()
        else:
            pool.close()
        pool.join()
        
        print("Done!")

    def ssl_check(self,sub_domain):
        length_url = len(self.url)
        ssl_check = self.url[ 0 : 5 ]

        if ssl_check == "https":
            url = self.url[8:length_url]
            url = url[:-1]
            sub_domain = sub_domain + "." + url 
            https_url = ssl_check + ":"

            return sub_domain, https_url
        else:
            url = self.url[7:length_url]
            url = url[:-1]
            sub_domain = sub_domain + "." + url

            return sub_domain, ssl_check

    def create_headers(self,sub_domain):
        header_check = {
            "Host" : "CQKXnw7oGYDjn8asozo5dQ",
            "Connection":"close"
        }

        header_found = {
            "Host" : sub_domain,
            "Connection":"close"
        }
        
        proxy_set = {}

        if args.a:
            header_check["User-Agent"] = self.user_agent
            header_found["User-Agent"] = self.user_agent

        if args.p:
            proxy_set = {
                "http": "http://" + self.proxy
            }
        
        if args.c:
            header_check['Cookie'] = self.cookie
            header_found['Cookie'] = self.cookie

        if args.H:
            header_list = self.header.split(': ')
            list_length = len(header_list) - 1 
            for each_header in range(0,list_length):
                header_check[header_list[each_header]] = header_list[each_header + 1]
                header_found[header_list[each_header]] = header_list[each_header + 1]

        return header_check, header_found, proxy_set

    def subd_finder(self,each_word):
        requests.packages.urllib3.disable_warnings() 

        sub_domain, http_print = self.ssl_check(each_word)
        header_check, header_found, proxy_set = self.create_headers(sub_domain)

        if args.b:
            self.blacklist = self.blacklist
        else:
            self.blacklist = 404         

        check_url_req = requests.get(self.url, headers=header_check, verify=False, allow_redirects=False,proxies=proxy_set)
        length_url_check = len(check_url_req.text)

        found_url_req = requests.get(self.url, headers=header_found, verify=False, allow_redirects=False,proxies=proxy_set)
        length_found_url = len(found_url_req.text)

        if args.o:
            if length_found_url != length_url_check and found_url_req.status_code != int(self.blacklist):
                print("Found: " + http_print + "//" + sub_domain,found_url_req.status_code) 
                            
                out_file = open(self.output_file,'a')
                out_file.write("Found: ")
                out_file.write(http_print)
                out_file.write("//")
                out_file.write(sub_domain)
                out_file.write(" ")
                out_file.write(str(found_url_req.status_code))
                out_file.write("\n")
                out_file.close()

        elif length_found_url != length_url_check and found_url_req.status_code != int(self.blacklist):
            print("Found: " + http_print + "//" + sub_domain,found_url_req.status_code)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Brute Force Sub Domains')

    parser.add_argument('-u', metavar='<Target URL>', help='target/host URL, E.G: -u http://findme.blah/', required=True)
    parser.add_argument('-w', metavar='<wordlist file>',help="Example: -w list.txt", required=True)
    parser.add_argument('-o', metavar='<output file>',help="Example: -o output.txt", required=False)
    parser.add_argument('-b', metavar='<blacklist status code>',help="Example: -b 301 ", required=False)
    parser.add_argument('-t', metavar='<Threads>',default="10",help="Example: -t 100", required=False)
    parser.add_argument('-H', metavar='<Header>',help="Example -H 'Parameter: Value", required=False)
    parser.add_argument('-c', metavar='<Cookie>',help="Example -c 'Cookie Value", required=False)
    parser.add_argument('-a', metavar='<User-Agent>',help="Example: -a Linux", required=False)
    parser.add_argument('-p', metavar='<Proxies>',help="Example: -p 127.0.0.1:8080", required=False)

    args = parser.parse_args()  

    try:
        Sub_Domain_Finder(args.u,args.w,args.o,args.b,args.t,args.H,args.c,args.a,args.p)
    except KeyboardInterrupt:
        print("Bye Bye") 
        exit()