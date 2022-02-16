from multiprocessing import Pool
import requests
import argparse
import signal

class Sub_Domain_Finder():
    def __init__(self,target,wordlist,output_file,blacklist,threads):
        self.target = target
        self.wordlist = wordlist
        self.output_file = output_file
        self.blacklist = blacklist
        self.threads = threads

        self.logo()
        self.url = self.check_url()
        self.options_and_wordlistset()

    def logo(self):
        display = "\n"
        display += "█▀ █░█ █▄▄ █▀▄ █▀▀ █ █▄░█ █▀▄ █▀▀ █▀█\n"
        display += "▄█ █▄█ █▄█ █▄▀ █▀░ █ █░▀█ █▄▀ ██▄ █▀▄\n"
        print(display)

    def check_url(self):
        check = self.target[-1]
        if check == "/": 
            return self.target
        else:
            fixed_url = self.target + "/"
            return fixed_url

    def options_and_wordlistset(self):
        print("Finding Sub_Domains:")

        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        pool = Pool(processes=int(self.threads))
        signal.signal(signal.SIGINT, original_sigint_handler)

        lines = [] 
        with open(self.wordlist,'r') as wordlist_file:
            for each_word in wordlist_file:
                lines.append(each_word.rstrip())

        if args.o:

            if args.b:
                    print("Blacklisted Status Code: " + self.blacklist)
                    file_write = open(self.output_file,"w")
                    file_write.close()
                    try:
                        start = pool.map_async(self.subd_finder_with_file_with_blacklist,lines)
                    except KeyboardInterrupt:
                        print("Bye Bye!")
                        pool.terminate()
                        exit()
                    else:
                        pool.close()
                    pool.join()  

            else:
                file_write = open(self.output_file,"w")
                file_write.close()
                try:
                    start = pool.map_async(self.subd_finder_with_file_no_blacklist,lines)
                except KeyboardInterrupt:
                    print("Bye Bye!")
                    pool.terminate()
                    exit()
                else:
                    pool.close()
                pool.join() 

        else:

            if args.b:
                print("Blacklisted Status Code: " + self.blacklist)
                try:
                    start = pool.map_async(self.subd_finder_no_outfile_with_blacklist,lines)
                except KeyboardInterrupt:
                    print("Bye Bye!")
                    pool.terminate()
                    exit()
                else:
                    pool.close()
                pool.join() 

            else:
                try:
                    start = pool.map_async(self.subd_finder_no_outfile_no_blacklist,lines)
                except KeyboardInterrupt:
                    print("Bye Bye!")
                    pool.terminate()
                    exit()
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

    def subd_finder_no_outfile_no_blacklist(self,each_word):
        requests.packages.urllib3.disable_warnings()

        sub_domain, http_print = self.ssl_check(each_word)

        header_check = {
            "Host" : "CQKXnw7oGYDjn8asozo5dQ==",
            "Connection":"close"
        }   

        check_url_req = requests.get(self.url, headers=header_check, verify=False, allow_redirects=False)
        length_url_check = len(check_url_req.text)

        header_found = {
                    "Host" : sub_domain,
                    "Connection":"close"
        }

        found_url_req = requests.get(self.url, headers=header_found, verify=False, allow_redirects=False)
        length_found_url = len(found_url_req.text)

        if length_found_url != length_url_check:
            print("Found: " + http_print + "//" + sub_domain,found_url_req.status_code)

    def subd_finder_no_outfile_with_blacklist(self,each_word):
        requests.packages.urllib3.disable_warnings() 

        sub_domain, http_print = self.ssl_check(each_word)

                
        header_check = {
            "Host" : "CQKXnw7oGYDjn8asozo5dQ==",
            "Connection":"close" 
        }   

        check_url_req = requests.get(self.url, headers=header_check, verify=False, allow_redirects=False)
        length_url_check = len(check_url_req.text)

        header_found = {
            "Host" : sub_domain,
            "Connection":"close"
        }

        found_url_req = requests.get(self.url, headers=header_found, verify=False, allow_redirects=False)
        length_found_url = len(found_url_req.text)

        if length_found_url != length_url_check and found_url_req.status_code != int(self.blacklist):
            print("Found: " + http_print + "//" + sub_domain,found_url_req.status_code)

    def subd_finder_with_file_no_blacklist(self,each_word):
        requests.packages.urllib3.disable_warnings()

        sub_domain, http_print = self.ssl_check(each_word)

        header_check = {
            "Host" : "CQKXnw7oGYDjn8asozo5dQ==",
            "Connection":"close" 
        }   

        check_url_req = requests.get(self.url, headers=header_check, verify=False, allow_redirects=False)
        length_url_check = len(check_url_req.text)

        header_found = {
            "Host" : sub_domain,
            "Connection":"close"
        }

        found_url_req = requests.get(self.url, headers=header_found, verify=False, allow_redirects=False)
        length_found_url = len(found_url_req.text)

        if length_found_url != length_url_check:
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

    def subd_finder_with_file_with_blacklist(self,each_word):
        requests.packages.urllib3.disable_warnings()

        sub_domain, http_print = self.ssl_check(each_word)

        header_check = {
            "Host" : "CQKXnw7oGYDjn8asozo5dQ==",
            "Connection":"close" 
        }   

        check_url_req = requests.get(self.url, headers=header_check, verify=False, allow_redirects=False)
        length_url_check = len(check_url_req.text)

        header_found = {
            "Host" : sub_domain,
            "Connection":"close"
        }

        found_url_req = requests.get(self.url, headers=header_found, verify=False, allow_redirects=False)
        length_found_url = len(found_url_req.text)

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Brute Force Sub Domains')

    parser.add_argument('-u', metavar='<Target URL>', help='target/host URL, E.G: -u http://findme.blah/', required=True)
    parser.add_argument('-w', metavar='<wordlist file>',default='list.txt',help="Example: -w list.txt", required=True)
    parser.add_argument('-o', metavar='<output file>',help="Example: -o output.txt", required=False)
    parser.add_argument('-b', metavar='<blacklist status code>',help="Example: -b 301 ", required=False)
    parser.add_argument('-t', metavar='<Threads>',default="10",help="Example: -t 100", required=False)

    args = parser.parse_args()  

    try:
        Sub_Domain_Finder(args.u,args.w,args.o,args.b,args.t)
    except KeyboardInterrupt:
        print("Bye Bye") 
        exit()