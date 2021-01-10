# RedirectPlz  
A Golang script to attempt to fuzz and find open redirect vulns across a range of URLs.  
This isn't the only script that does this, I just enjoy writing code and working on little tools to help my custom pipelines.  
  
Any issues, let me know! I plan to extend the source code it can identify, so if there are specific requests please let me know.  
  
## Thanks  
Big thanks to Hakluke, I used Hakrawler's (https://github.com/hakluke/hakrawler) concurrency and picked at the concurrency/goroutine code to patch mine.  
Thanks LeonMugen (https://github.com/Leonmugen/ORtester) for the payload list.  
  
## Installing  
```
go get github.com/crawl3r/redirectplz
```  
  
## Usage  
For now, just supply base URL's (i.e www.skid.com, www.reee.co.uk). I plan to tweak the logic to attempt to fuzz for redirects across all identified links, smartlinks, etc. And ofcourse, if we identify a URL that already performs a redirect, then that will supercede all others.  
  
Standard Run:  
```
cat urls.txt | ./redirectplz -p payloads.txt
```
  
Run and save the output to file  
```
cat urls.txt | ./redirectplz -p payloads.txt -o output.txt
```  
  
Run in quiet mode, only prints the identified open redirect endpoints. 
```
cat urls.txt | ./redirectplz -p payloads.txt -q
```
  
## License  
I'm just a simple skid. Licensing isn't a big issue to me, I post things that I find helpful online in the hope that others can:  
 A) learn from the code  
 B) find use with the code or   
 C) need to just have a laugh at something to make themselves feel better  
  
Either way, if this helped you - cool :)  
