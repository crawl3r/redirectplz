package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

/*
	Input: cat a list of URLs via stdin

	Aim: Loop the URL's and fuzz the endpoint for an open redirect.

	Reason: Open redirects are pretty common. These tools exist already, but I love writing code and learning. So, here we are :)
*/

var out io.Writer = os.Stdout

// make this an optional argument instead to allow users to use their own wordlist
var redirEndpoints = []string{
	"/{payload}",
	"?next={payload}",
	"?url={payload}",
	"?target={payload}",
	"?rurl={payload}",
	"?dest={payload}",
	"?destination={payload}",
	"?redir={payload}",
	"?redirect_uri={payload}",
	"?redirect_url={payload}",
	"?redirect={payload}",
	"/redirect/{payload}",
	"/cgi-bin/redirect.cgi?{payload}",
	"/out/{payload}",
	"/out?{payload}",
	"?view={payload}",
	"/login?to={payload}",
	"?image_url={payload}",
	"?go={payload}",
	"?return={payload}",
	"?returnTo={payload}",
	"?return_to={payload}",
	"?checkout_url={payload}",
	"?continue={payload}",
	"?return_path={payload}",
}
var payloadFuzzTag = "{payload}"
var openRedirectPayloads = []string{}

func main() {
	var outputFileFlag string
	flag.StringVar(&outputFileFlag, "o", "", "Output file for open redirect URLs")
	var payloadFileFlag string
	flag.StringVar(&payloadFileFlag, "p", "", "List of payloads")
	quietModeFlag := flag.Bool("q", false, "Only output the URL's with open redirect vulnerabilities")
	flag.Parse()

	if payloadFileFlag == "" {
		fmt.Println("Please supply a list of payloads with the -p switch")
		os.Exit(1)
	}

	quietMode := *quietModeFlag
	saveOutput := outputFileFlag != ""
	outputToSave := []string{}

	openRedirectPayloads = readFile(payloadFileFlag)

	if !quietMode {
		banner()
		fmt.Println("")
	}

	writer := bufio.NewWriter(out)
	urls := make(chan string, 1)
	var wg sync.WaitGroup

	ch := readStdin()
	go func() {
		//translate stdin channel to domains channel
		for u := range ch {
			// create the fuzzed endpoints relative to our above list
			for _, ep := range redirEndpoints {
				for _, payload := range openRedirectPayloads {
					finalUrl := u + ep
					finalUrl = strings.Replace(finalUrl, payloadFuzzTag, payload, -1)
					urls <- finalUrl
				}
			}
		}
		close(urls)
	}()

	// flush to writer periodically
	t := time.NewTicker(time.Millisecond * 500)
	defer t.Stop()
	go func() {
		for {
			select {
			case <-t.C:
				writer.Flush()
			}
		}
	}()

	for u := range urls {
		wg.Add(1)
		go func(site string) {
			defer wg.Done()
			finalUrls := []string{}

			// If the identified URL has neither http or https infront of it. Create both and scan them.
			if !strings.Contains(u, "http://") && !strings.Contains(u, "https://") {
				finalUrls = append(finalUrls, "http://"+u)
				finalUrls = append(finalUrls, "https://"+u)
			} else if strings.Contains(u, "http://") {
				finalUrls = append(finalUrls, "https://"+u)
			} else if strings.Contains(u, "https://") {
				finalUrls = append(finalUrls, "http://"+u)
			} else {
				// else, just scan the submitted one as it has either protocol
				finalUrls = append(finalUrls, u)
			}

			// now loop the slice of finalUrls (either submitted OR 2 urls with http/https appended to them)
			for _, uu := range finalUrls {
				if !quietMode {
					fmt.Println("Checking:", uu)
				}
				openRedirect := makeRequest(uu, "www.bing.com", quietMode)
				if openRedirect {
					// if we had a leak, let the user know
					fmt.Printf("%s\n", uu)

					if saveOutput {
						outputToSave = append(outputToSave, uu)
					}
				}
			}
		}(u)
	}

	wg.Wait()

	// just in case anything is still in buffer
	writer.Flush()

	if saveOutput {
		file, err := os.OpenFile(outputFileFlag, os.O_CREATE|os.O_WRONLY, 0644)

		if err != nil && !quietMode {
			log.Fatalf("failed creating file: %s", err)
		}

		datawriter := bufio.NewWriter(file)

		for _, data := range outputToSave {
			_, _ = datawriter.WriteString(data + "\n")
		}

		datawriter.Flush()
		file.Close()
	}
}

func banner() {
	fmt.Println("---------------------------------------------------")
	fmt.Println("RedirectPlz -> Crawl3r")
	fmt.Println("List URL's which appear to be vulnerable to open redirects. This is basically a fuzzer but not quite as smart.")
	fmt.Println("Run again with -q for cleaner output")
	fmt.Println("---------------------------------------------------")
}

func readStdin() <-chan string {
	lines := make(chan string)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			url := strings.ToLower(sc.Text())
			if url != "" {
				lines <- url
			}
		}
	}()
	return lines
}

func makeRequest(url string, redirectTarget string, quietMode bool) bool {
	resp, err := http.Get(url)
	if err != nil {
		if !quietMode {
			fmt.Println("[error] performing the request to:", url)
		}
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return strings.Contains(resp.Request.URL.String(), redirectTarget)
	} else {
		return false
	}
}

func readFile(filePath string) []string {
	lines := []string{}

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
		return nil
	}

	return lines
}
