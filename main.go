package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

type PageType struct {
	Name          string
	UrlSuffix     string
	DetectRegex   string
	ExtractRegex  string
	RegexMatchIdx int
}

func main() {
	baseUrl := parseCommandLineArguments()
	baseUrl = validateBaseUrl(baseUrl)

	art := `   
     ___      _   _      __ _           _           
    / _ \__ _| |_| |__  / _(_)_ __   __| | ___ _ __ 
   / /_)/ _' | __| '_ \| |_| | '_ \ / _' |/ _ \ '__|
  / ___/ (_| | |_| | | |  _| | | | | (_| |  __/ |   
  \/    \__,_|\__|_| |_|_| |_|_| |_|\__,_|\___|_|   
													
  
`

	fmt.Fprint(os.Stderr, art)
	fmt.Fprint(os.Stderr, "🎯 Target: ", baseUrl, "\n")

	httpClient := createHttpClient()

	pageTypes := []PageType{
		{"php-fpm", "/status?full=true", "request URI:", `(script|request URI):\s+([^\s]+)`, 2},
		{"apache-server-status", "/server-status", "Apache Server Status", `(?:GET|OPTIONS)\s+([^\s]+)\s+HTTP`, 1},
		{"prometheus", "/metrics", "endpoint=", `endpoint="([^"]+)"`, 1},
	}

	pageType, fullUrl := findPageType(httpClient, baseUrl, pageTypes)

	if pageType.Name == "" {
		fmt.Fprintln(os.Stderr, "🚫 Host not vulnerable")
		os.Exit(1)
	}

	fmt.Fprint(os.Stderr, "🧙 Discovered status page: ", pageType.Name, "\n")
	fmt.Fprint(os.Stderr, "⏳ Collecting paths...\n\n")

	uniqueValues := extractUniqueValues(httpClient, fullUrl, pageType)

	sortAndPrintValues(baseUrl, uniqueValues)
}

func parseCommandLineArguments() string {
	baseUrlPtr := flag.String("url", "", "Base URL of the host")
	flag.Parse()
	return *baseUrlPtr
}

func validateBaseUrl(baseUrl string) string {
	if baseUrl == "" {
		fmt.Println("Please provide the base URL with the --url flag")
		os.Exit(1)
	}

	parsedUrl, err := url.Parse(baseUrl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid URL format: %v\n", err)
		os.Exit(1)
	}

	return fmt.Sprintf("%s://%s", parsedUrl.Scheme, parsedUrl.Host)
}

func createHttpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func findPageType(client *http.Client, baseUrl string, pageTypes []PageType) (PageType, string) {
	for _, pt := range pageTypes {
		fullUrl := baseUrl + pt.UrlSuffix
		if checkPageType(client, fullUrl, pt.DetectRegex) {
			return pt, fullUrl
		}
	}
	return PageType{}, ""
}

func checkPageType(client *http.Client, url string, searchString string) bool {
	resp := performGetRequest(client, url)
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), searchString) {
			return true
		}
	}
	return false
}

func performGetRequest(client *http.Client, url string) *http.Response {
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GET request failed: %v\n", err)
		os.Exit(1)
	}
	return resp
}

func extractUniqueValues(client *http.Client, fullUrl string, pageType PageType) map[string]bool {
	resp := performGetRequest(client, fullUrl)
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)

	uniqueValues := make(map[string]bool)
	regex, _ := regexp.Compile(pageType.ExtractRegex)

	for scanner.Scan() {
		line := scanner.Text()
		if matches := regex.FindStringSubmatch(line); len(matches) > pageType.RegexMatchIdx {
			uniqueValues[matches[pageType.RegexMatchIdx]] = true
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading response body:", err)
		os.Exit(1)
	}

	return uniqueValues
}

func sortAndPrintValues(baseUrl string, values map[string]bool) {
	var sortedValues []string
	for value := range values {
		sortedValues = append(sortedValues, value)
	}
	sort.Strings(sortedValues)

	for _, value := range sortedValues {
		if value != "*" && value != "-" && value != "/" {
			fmt.Println(baseUrl + value)
		}
	}
}
