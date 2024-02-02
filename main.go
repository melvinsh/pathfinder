package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

func main() {
	baseUrl := parseCommandLineArguments()
	validateBaseUrl(baseUrl)

	httpClient := createHttpClient()

	pageType, fullUrl := findPageType(httpClient, baseUrl)

	if pageType == "" {
		fmt.Fprintln(os.Stderr, "host not vulnerable")
		os.Exit(1)
	}

	fmt.Fprint(os.Stderr, "Discovered page type: ", pageType, "\n")

	uniqueValues := extractUniqueValues(httpClient, fullUrl, pageType)

	sortAndPrintValues(uniqueValues)
}

func parseCommandLineArguments() string {
	baseUrlPtr := flag.String("url", "", "Base URL of the host")
	flag.Parse()
	return *baseUrlPtr
}

func validateBaseUrl(baseUrl string) {
	if baseUrl == "" {
		fmt.Println("Please provide the base URL with the --url flag")
		os.Exit(1)
	}
}

func createHttpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func performGetRequest(client *http.Client, url string) *http.Response {
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GET request failed: %v\n", err)
		os.Exit(1)
	}
	return resp
}

func findPageType(client *http.Client, baseUrl string) (string, string) {
	var fullUrl string

	fullUrl = baseUrl + "/status?full=true"

	if checkPageType(client, fullUrl, "request URI:") {
		return "php-fpm", fullUrl
	}

	fullUrl = baseUrl + "/server-status"

	if checkPageType(client, fullUrl, "Apache Server Status") {
		return "apache-server-status", fullUrl
	}
	return "", ""
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

func extractUniqueValues(client *http.Client, fullUrl string, pageType string) map[string]bool {
	var regex *regexp.Regexp

	resp := performGetRequest(client, fullUrl)
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)

	uniqueValues := make(map[string]bool)

	for scanner.Scan() {
		line := scanner.Text()

		switch pageType {
		case "php-fpm":
			regex, _ = regexp.Compile(`(script|request URI):\s+([^\s]+)`)
			if matches := regex.FindStringSubmatch(line); len(matches) > 2 {
				uniqueValues[matches[2]] = true
			}
		case "apache-server-status":
			regex, _ = regexp.Compile(`(?:GET|OPTIONS)\s+([^\s]+)\s+HTTP`)
			if matches := regex.FindStringSubmatch(line); len(matches) > 1 {
				if matches[1] != "*" {
					uniqueValues[matches[1]] = true
				}
			}
		default:
			regex = nil
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading response body:", err)
		os.Exit(1)
	}

	return uniqueValues
}

func sortAndPrintValues(values map[string]bool) {
	var sortedValues []string
	for value := range values {
		sortedValues = append(sortedValues, value)
	}
	sort.Strings(sortedValues)

	for _, value := range sortedValues {
		fmt.Println(value)
	}
}
