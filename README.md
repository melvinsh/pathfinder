# pathfinder

![screenshot](https://github.com/melvinsh/pathfinder/assets/1312973/cfe537e3-8602-4913-8cb8-9e299b7a9e69)

## Overview
Pathfinder is an open-source tool designed to identify paths from exposed status pages. It focuses on parsing status pages of web servers and services like Apache, PHP-FPM, and Prometheus to extract unique URLs or paths which can be crucial for security assessments or web reconnaissance.

## Features
- Supports extracting paths from:
  - Apache Server Status pages.
  - PHP-FPM status pages.
  - Prometheus metrics endpoints.
- Simple and efficient command-line interface.
- Sorts and lists unique paths or URLs found in the status pages.
- Uses Go's native libraries for network and regular expression handling.

## Installation
To use Pathfinder, you need to have Go installed on your system. You can install Go from [the official Go website](https://golang.org/dl/). Once Go is installed, you can clone the repository and build the binary:

``` shell
git clone https://github.com/melvinsh/pathfinder.git
cd pathfinder
go install
```

## Usage
To run Pathfinder, use the following command:

``` shell
pathfinder --url <Base URL of the host>
```

- `--url` flag: Specify the base URL of the target host.

Example:

``` shell
pathfinder --url http://example.com
```

You can easily chain it with `httpx` to filter or perform further recon:

``` shell
# Get rid of all 404 pages
pathfinder --url http://example.com | httpx -fc 404
```

## How it Works
1. **Command-Line Argument Parsing**: Parses the base URL of the target host provided by the user.
2. **HTTP Client Creation**: Initializes an HTTP client to handle requests, with TLS verification disabled for broader compatibility.
3. **Page Type Identification**: Determines if the target URL exposes PHP-FPM, Apache Server Status, or Prometheus metrics pages.
4. **Data Extraction**: Extracts unique paths based on the identified page type using regular expressions.
5. **Output**: Sorts and prints the unique paths extracted from the status page as URLs.

## Limitations
Pathfinder currently supports PHP-FPM, Apache Server Status pages, and Prometheus metrics endpoints. Further extensions are planned for future releases.
