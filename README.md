# pathfinder

## Overview
Pathfinder is an open-source tool designed to identify paths from exposed status pages. It focuses on parsing status pages of web servers and services like Apache and PHP-FPM to extract unique URLs or paths which can be crucial for security assessments or web reconnaissance.

## Features
- Supports extracting paths from Apache Server Status and PHP-FPM status pages.
- Simple and efficient command-line interface.
- Sorts and lists unique paths or URLs found in the status pages.
- Uses Go's native libraries for network and regular expression handling.

## Installation
To use Pathfinder, you need to have Go installed on your system. You can install Go from [the official Go website](https://golang.org/dl/). Once Go is installed, you can clone the repository and build the binary:

```bash
git clone https://github.com/melvinsh/pathfinder.git
cd pathfinder
go install
```

## Usage
To run Pathfinder, use the following command:

```bash
./pathfinder --url <Base URL of the host>
```

- `--url` flag: Specify the base URL of the target host.

Example:

```bash
./pathfinder --url http://example.com
```

## How it Works
1. **Command-Line Argument Parsing**: Parses the base URL of the target host provided by the user.
2. **HTTP Client Creation**: Initializes an HTTP client to handle requests, with TLS verification disabled for broader compatibility.
3. **Page Type Identification**: Determines if the target URL exposes PHP-FPM or Apache Server Status pages.
4. **Data Extraction**: Extracts unique values based on the identified page type using regular expressions.
5. **Output**: Sorts and prints the unique paths or URLs extracted from the status page.

## Limitations
- Pathfinder currently only supports PHP-FPM and Apache Server Status pages.