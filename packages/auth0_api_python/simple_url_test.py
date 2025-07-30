#!/usr/bin/env python3
"""
Simple URL Normalization Test Script

Usage:
    python simple_url_test.py
"""

import sys

from auth0_api_python.utils import normalize_url_for_htu

# Test cases covering different normalization aspects
TEST_CASES = [
    # Basic URL
    "https://example.com/path",

    # Case normalization (scheme and host)
    "HTTPS://EXAMPLE.COM/path",

    # Default port removal
    "https://example.com:443/path",

    # Trailing slashes
    "https://example.com/path/",

    # Percent-encoding normalization
    "https://example.com/path%2fto%2fresource",

    # Path normalization
    "https://example.com/path/../resource/./file.txt",

    # Query parameters and fragments
    "https://example.com/path?query=value#fragment",

    # User info and case in path
    "HTTPS://USER:PASS@EXAMPLE.COM:443/path/../RESOURCE/./file.txt?query=value#fragment",

    "https://example.com/path to my file",

    "https://example.com/path to %my+file",

    "https://example.com/path%20to%20%my+file"
]

def process_url(url):
    """Process a single URL and show the normalization result."""
    try:
        normalized = normalize_url_for_htu(url)
        print(f"Input:      {url}")
        print(f"Normalized: {normalized}")
        print("-" * 50)
    except Exception as e:
        print(f"Input:      {url}")
        print(f"Error:      {str(e)}")
        print("-" * 50)

def main():
    """Main function to run the test script."""
    print("URL Normalization Test")
    print("=====================")
    print()

    # Use command line arguments if provided, otherwise use default test cases
    test_urls = sys.argv[1:] if len(sys.argv) > 1 else TEST_CASES

    for url in test_urls:
        process_url(url)

    print("To test your own URLs, run:")
    print(f"python {sys.argv[0]} \"https://example.com/your/path\" \"https://another.example.com/path\"")

if __name__ == "__main__":
    main()
