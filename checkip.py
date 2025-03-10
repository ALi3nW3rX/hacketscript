import argparse
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning # type: ignore

# Suppress InsecureRequestWarning messages
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Set the number of threads and timeout duration
MAX_THREADS = 10
TIMEOUT = 10

def get_status_message(status_code):
    """Returns a human-readable status message for the given status code"""
    status_messages = {
        200: "OK",
        301: "Moved Permanently",
        302: "Found (Temporary Redirect)",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout"
    }
    return status_messages.get(status_code, "Unknown Status")

def check_redirect_to_https(url, ip):
    """Follows the redirect chain and checks if it leads to HTTPS on port 443 of the same IP"""
    try:
        response = requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
        final_url = response.url
        parsed_final_url = urlparse(final_url)
        
        # Check if the final URL is HTTPS on port 443 with the same IP
        if parsed_final_url.scheme == 'https' and parsed_final_url.hostname == ip and parsed_final_url.port in [443, None]:
            return True, final_url
        
        return False, final_url
    except requests.RequestException as e:
        print(f"[!] Failed to follow redirect for {url}: {e}")
        return False, None

def is_valid_url(url):
    try:
        # Parse the URL to extract scheme, IP, and port
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme
        ip = parsed_url.hostname
        port = parsed_url.port
        
        # If port is not specified, set default based on scheme
        if not port:
            port = 443 if scheme == 'https' else 80
        
        # Reconstruct the URL for the request
        check_url = f"{scheme}://{ip}:{port}"
        
        # Make the request while ignoring SSL certificate warnings
        response = requests.get(check_url, timeout=TIMEOUT, verify=False, allow_redirects=False)
        
        status_code = response.status_code
        status_message = get_status_message(status_code)
        
        # Check for redirection from HTTP (port 80) to HTTPS (port 443)
        if scheme == 'http' and port == 80 and status_code in [301, 302]:
            redirect_to_https, final_url = check_redirect_to_https(check_url, ip)
            if redirect_to_https:
                redirect_message = "Port 80 appears to be associated with a web server that responds by redirecting to another web server on port 443."
                print(f"[+] {check_url} response {status_code} {status_message}")
                print(f"    ↳ {redirect_message} → {final_url}")
                return f"{check_url} response {status_code} {status_message} - {redirect_message} → {final_url}"
            else:
                print(f"[+] {check_url} response {status_code} {status_message} - Redirected to {final_url}")
                return f"{check_url} response {status_code} {status_message} - Redirected to {final_url}"
        
        # General response message
        output = f"{check_url} response {status_code} {status_message}"
        print(f"[+] {output}")
        return output
        
    except requests.ConnectionError:
        print(f"[!] {check_url} [!]] Port {port} appears to be open however this could be due to a firewall or other network issues.")
        return f"{url} response Connection Error"
    except requests.Timeout:
        print(f"[!] {check_url} [!]] Port {port} appears to be open however this could be due to a firewall or other network issues.")
        return f"{url} response Timeout"
    except requests.RequestException as e:
        print(f"[!] {check_url} [!]] Port {port} appears to be open however this could be due to a firewall or other network issues.")
        return f"{url} response Request Exception"
    except Exception as e:
        print(f"[!] Error processing {url}: {e}")
        return f"{url} response Unknown Error"

def parse_file(file_path):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file.readlines()]
    return urls

def check_urls_threaded(urls):
    results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(is_valid_url, url) for url in urls]
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    return results

def save_results(results, output_file='url_responses.txt'):
    # Change encoding to utf-8 to support special characters
    with open(output_file, 'w', encoding='utf-8') as file:
        for line in results:
            file.write(line + '\n')
    print(f"\n[+] URL responses saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Check URLs, follow redirects, and verify HTTPS redirection to port 443 (Ignoring SSL Warnings)")
    parser.add_argument('-f', '--file', required=True, help="Input file containing URLs")
    args = parser.parse_args()

    urls = parse_file(args.file)
    results = check_urls_threaded(urls)
    save_results(results)

if __name__ == "__main__":
    main()
