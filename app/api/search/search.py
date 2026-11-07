import urllib.parse

import requests
import tldextract
from bs4 import BeautifulSoup


def find_official_domain(brand_query):
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,"
            " like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
    }
    search_url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(brand_query)}+official+website"

    try:
        response = requests.get(search_url, headers=headers, timeout=10)
    except Exception as e:
        print(f"Error querying DuckDuckGo: {e}")
        return None

    if response.status_code != 200:
        return None

    soup = BeautifulSoup(response.text, "html.parser")

    # Loop through the search result containers on DuckDuckGo's HTML page
    for result in soup.find_all("div", class_="result"):
        # Target the main result anchor link
        a = result.find("a", class_="result__url") or result.find(
            "a", class_="result__a"
        )
        if not a:
            continue

        raw_link = a.get("href", "")

        # DuckDuckGo wraps links in a redirect structure; extract the real target URL via 'uddg'
        if "uddg=" in raw_link:
            parsed_url = urllib.parse.urlparse(raw_link)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            if "uddg" in query_params:
                link = query_params["uddg"][0]
            else:
                continue
        else:
            link = raw_link

        if not link or "duckduckgo.com" in link:
            continue

        # Extract clean registered domain
        ext = tldextract.extract(link)
        if ext.registered_domain:
            # Skip common aggregator/social profiles if they slip through the top
            if any(
                domain in ext.registered_domain
                for domain in ["facebook.com", "wikipedia.org", "twitter.com"]
            ):
                continue
            return f"https://{ext.registered_domain}/"

    return None


print(find_official_domain("easy coach"))
