import tldextract
import wordninja


def extract_domain_name(url):
    ext = tldextract.extract(url)
    domain_name = ext.domain

    # Common generic phishing/action words to filter out
    stop_words = {
        "online",
        "booking",
        "login",
        "secure",
        "official",
        "support",
        "app",
        "portal",
        "kenya",
    }
    words = wordninja.split(domain_name)

    brand_keywords = [w.lower() for w in words if w.lower() not in stop_words]
    brand_query = " ".join(brand_keywords)

    return brand_query if brand_query else domain_name
