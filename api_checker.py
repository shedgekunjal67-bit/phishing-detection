import requests
from urllib.parse import quote

def check_phishstats(url):
    """Checks if a URL exists in the PhishStats database."""
    
    safe_url = quote(url, safe='')
    
    api_url = f"https://phishstats.info:2096/api/phishing?_where=(url,eq,{safe_url})"
    
    try:
        response = requests.get(api_url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            return len(data) > 0   # True if found
        
    except Exception as e:
        print(f"PhishStats lookup error: {e}")
    
    return False
