import time
from typing import Dict
import logging

logger = logging.getLogger(__name__)

def launch_interactive_browser(login_url: str) -> Dict[str, str]:
    """
    Launches a visible Chromium browser for the user to log in interactively.
    Waits for the user to close the browser, continuously capturing cookies.
    Returns the final cookies once the window is closed.
    """
    from playwright.sync_api import sync_playwright
    
    cookie_dict = {}
    
    try:
        with sync_playwright() as p:
            # Launch in headful mode (headless=False) so user can see it
            browser = p.chromium.launch(headless=False)
            context = browser.new_context()
            page = context.new_page()
            
            logger.info(f"Navigating to {login_url} for interactive login...")
            try:
                page.goto(login_url)
            except Exception as e:
                logger.warning(f"Initial navigation error (continuing anyway): {e}")
            
            latest_cookies = []
            
            # Poll cookies continuously until the user closes the window
            while not page.is_closed():
                try:
                    latest_cookies = context.cookies()
                    time.sleep(1)
                except Exception:
                    # Connection closed or context destroyed
                    break
                    
            # Map cookies to a simple key-value dictionary
            cookie_dict = {c['name']: c['value'] for c in latest_cookies}
            
            try:
                browser.close()
            except Exception:
                pass
                
    except Exception as e:
        logger.error(f"Interactive login failed: {e}")
            
    return cookie_dict
