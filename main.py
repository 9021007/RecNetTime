from recnetlogin import RecNetLogin
import hmac, base64, struct, hashlib, time
import requests
import pytz
from datetime import datetime

# from https://github.com/TheDanniCraft/2FA-Generator
def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = o = h[19] & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h
def get_totp_token(secret):
    x =str(get_hotp_token(secret,intervals_no=int(time.time())//30))
    while len(x)!=6:
        x+='0'
    return x

# check if config.json exists
try:
    open("config.json", "r")
except FileNotFoundError:
    raise FileNotFoundError("config.json not found. Please create a config.json file with your username, password, and secret, if applicable. See config.json.example for an example.")

# read config.json
with open("config.json", "r") as f:
    config = json.load(f)
    USERNAME = config["username"]
    PASSWORD = config["password"]
    SECRET = config["secret"]
    USING2FA = config["2fa"]
    TIMEZONE = config["timezone"]

tz = pytz.timezone(TIMEZONE)
currenttoken = ""
decoded_token = {}


def main() -> None:
    # generate time, formatted for bio
    currenttime = datetime.now(tz).strftime("%I:%M %p")
    # get existing bio
    existing_bio = requests.get("https://accounts.rec.net/account/2896689/bio").json()["bio"]
    # split bio into lines
    lines = existing_bio.splitlines()
    # replace last line with new time
    lines[-1] = "It is " + currenttime + " for me."
    print(currenttime)
    # join lines back into bio
    new_bio = "\n".join(lines)
    # update bio
    requests.put("https://accounts.rec.net/account/me/bio", data={'bio': new_bio}, headers={'Authorization': currenttoken})


def auth():
    print("authing")
    global decoded_token
    # check if token is within 70 seconds of expiring
    if decoded_token != {}:
        if decoded_token['exp'] - time.time() < 70:
            print("token is expiring")
            rnl.close()
            time.sleep(5)
    # get 2fa code from secret
    current_2fa = get_totp_token(SECRET)
    # attempt login using RecNetLogin
    try:
        if USING2FA == True:
            rnl = RecNetLogin(username=USERNAME, password=PASSWORD, prompt_2fa=True, given_2fa=current_2fa)
        else:
            rnl = RecNetLogin(username=USERNAME, password=PASSWORD)
    except:
        # if login fails, wait 5 seconds and try again
        print("error in auth")
        time.sleep(5)
        auth()
        return
    # get token
    token = rnl.get_token(include_bearer=True)
    # get decoded token
    decoded_token = rnl.get_decoded_token()
    global currenttoken
    # set global variables
    currenttoken = token
    currentrnl = rnl
    # return to main loop
    topofmain()




def topofmain():
    # check if token is empty
    if currenttoken == "":
        print("token is empty")
        auth()
        return
    # check if token is within 70 seconds of expiring
    elif decoded_token['exp'] - time.time() < 70:
        print("token is expiring")
        auth()
        return
    else:
        print("token is valid")
        main()

print("Welcome. This script will update your RecNet bio with the current time every minute.")

# execute loop at top of the minute
while True:
    now = datetime.now(tz)
    if now.second == 0:
        topofmain()
    time.sleep(1)
