import network
import socket
import ure
import time
import errno
from microwifimanager.microDNSSrv import MicroDNSSrv

# wifi.dat and semi-colon (';') is compatible with other Wifi Manager implementations
NETWORK_PROFILES = 'wifi.dat'
NETWORK_PROFILE_SEPERATOR = ';'  # FIXME ';' (semi-colon) is a valid character for SSIDs :-( Use TAB instead? https://community.cisco.com/t5/wireless-mobility-knowledge-base/characteristics-of-ssids/ta-p/3131765
# Original SSID standard; A valid SSID is 0-32 octets with arbitrary contents. A 0-length SSID indicates the wildcard SSID (in probe request frames for instance). no character set associated with the SSID - a 32-byte string of NUL-bytes is a valid SSID.
# later standards suggest/use utf-8

wlan_ap = network.WLAN(network.AP_IF)
wlan_sta = network.WLAN(network.STA_IF)

class WifiManager:
    ap_ipaddr = '192.168.4.1'  # wlan_ap.ifconfig()[0]  # TODO?

    # authmodes: 0=open, 1=WEP, 2=WPA-PSK, 3=WPA2-PSK, 4=WPA/WPA2-PSK
    def __init__(self, ssid='WifiManager', password='', authmode=0):
        self.ssid = ssid
        self.password = password
        self.authmode = authmode
        self.server_socket = None
        self.hostname = 'hostname_notset'

    def get_connection(self):
        """return a working WLAN(STA_IF) instance or None"""

        # FIXME/TODO force disconnect
        # First check if there already is any connection:
        if wlan_sta.isconnected():
            return wlan_sta
        mac = wlan_ap.config('mac')
        print('MAC %r' % (mac,))
        self.hostname = network.hostname() + '_' + mac[-2:].hex()  # try and get a unique hostname. TODO more digits?
        network.hostname(self.hostname)

        connected = False
        try:
            # ESP connecting to WiFi takes time, wait a bit and try again:
            time.sleep(3)
            if wlan_sta.isconnected():
                return wlan_sta

            # Read known network profiles from file
            profiles = read_profiles()

            # Search WiFis in range
            wlan_sta.active(True)
            networks = wlan_sta.scan()

            AUTHMODE = {0: "open", 1: "WEP", 2: "WPA-PSK", 3: "WPA2-PSK", 4: "WPA/WPA2-PSK"}
            for ssid, bssid, channel, rssi, authmode, hidden in sorted(networks, key=lambda x: x[3], reverse=True):
                ssid = ssid.decode('utf-8')
                encrypted = authmode > 0
                print("ssid: %s chan: %d rssi: %d authmode: %s" % (ssid, channel, rssi, AUTHMODE.get(authmode, '?')))
                if encrypted:
                    if ssid in profiles:
                        password = profiles[ssid]
                        connected = do_connect(ssid, password)
                    else:
                        print("skipping unknown encrypted network")
                else:  # open
                    connected = do_connect(ssid, None)
                if connected:
                    break

        except OSError as e:
            print("exception", str(e))

        # start web server for connection manager:
        if not connected:
            connected = self.start()

        return wlan_sta if connected else None


    def stop(self):
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None

    
    def start(self, port=80):
        print('Starting DNS and web server')
        addr = socket.getaddrinfo('0.0.0.0', port)[0][-1]

        self.stop()

        wlan_sta.active(True)
        wlan_ap.active(True)

        wlan_ap.config(essid=self.ssid, password=self.password, authmode=self.authmode)

        self.server_socket = socket.socket()
        self.server_socket.bind(addr)
        self.server_socket.listen(1)
        print('IP details %r' % (wlan_ap.ifconfig(),))


        #mdns = MicroDNSSrv.Create({ '*' : self.ap_ipaddr })
        hostname = 'clock'
        mdns = MicroDNSSrv.Create({
            hostname: self.ap_ipaddr,
            self.hostname: self.ap_ipaddr,

            'connectivitycheck.gstatic.com': self.ap_ipaddr,
            'detectportal.firefox.com': self.ap_ipaddr,
            'example.org': self.ap_ipaddr,
            '*.google.com': self.ap_ipaddr,
            'google.com': self.ap_ipaddr,
            'captive.apple.com': self.ap_ipaddr,
            'www.msftncsi.com': self.ap_ipaddr,
            'www.msftconnecttest.com': self.ap_ipaddr,
        })

        print('Connect to WiFi ssid ' + self.ssid + ', default password: ' + self.password)
        print('and open browser window (captive portal should redirect)')
        print('Listening on:', addr)

        while True:
            if wlan_sta.isconnected():
                # Allow confirmation page to display before shutting down network
                time.sleep(3)
                mdns.Stop()
                self.stop()
                wlan_ap.active(False)
                return True

            client, addr = self.server_socket.accept()
            print('client connected from', addr)
            try:
                client.settimeout(5.0)

                request = b""
                try:
                    while "\r\n\r\n" not in request:
                        request += client.recv(512)
                except OSError:
                    pass

                # Handle form data from Safari on macOS and iOS; it sends \r\n\r\nssid=<ssid>&password=<password>
                try:
                    request += client.recv(1024)
                    print("Received form data after \\r\\n\\r\\n(i.e. from Safari on macOS or iOS)")
                except OSError:
                    pass

                print("Request is: {}".format(request))
                if "HTTP" not in request:  # skip invalid requests
                    continue



                print("request: %r" % (request,))
                #if self.ap_ipaddr not in request:
                if ('Host: ' + self.ap_ipaddr) not in request and ('Host: ' + hostname) not in request and ('Host: ' + self.hostname) not in request:
                    # skip it, something is trying to get access to something else
                    continue
                # version 1.9 compatibility
                try:
                    url = ure.search("(?:GET|POST) /(.*?)(?:\\?.*?)? HTTP", request).group(1).decode("utf-8").rstrip("/")
                except Exception:
                    url = ure.search("(?:GET|POST) /(.*?)(?:\\?.*?)? HTTP", request).group(1).rstrip("/")
                print("URL is {}".format(url))


                # TODO see if can trigger login to network on phone/PC
                # TODO getting "generate_204 as address"
                if url == "configure" or url == "/configure":
                    handle_configure(client, request)
                if url == "setup" or url == "/setup":
                    handle_setup(client)
                else:  # including; url == "" or url == "/"
                    # TODO consider scan seperate from form - so manually request rescan
                    send_response(client,
                        '''<html>
<head>
<title>WiFi Manager</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:,">
</head>
<center>
404</br><a href="http://clock/setup">Setup http://clock/setup</a></br>
</center></html>''',  # FIXME actual hostname/IP Address
                        status_code=404)

            finally:
                client.close()


def read_profiles():
    with open(NETWORK_PROFILES) as f:
        lines = f.readlines()
    profiles = {}
    for line in lines:
        ssid, password = line.strip("\n").split(NETWORK_PROFILE_SEPERATOR)
        profiles[ssid] = password
    return profiles


def write_profiles(profiles):
    lines = []
    for ssid, password in profiles.items():
        lines.append("%s%s%s\n" % (ssid, NETWORK_PROFILE_SEPERATOR, password))
    with open(NETWORK_PROFILES, "w") as f:
        f.write(''.join(lines))


def do_connect(ssid, password):
    wlan_sta.active(True)
    if wlan_sta.isconnected():
        return None
    print('Trying to connect to %s...' % ssid)
    wlan_sta.connect(ssid, password)
    for retry in range(200):
        connected = wlan_sta.isconnected()
        if connected:
            break
        time.sleep(0.1)  # FIXME use MicroPython sleep_XY()
        print('.', end='')
    if connected:
        print('\nConnected. Network config: ', wlan_sta.ifconfig())
    else:
        print('\nFailed. Not Connected to: ' + ssid)
    return connected


def send_header(client, status_code=200, content_length=None ):
    client.sendall("HTTP/1.0 {} OK\r\n".format(status_code))
    client.sendall("Content-Type: text/html\r\n")
    if content_length is not None:
        client.sendall("Content-Length: {}\r\n".format(content_length))
    client.sendall("\r\n")


def send_response(client, payload, status_code=200):
    content_length = len(payload)
    send_header(client, status_code, content_length)
    if content_length > 0:
        client.sendall(payload)
    client.close()


def handle_setup(client):
    try:
        wlan_sta.active(True)
        ssids = sorted(ssid.decode('utf-8') for ssid, *_ in wlan_sta.scan())
        send_header(client)
        client.sendall("""\
            <html>
<head>
    <title>WiFi Manager</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" href="data:,">
</head>
                <h1 style="color: #5e9ca0; text-align: center;">
                    <span style="color: #ff0000;">
                        Wi-Fi Client Setup
                    </span>
                </h1>
                <form action="configure" method="post">
                    <table style="margin-left: auto; margin-right: auto;">
                        <tbody>
        """)
        while len(ssids):
            ssid = ssids.pop(0)
            client.sendall(f"""\
                            <tr>
                                <td colspan="2">
                                    <input type="radio" name="ssid" value="{ssid}" />{ssid}
                                </td>
                            </tr>
            """)
        client.sendall("""\
                            <tr>
                                <td>Password:</td>
                                <td><input name="password" type="password" /></td>
                            </tr>
                        </tbody>
                    </table>
                    <p style="text-align: center;">
                        <input type="submit" value="Submit" />
                    </p>
                </form>
            </html>
        """)
        client.close()
    except Exception as e:
        if e.errno == errno.ECONNRESET:
            pass
        else:
            raise

def handle_configure(client, request):
    match = ure.search("ssid=([^&]*)&password=(.*)", request)

    if match is None:
        send_response(client, "Parameters not found", status_code=400)
        return False
    # version 1.9 compatibility
    try:
        ssid = match.group(1).decode("utf-8").replace("%3F", "?").replace("%21", "!").replace("+"," ").replace("%26", "&")
        password = match.group(2).decode("utf-8").replace("%3F", "?").replace("%21", "!").replace("%26", "&")
    except Exception:
        ssid = match.group(1).replace("%3F", "?").replace("%21", "!").replace("+"," ").replace("%26", "&")
        password = match.group(2).replace("%3F", "?").replace("%21", "!").replace("%26", "&")

    if len(ssid) == 0:
        send_response(client, "SSID must be provided", status_code=400)
        return False

    if do_connect(ssid, password):
        response = """\
<html>
<head>
    <title>WiFi Manager</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" href="data:,">
</head>
    <center>
        <br><br>
        <h1 style="color: #5e9ca0; text-align: center;">
            <span style="color: #00ff00;">
                ESP successfully connected to WiFi network %(ssid)s.
            </span>
        </h1>
        <br><br>
    </center>
</html>
        """ % dict(ssid=ssid)
        send_response(client, response)
        try:
            profiles = read_profiles()
        except OSError:
            profiles = {}
        profiles[ssid] = password
        write_profiles(profiles)

        time.sleep(5)

        return True
    else:
        response = """\
<html>
    <head>
        <title>WiFi Manager</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="icon" href="data:,">
    </head>
    <center>
        <h1 style="color: #5e9ca0; text-align: center;">
            <span style="color: #ff0000;">
                ESP could not connect to WiFi network %(ssid)s.
            </span>
        </h1>
        <br><br>
        <form>
            <input type="button" value="Go back!" onclick="history.back()"></input>
        </form>
    </center>
</html>
""" % dict(ssid=ssid)
        send_response(client, response)
        return False
