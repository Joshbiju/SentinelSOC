import asyncio
import os
import re
import socket
import threading
import time
from collections import defaultdict, deque
import psutil
from .config import AUTH_LOGS, PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW

class LocalCollector:
    def _register_local_asset(self):
        """Register the monitored local host as an agentless asset."""
        import os
        import platform
        from .db import execute

        hostname = platform.node() or os.uname().nodename or "localhost"

        os_name = "Linux"
        try:
            release = Path("/etc/os-release").read_text()
            m = re.search(r'^PRETTY_NAME="?(.*?)"?$', release, re.M)
            if m:
                os_name = m.group(1).strip('"')
        except Exception:
            os_name = platform.system()

        execute(
            """
            INSERT INTO assets(hostname, os, status, collection)
            SELECT ?, ?, 'online', 'Agentless Local Collector'
            WHERE NOT EXISTS (
                SELECT 1 FROM assets WHERE hostname=?
            )
            """,
            (hostname, os_name, hostname)
        )

        execute(
            """
            UPDATE assets
            SET os=?, status='online', collection='Agentless Local Collector'
            WHERE hostname=?
            """,
            (os_name, hostname)
        )

    """Agentless collector running inside SentinelSOC on the monitored Kali host."""
    def __init__(self, ingest):
        self._register_local_asset()
        self.ingest = ingest
        self.positions = {}
        self.running = True
        self.scan_hits = defaultdict(deque)
        self.scan_last_alert = {}
        self.local_ips = self._local_ips()

    def _local_ips(self):
        ips = {"127.0.0.1", "::1"}
        try:
            for _, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family in (socket.AF_INET, socket.AF_INET6):
                        ips.add(a.address.split('%')[0])
        except Exception:
            pass
        return ips

    def parse_auth_line(self, line):
        low = line.lower()
        ip_match = re.search(r'(?:from|rhost=|client=)([0-9a-fA-F:.]+)', line, re.I)
        src_ip = ip_match.group(1) if ip_match else None
        if "failed password" in low or "authentication failure" in low or "failed login" in low:
            user_match = re.search(r'for (?:invalid user )?([\w.-]+)', line, re.I)
            return {"event_type":"login_failed", "severity":"medium", "message":line.strip(),
                    "user":user_match.group(1) if user_match else None, "src_ip":src_ip,
                    "source":"linux_auth"}
        if "accepted password" in low or "accepted publickey" in low:
            user_match = re.search(r'for ([\w.-]+)', line, re.I)
            return {"event_type":"login_success", "severity":"info", "message":line.strip(),
                    "user":user_match.group(1) if user_match else None, "src_ip":src_ip, "source":"linux_auth"}
        if "sudo:" in low:
            return {"event_type":"privilege_change", "severity":"info", "message":line.strip(), "source":"linux_auth"}
        if "new user" in low or "useradd" in low or "userdel" in low:
            return {"event_type":"account_change", "severity":"medium", "message":line.strip(), "source":"linux_auth"}
        return None

    async def auth_logs(self):
        while self.running:
            for path in AUTH_LOGS:
                try:
                    if not os.path.exists(path):
                        continue
                    size = os.path.getsize(path)
                    pos = self.positions.get(path, max(0, size - 8192))
                    if size < pos:
                        pos = 0
                    with open(path, errors="replace") as f:
                        f.seek(pos)
                        lines = f.readlines()
                        self.positions[path] = f.tell()
                    for line in lines:
                        event = self.parse_auth_line(line)
                        if event:
                            await self.ingest(event)
                except (PermissionError, OSError):
                    pass
            await asyncio.sleep(1)

    async def metrics(self):
        while self.running:
            try:
                vm = psutil.virtual_memory()
                disk = psutil.disk_usage("/")
                cpu = psutil.cpu_percent(interval=0.1)
                count = len(psutil.pids())
                await self.ingest({"event_type":"system_metrics", "severity":"info",
                    "message":f"CPU {cpu:.1f}% | RAM {vm.percent:.1f}% | Disk {disk.percent:.1f}% | Processes {count}",
                    "raw":{"cpu":cpu,"memory":vm.percent,"disk":disk.percent,"processes":count},
                    "source":"local_monitor"})
            except Exception:
                pass
            await asyncio.sleep(5)

    async def process_inventory(self):
        while self.running:
            try:
                count = len(psutil.pids())
                await self.ingest({"event_type":"process_inventory","severity":"info",
                    "message":f"{count} local processes observed", "raw":{"count":count}, "source":"local_monitor"})
            except Exception:
                pass
            await asyncio.sleep(30)

    async def network_inventory(self):
        while self.running:
            try:
                remote = sum(1 for c in psutil.net_connections(kind="inet") if c.raddr)
                await self.ingest({"event_type":"network_inventory","severity":"info",
                    "message":f"{remote} remote network connections observed", "raw":{"count":remote}, "source":"local_monitor"})
            except Exception:
                pass
            await asyncio.sleep(15)

    def _record_syn(self, src_ip, dst_ip, dst_port, protocol="tcp"):
        if not src_ip or not dst_ip or dst_ip not in self.local_ips:
            return None
        key = (src_ip, dst_ip)
        now = time.time()
        q = self.scan_hits[key]
        q.append((now, int(dst_port), protocol))
        cutoff = now - PORT_SCAN_WINDOW
        while q and q[0][0] < cutoff:
            q.popleft()
        ports = sorted({p for _, p, _ in q})
        last = self.scan_last_alert.get(key, 0)
        if len(ports) >= PORT_SCAN_THRESHOLD and now - last >= PORT_SCAN_WINDOW:
            self.scan_last_alert[key] = now
            return {"event_type":"port_scan", "severity":"high",
                    "message":f"Port scan detected from {src_ip}: {len(ports)} destination TCP ports probed on {dst_ip}",
                    "src_ip":src_ip, "dst_ip":dst_ip, "protocol":"tcp", "source":"packet_sensor",
                    "raw":{"unique_ports":ports, "port_count":len(ports), "window_seconds":PORT_SCAN_WINDOW}}
        return None

    async def packet_sensor(self):
        """Agentless real packet sensor for TCP SYN scans."""
        try:
            from scapy.all import sniff, IP, IPv6, TCP
        except Exception as exc:
            print(f"[SentinelSOC] Scapy unavailable: {exc}", flush=True)
            return

        loop = asyncio.get_running_loop()
        queue = asyncio.Queue()

        def packet_callback(pkt):
            try:
                if not pkt.haslayer(TCP):
                    return

                tcp = pkt[TCP]

                # SYN without ACK = initial TCP connection probe
                if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
                    return

                if pkt.haslayer(IP):
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    src = pkt[IPv6].src
                    dst = pkt[IPv6].dst
                else:
                    return

                event = self._record_syn(src, dst, tcp.dport)

                if event:
                    loop.call_soon_threadsafe(queue.put_nowait, event)

            except Exception as exc:
                print(f"[SentinelSOC] Packet callback error: {exc}", flush=True)

        def sniff_thread():
            try:
                print("[SentinelSOC] Packet sensor listening on lo and eth0", flush=True)

                sniff(
                    iface=["lo", "eth0"],
                    filter="tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0",
                    prn=packet_callback,
                    store=False,
                    stop_filter=lambda _: not self.running
                )

            except Exception as exc:
                print(f"[SentinelSOC] Packet sensor error: {exc}", flush=True)

        t = threading.Thread(target=sniff_thread, daemon=True)
        t.start()

        while self.running:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=1)
                await self.ingest(event)
            except asyncio.TimeoutError:
                continue

    async def start(self):
        await asyncio.gather(self.auth_logs(), self.metrics(), self.process_inventory(), self.network_inventory(), self.packet_sensor())
