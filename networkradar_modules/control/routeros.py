"""Safe RouterOS 7 REST adapter for NetworkRadar network controls.

Only fixed, allow-listed RouterOS resources are used. The adapter never exposes
an arbitrary command endpoint, never disables TLS verification, and only
creates/removes objects carrying NetworkRadar-owned comments.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


MANAGED_PAUSE_LIST = "NetworkRadar-paused"
MANAGED_RULE_V4 = "NetworkRadar:managed-internet-pause:ipv4"
MANAGED_RULE_V6 = "NetworkRadar:managed-internet-pause:ipv6"
MANAGED_PREFIX = "NetworkRadar:"
MAX_DURATION_MINUTES = 1440


class RouterOSError(RuntimeError):
    """Sanitised RouterOS REST transport or API error."""


def validate_router_host(host: str, network: str) -> str:
    try:
        address = ipaddress.ip_address(str(host).strip())
        scope = ipaddress.ip_network(str(network).strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Router host and authorised network must be valid IP addresses.") from exc
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
        raise ValueError("Router management is restricted to a private IPv4 address.")
    if scope.version != 4 or not scope.is_private or address not in scope:
        raise ValueError("Router host must be inside the currently authorised private IPv4 subnet.")
    return str(address)


def validate_target_ip(ip: str, network: str, gateway: str = "") -> str:
    try:
        address = ipaddress.ip_address(str(ip).strip())
        scope = ipaddress.ip_network(str(network).strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Target must be a valid IPv4 address in the authorised network.") from exc
    if scope.version != 4 or not scope.is_private or address.version != 4 or not address.is_private or address not in scope:
        raise ValueError("Target must be inside the current authorised private IPv4 subnet.")
    if gateway and str(address) == str(gateway):
        raise ValueError("The default gateway cannot be bandwidth-limited or paused as an endpoint.")
    if address in (scope.network_address, scope.broadcast_address):
        raise ValueError("Network and broadcast addresses are not valid device targets.")
    return str(address)


def validate_duration(minutes) -> int:
    """Accept any whole-minute pause from 1 minute through 24 hours."""
    if isinstance(minutes, bool) or not (
        isinstance(minutes, int)
        or (isinstance(minutes, str) and minutes.strip().isdigit())
    ):
        raise ValueError("Duration must be a whole number of minutes.")
    value = int(minutes)
    if not 1 <= value <= 1440:
        raise ValueError("Pause duration must be between 1 minute and 24 hours.")
    return value


def format_routeros_rate(mbps) -> str:
    try:
        value = float(mbps)
    except (TypeError, ValueError) as exc:
        raise ValueError("Bandwidth must be a number in Mbps.") from exc
    if not 0.064 <= value <= 1000:
        raise ValueError("Bandwidth must be between 0.064 and 1000 Mbps.")
    kbps = int(round(value * 1000))
    if kbps % 1000 == 0:
        return f"{kbps // 1000}M"
    return f"{kbps}k"


def _private_ipv4(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ValueError("A valid private IPv4 address is required.") from exc
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
        raise ValueError("A private IPv4 endpoint address is required.")
    return str(address)


def _rows(value):
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _first(value):
    rows = _rows(value)
    return rows[0] if rows else {}


def _truthy(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RouterOSRESTClient:
    """HTTPS-only RouterOS REST client. Credentials remain in process memory."""

    def __init__(self, host, username, password, port=443, ca_file="",
                 timeout=8.0, opener=None):
        try:
            address = ipaddress.ip_address(str(host).strip())
        except ValueError as exc:
            raise ValueError("Router host must be an IPv4 address, not a URL or hostname.") from exc
        if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
            raise ValueError("RouterOS REST is restricted to a private IPv4 address.")
        if not str(username).strip() or not str(password):
            raise ValueError("A dedicated RouterOS REST username and password are required.")
        try:
            port = int(port)
        except (TypeError, ValueError) as exc:
            raise ValueError("HTTPS port must be an integer.") from exc
        if not 1 <= port <= 65535:
            raise ValueError("HTTPS port must be between 1 and 65535.")
        context = ssl.create_default_context()
        if ca_file:
            path = Path(str(ca_file)).expanduser()
            if not path.is_file():
                raise ValueError("The supplied TLS CA certificate file does not exist.")
            context.load_verify_locations(cafile=str(path.resolve()))
        self.host = str(address)
        self.port = port
        self.username = str(username).strip()
        self._password = str(password)
        self.timeout = min(max(float(timeout), 2.0), 12.0)
        self.base_url = f"https://{self.host}:{self.port}/rest"
        self._opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

    def request(self, method, path, payload=None, params=None):
        if not str(path).startswith("/") or ".." in str(path).split("/"):
            raise ValueError("Invalid RouterOS resource path.")
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {
            "Authorization": "Basic " + __import__("base64").b64encode(
                f"{self.username}:{self._password}".encode("utf-8")
            ).decode("ascii"),
            "Accept": "application/json",
            "Cache-Control": "no-store",
        }
        data = None
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                status = int(getattr(response, "status", 200))
                raw = response.read(1_000_001)
        except urllib.error.HTTPError as exc:
            raw = exc.read(65536)
            detail = ""
            try:
                body = json.loads(raw.decode("utf-8", "replace"))
                detail = str(body.get("detail") or body.get("message") or body.get("error") or "")
            except Exception:
                detail = "Router rejected the request."
            raise RouterOSError(f"RouterOS REST returned HTTP {exc.code}: {detail[:240]}") from None
        except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            reason = getattr(exc, "reason", exc)
            raise RouterOSError(f"Router connection failed: {str(reason)[:180]}") from None
        if 300 <= status < 400:
            raise RouterOSError("RouterOS REST redirects are refused to protect credentials.")
        if len(raw) > 1_000_000:
            raise RouterOSError("RouterOS response exceeded the 1 MB safety limit.")
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RouterOSError("RouterOS returned a non-JSON response; verify the REST endpoint and permissions.") from None

    def get(self, path, params=None):
        return self.request("GET", path, params=params)

    def put(self, path, payload):
        return self.request("PUT", path, payload=payload)

    def patch(self, path, item_id, payload):
        return self.request("PATCH", path + "/" + urllib.parse.quote(str(item_id), safe="*"), payload=payload)

    def delete(self, path, item_id):
        return self.request("DELETE", path + "/" + urllib.parse.quote(str(item_id), safe="*"))


class RouterOSAdapter:
    """Managed queues and expiring IPv4/IPv6 firewall address-list policies."""

    def __init__(self, host, username, password, port=443, ca_file="", client=None):
        self.host = str(host)
        self.client = client or RouterOSRESTClient(host, username, password, port, ca_file)
        self.info = {}

    def connect(self):
        resource = _first(self.client.get("/system/resource"))
        identity = _first(self.client.get("/system/identity"))
        platform = str(resource.get("platform") or "")
        if platform.lower() != "mikrotik":
            raise ValueError("The REST endpoint did not identify itself as MikroTik RouterOS.")
        version = str(resource.get("version") or "")
        try:
            version_parts = tuple(int(part) for part in version.split()[0].split(".")[:2])
        except (ValueError, IndexError):
            version_parts = ()
        if not version_parts or version_parts < (7, 1):
            raise ValueError("NetworkRadar requires RouterOS 7.1 or newer for its REST adapter.")
        lists = _rows(self.client.get("/interface/list"))
        list_names = {str(row.get("name") or "") for row in lists}
        try:
            v6_rows = _rows(self.client.get("/ipv6/firewall/filter", {"chain": "forward"}))
            ipv6_supported = True
        except Exception:
            v6_rows = []
            ipv6_supported = False
        v4_rows = _rows(self.client.get("/ip/firewall/filter", {"chain": "forward"}))
        fasttrack = any(
            str(row.get("action", "")).lower() == "fasttrack-connection"
            and not _truthy(row.get("disabled", "false"))
            for row in v4_rows
        )
        self.info = {
            "platform": platform, "identity": str(identity.get("name") or ""),
            "model": str(resource.get("board-name") or ""),
            "version": version, "uptime": str(resource.get("uptime") or ""),
            "ipv6_supported": ipv6_supported,
            "fasttrack_detected": fasttrack,
            "interface_lists": sorted(name for name in list_names if name),
            "lan_wan_ready": {"LAN", "WAN"}.issubset(list_names),
        }
        return dict(self.info)

    def _require_interface_lists(self):
        lists = _rows(self.client.get("/interface/list"))
        names = {str(row.get("name") or "") for row in lists}
        if not {"LAN", "WAN"}.issubset(names):
            raise ValueError(
                "RouterOS must expose interface lists named LAN and WAN. "
                "NetworkRadar will not guess which interfaces are internal or internet-facing."
            )

    def _ensure_firewall_rule(self, ipv6=False):
        self._require_interface_lists()
        path = "/ipv6/firewall/filter" if ipv6 else "/ip/firewall/filter"
        comment = MANAGED_RULE_V6 if ipv6 else MANAGED_RULE_V4
        rows = _rows(self.client.get(path, {"chain": "forward"}))
        managed = [row for row in rows if str(row.get("comment") or "") == comment]
        expected = {
            "chain": "forward", "action": "drop",
            "src-address-list": MANAGED_PAUSE_LIST,
            "in-interface-list": "LAN", "out-interface-list": "WAN",
        }
        if managed:
            rule = managed[0]
            if len(managed) > 1:
                raise ValueError("Duplicate NetworkRadar firewall rules detected; review them in the router before continuing.")
            if rows and str(rows[0].get(".id")) != str(rule.get(".id")):
                raise ValueError("The managed pause rule is no longer first in the forward chain. Review router rule order before applying controls.")
            for key, value in expected.items():
                if str(rule.get(key) or "").lower() != value.lower():
                    raise ValueError("The existing NetworkRadar firewall rule was modified. It was left untouched for manual review.")
            if _truthy(rule.get("disabled", "false")):
                raise ValueError("The NetworkRadar firewall rule is disabled on the router. Enable it manually after review.")
            return
        payload = dict(expected, comment=comment, disabled="false")
        if rows and rows[0].get(".id"):
            payload["place-before"] = str(rows[0][".id"])
        self.client.put(path, payload)
        verify = _rows(self.client.get(path, {"chain": "forward"}))
        if not verify or str(verify[0].get("comment") or "") != comment:
            for row in verify:
                if str(row.get("comment") or "") == comment and row.get(".id"):
                    self.client.delete(path, row[".id"])
            raise RouterOSError("Could not verify that the NetworkRadar firewall rule is first in the forward chain; the unverified rule was removed.")

    def _rollback_pause_entries(self, comment_prefix):
        """Best-effort removal of entries created by a failed pause operation."""
        self._remove_managed_addresses(
            "/ip/firewall/address-list",
            lambda row: str(row.get("comment") or "").startswith(comment_prefix),
        )
        if self.info.get("ipv6_supported"):
            self._remove_managed_addresses(
                "/ipv6/firewall/address-list",
                lambda row: str(row.get("comment") or "").startswith(comment_prefix),
            )

    @staticmethod
    def _router_timeout(minutes):
        return f"{validate_duration(minutes)}m"

    def _add_timed_address(self, path, address, minutes, comment):
        rows = _rows(self.client.get(path, {"list": MANAGED_PAUSE_LIST}))
        for row in rows:
            if str(row.get("address") or "") != str(address):
                continue
            row_comment = str(row.get("comment") or "")
            if not row_comment.startswith(MANAGED_PREFIX):
                raise ValueError("An address already exists in the NetworkRadar pause list with a different owner comment; no change was made.")
            if row.get(".id"):
                self.client.delete(path, row[".id"])
        self.client.put(path, {
            "list": MANAGED_PAUSE_LIST, "address": str(address),
            "timeout": self._router_timeout(minutes), "comment": comment,
        })

    def _remove_managed_addresses(self, path, predicate):
        removed = 0
        for row in _rows(self.client.get(path, {"list": MANAGED_PAUSE_LIST})):
            comment = str(row.get("comment") or "")
            if comment.startswith("NetworkRadar:pause:") and predicate(row):
                if row.get(".id"):
                    self.client.delete(path, row[".id"])
                    removed += 1
        return removed

    def _lan_ipv6_prefixes(self, ipv4_network):
        # Match the IPv6 prefix only to the RouterOS LAN interface that owns
        # the currently authorised IPv4 subnet. Do not pause unrelated VLANs.
        scope = ipaddress.ip_network(str(ipv4_network), strict=False)
        members = _rows(self.client.get("/interface/list/member", {"list": "LAN"}))
        lan_interfaces = {str(row.get("interface") or "") for row in members}
        matching_interfaces = set()
        for row in _rows(self.client.get("/ip/address")):
            raw = str(row.get("address") or "")
            try:
                interface = ipaddress.ip_interface(raw)
            except ValueError:
                continue
            name = str(row.get("interface") or "")
            if interface.version == 4 and interface.network == scope and name in lan_interfaces:
                matching_interfaces.add(name)
        prefixes = set()
        for row in _rows(self.client.get("/ipv6/address")):
            if str(row.get("interface") or "") not in matching_interfaces:
                continue
            raw = str(row.get("address") or "")
            try:
                interface = ipaddress.ip_interface(raw)
            except ValueError:
                continue
            if interface.version == 6 and interface.ip.is_global:
                prefixes.add(str(interface.network))
        return sorted(prefixes)

    @staticmethod
    def _global_ipv6_addresses(values):
        result = set()
        for value in values or []:
            try:
                address = ipaddress.ip_address(str(value).split("/")[0])
            except ValueError:
                continue
            if address.version == 6 and address.is_global:
                result.add(str(address))
        return sorted(result)

    def pause_device(self, ip, ipv6_addresses, minutes, allow_ipv4_only=False):
        minutes = validate_duration(minutes)
        ip = _private_ipv4(ip)
        ipv6 = self._global_ipv6_addresses(ipv6_addresses)
        ipv6_supported = bool(self.info.get("ipv6_supported"))
        if (not ipv6_supported or not ipv6) and not allow_ipv4_only:
            raise ValueError(
                "Complete dual-stack coverage cannot be verified for this device. "
                "Confirm an explicitly IPv4-only pause to continue."
            )
        # Verify both address families and rule ordering before inserting
        # any active timed entries. Roll back this operation on partial failure.
        self._ensure_firewall_rule(False)
        if ipv6 and ipv6_supported:
            self._ensure_firewall_rule(True)
        prefix = f"NetworkRadar:pause:device:{ip}:"
        try:
            self._add_timed_address(
                "/ip/firewall/address-list", ip + "/32", minutes,
                prefix + "ipv4",
            )
            if ipv6 and ipv6_supported:
                for address in ipv6:
                    self._add_timed_address(
                        "/ipv6/firewall/address-list", address + "/128", minutes,
                        prefix + "ipv6:" + address,
                    )
        except Exception:
            self._rollback_pause_entries(prefix)
            raise
        return {
            "scope": "device", "target": ip, "duration_minutes": minutes,
            "ipv4_blocked": True, "ipv6_blocked_addresses": ipv6 if ipv6_supported else [],
            "ipv6_complete": bool(ipv6_supported and ipv6),
            "note": "RouterOS expires the timed address-list entries automatically. IPv6 privacy-address rotation can create new addresses not yet observed by NetworkRadar."
                    if ipv6 else "IPv4-only restriction; no current global IPv6 address was available for this device.",
        }

    def pause_network(self, network, minutes, allow_ipv4_only=False):
        minutes = validate_duration(minutes)
        scope = ipaddress.ip_network(str(network), strict=False)
        if scope.version != 4 or not scope.is_private or scope.prefixlen < 16:
            raise ValueError("Network-wide pause requires the current private IPv4 subnet, no broader than /16.")
        ipv6_prefixes = []
        if self.info.get("ipv6_supported"):
            ipv6_prefixes = self._lan_ipv6_prefixes(str(scope))
        if not ipv6_prefixes and not allow_ipv4_only:
            raise ValueError(
                "No global IPv6 LAN prefix could be verified. "
                "Confirm an explicitly IPv4-only network pause to continue."
            )
        # Preflight both rule families before activating any address-list
        # entry, then make a best-effort rollback if a later write fails.
        self._ensure_firewall_rule(False)
        if ipv6_prefixes:
            self._ensure_firewall_rule(True)
        prefix = "NetworkRadar:pause:network:"
        try:
            self._add_timed_address(
                "/ip/firewall/address-list", str(scope), minutes,
                prefix + "ipv4",
            )
            for ipv6_prefix in ipv6_prefixes:
                self._add_timed_address(
                    "/ipv6/firewall/address-list", ipv6_prefix, minutes,
                    prefix + "ipv6:" + ipv6_prefix,
                )
        except Exception:
            self._rollback_pause_entries(prefix)
            raise
        return {
            "scope": "network", "target": str(scope), "duration_minutes": minutes,
            "ipv4_blocked": True, "ipv6_blocked_prefixes": ipv6_prefixes,
            "ipv6_complete": bool(ipv6_prefixes),
            "note": "The router expires the timed IPv4/IPv6 entries automatically."
                    if ipv6_prefixes else "IPv4-only restriction; no global IPv6 LAN prefix was verified.",
        }

    def resume_device(self, ip):
        ip = _private_ipv4(ip)
        prefix = f"NetworkRadar:pause:device:{ip}:"
        v4 = self._remove_managed_addresses(
            "/ip/firewall/address-list",
            lambda row: str(row.get("comment") or "").startswith(prefix),
        )
        v6 = 0
        if self.info.get("ipv6_supported"):
            v6 = self._remove_managed_addresses(
                "/ipv6/firewall/address-list",
                lambda row: str(row.get("comment") or "").startswith(prefix),
            )
        return {"target": ip, "removed_ipv4_entries": v4, "removed_ipv6_entries": v6}

    def resume_network(self):
        predicate = lambda row: str(row.get("comment") or "").startswith("NetworkRadar:pause:network:")
        v4 = self._remove_managed_addresses("/ip/firewall/address-list", predicate)
        v6 = 0
        if self.info.get("ipv6_supported"):
            v6 = self._remove_managed_addresses("/ipv6/firewall/address-list", predicate)
        return {"removed_ipv4_entries": v4, "removed_ipv6_entries": v6}

    def set_bandwidth_limit(self, ip, download_mbps, upload_mbps):
        ip = _private_ipv4(ip)
        download = format_routeros_rate(download_mbps)
        upload = format_routeros_rate(upload_mbps)
        comment = f"NetworkRadar:bandwidth:{ip}"
        path = "/queue/simple"
        rows = _rows(self.client.get(path))
        matches = [row for row in rows if str(row.get("comment") or "") == comment]
        if len(matches) > 1:
            raise ValueError("Duplicate NetworkRadar bandwidth queues detected; review them manually.")
        payload = {
            "name": "nr-" + hashlib.sha256(ip.encode("ascii")).hexdigest()[:12],
            "target": ip + "/32", "max-limit": f"{upload}/{download}",
            "comment": comment, "disabled": "false",
        }
        if matches:
            if rows and str(rows[0].get(".id")) != str(matches[0].get(".id")):
                raise ValueError("The managed Simple Queue is not first in queue order. Review queue priority before changing the limit.")
            self.client.patch(path, matches[0].get(".id"), payload)
            action = "updated"
        else:
            if rows and rows[0].get(".id"):
                payload["place-before"] = str(rows[0][".id"])
            self.client.put(path, payload)
            action = "created"
        return {
            "target": ip, "download_mbps": float(download_mbps),
            "upload_mbps": float(upload_mbps), "max_limit": f"{upload}/{download}",
            "action": action,
            "warning": "RouterOS FastTrack can bypass Simple Queues. NetworkRadar detects FastTrack but does not change your existing FastTrack policy.",
        }

    def remove_bandwidth_limit(self, ip):
        ip = _private_ipv4(ip)
        comment = f"NetworkRadar:bandwidth:{ip}"
        rows = _rows(self.client.get("/queue/simple"))
        removed = 0
        for row in rows:
            if str(row.get("comment") or "") == comment and row.get(".id"):
                self.client.delete("/queue/simple", row[".id"])
                removed += 1
        return {"target": ip, "removed_queues": removed}

    def restore_all(self):
        removed_v4 = self._remove_managed_addresses(
            "/ip/firewall/address-list",
            lambda row: str(row.get("comment") or "").startswith("NetworkRadar:pause:"),
        )
        removed_v6 = 0
        if self.info.get("ipv6_supported"):
            removed_v6 = self._remove_managed_addresses(
                "/ipv6/firewall/address-list",
                lambda row: str(row.get("comment") or "").startswith("NetworkRadar:pause:"),
            )
        queues = _rows(self.client.get("/queue/simple"))
        removed_queues = 0
        for row in queues:
            if str(row.get("comment") or "").startswith("NetworkRadar:bandwidth:") and row.get(".id"):
                self.client.delete("/queue/simple", row[".id"])
                removed_queues += 1
        removed_rules = 0
        for path, comment in (
            ("/ip/firewall/filter", MANAGED_RULE_V4),
            ("/ipv6/firewall/filter", MANAGED_RULE_V6),
        ):
            if path.startswith("/ipv6") and not self.info.get("ipv6_supported"):
                continue
            for row in _rows(self.client.get(path, {"chain": "forward"})):
                if str(row.get("comment") or "") == comment and row.get(".id"):
                    self.client.delete(path, row[".id"])
                    removed_rules += 1
        return {
            "removed_ipv4_pause_entries": removed_v4,
            "removed_ipv6_pause_entries": removed_v6,
            "removed_bandwidth_queues": removed_queues,
            "removed_managed_firewall_rules": removed_rules,
        }

    def status(self):
        resource = _first(self.client.get("/system/resource"))
        identity = _first(self.client.get("/system/identity"))
        v4_entries = _rows(self.client.get("/ip/firewall/address-list", {"list": MANAGED_PAUSE_LIST}))
        v4_queues = [
            row for row in _rows(self.client.get("/queue/simple"))
            if str(row.get("comment") or "").startswith("NetworkRadar:bandwidth:")
        ]
        v6_entries = []
        if self.info.get("ipv6_supported"):
            v6_entries = _rows(self.client.get("/ipv6/firewall/address-list", {"list": MANAGED_PAUSE_LIST}))
        return {
            "connected": True, "provider": "mikrotik-routeros",
            "host": self.host, "identity": str(identity.get("name") or ""),
            "model": str(resource.get("board-name") or self.info.get("model") or ""),
            "version": str(resource.get("version") or self.info.get("version") or ""),
            "uptime": str(resource.get("uptime") or ""),
            "ipv6_supported": bool(self.info.get("ipv6_supported")),
            "fasttrack_detected": bool(self.info.get("fasttrack_detected")),
            "interface_lists": self.info.get("interface_lists", []),
            "active_ipv4_pauses": [
                {"address": row.get("address"), "comment": row.get("comment"), "timeout": row.get("timeout")}
                for row in v4_entries if str(row.get("comment") or "").startswith("NetworkRadar:pause:")
            ],
            "active_ipv6_pauses": [
                {"address": row.get("address"), "comment": row.get("comment"), "timeout": row.get("timeout")}
                for row in v6_entries if str(row.get("comment") or "").startswith("NetworkRadar:pause:")
            ],
            "bandwidth_queues": [
                {"target": row.get("target"), "max_limit": row.get("max-limit"), "name": row.get("name")}
                for row in v4_queues
            ],
            "credentials_persisted": False,
        }
