"""Privacy-aware interpretation of observed DNS query metadata.

DNS observations reveal queried domains, not HTTPS search terms, page paths or
the text entered into a search box. This module deliberately classifies domain
activity only and never attempts TLS interception or content reconstruction.
"""
from __future__ import annotations

import ipaddress
from collections import Counter


_DOMAIN_GROUPS = {
    "SEARCH": {
        "google.com": "Google", "google.co.ke": "Google", "google.co.uk": "Google", "google.co.in": "Google", "bing.com": "Microsoft Bing",
        "duckduckgo.com": "DuckDuckGo", "search.brave.com": "Brave Search",
        "yandex.com": "Yandex", "baidu.com": "Baidu",
    },
    "VIDEO & STREAMING": {
        "youtube.com": "YouTube", "googlevideo.com": "YouTube delivery",
        "netflix.com": "Netflix", "nflxvideo.net": "Netflix delivery",
        "twitch.tv": "Twitch", "tiktok.com": "TikTok",
    },
    "SOCIAL": {
        "facebook.com": "Facebook", "instagram.com": "Instagram",
        "whatsapp.net": "WhatsApp", "x.com": "X", "twitter.com": "X",
        "reddit.com": "Reddit", "snapchat.com": "Snapchat",
    },
    "GAMING": {
        "steampowered.com": "Steam", "steamcommunity.com": "Steam",
        "xboxlive.com": "Xbox", "playstation.net": "PlayStation",
        "epicgames.com": "Epic Games", "roblox.com": "Roblox",
    },
    "EDUCATION": {
        "khanacademy.org": "Khan Academy", "coursera.org": "Coursera",
        "edx.org": "edX", "duolingo.com": "Duolingo",
        "quizlet.com": "Quizlet", "wikipedia.org": "Wikipedia",
    },
    "CLOUD & PRODUCTIVITY": {
        "microsoft.com": "Microsoft", "office.com": "Microsoft 365",
        "live.com": "Microsoft account", "apple.com": "Apple",
        "icloud.com": "iCloud", "googleapis.com": "Google APIs",
        "dropbox.com": "Dropbox", "zoom.us": "Zoom",
    },
}


def _normalise_domain(value: str) -> str:
    domain = str(value or "").strip().lower().rstrip(".")
    if not domain or len(domain) > 253 or any(ch.isspace() for ch in domain):
        return ""
    if domain.endswith((".local", ".in-addr.arpa", ".ip6.arpa")):
        return ""
    return domain


def classify_domain(domain: str) -> dict:
    """Return conservative category/provider labels; otherwise OTHER."""
    value = _normalise_domain(domain)
    if not value:
        return {"domain": "", "category": "IGNORED", "provider": ""}
    for category, providers in _DOMAIN_GROUPS.items():
        for suffix, provider in providers.items():
            if value == suffix or value.endswith("." + suffix):
                return {"domain": value, "category": category, "provider": provider}
    return {"domain": value, "category": "OTHER", "provider": ""}


def build_domain_activity(rows, *, limit: int = 300) -> dict:
    """Aggregate query rows into device/domain activity without query contents."""
    grouped = {}
    categories = Counter()
    providers = Counter()
    total = 0
    for row in rows or []:
        try:
            timestamp, client_ip, domain, query_type, count = row[:5]
        except (TypeError, ValueError):
            continue
        label = classify_domain(domain)
        if not label["domain"] or not client_ip:
            continue
        try:
            ip = ipaddress.ip_address(str(client_ip))
        except ValueError:
            continue
        if ip.version != 4 or not ip.is_private:
            continue
        key = (str(client_ip), label["domain"])
        item = grouped.setdefault(key, {
            "client_ip": str(client_ip), "domain": label["domain"],
            "category": label["category"], "provider": label["provider"],
            "query_count": 0, "last_seen": str(timestamp or ""),
            "query_types": set(),
        })
        item["query_count"] += max(0, int(count or 0))
        if str(timestamp or "") > item["last_seen"]:
            item["last_seen"] = str(timestamp or "")
        if query_type:
            item["query_types"].add(str(query_type)[:20])
        total += max(0, int(count or 0))
        categories[label["category"]] += max(0, int(count or 0))
        if label["provider"]:
            providers[label["provider"]] += max(0, int(count or 0))
    activity = []
    for item in grouped.values():
        item["query_types"] = sorted(item["query_types"])
        activity.append(item)
    activity.sort(key=lambda item: (item["query_count"], item["last_seen"]), reverse=True)
    return {
        "observed_query_count": total,
        "unique_device_domain_pairs": len(activity),
        "categories": [{"category": key, "query_count": value}
                       for key, value in categories.most_common()],
        "search_providers": [{"provider": key, "query_count": value}
                             for key, value in providers.most_common()],
        "activity": activity[:max(1, min(1000, int(limit)))],
        "limitations": [
            "These are observed DNS domain lookups, not a complete record of every website visit.",
            "HTTPS search phrases, page URLs, page contents and typed queries are not visible in DNS.",
            "Encrypted DNS, VPNs, cached answers, DoH/DoT and network isolation can reduce visibility.",
            "Provider labels are domain-level classifications, not proof of a person performing a search.",
        ],
    }
