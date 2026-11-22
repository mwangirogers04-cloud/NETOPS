"""
Web Categorization Engine for NETOPS.
Maps requested domains to categories:
- streaming (YouTube, Netflix, Prime Video, Disney+, Twitch, TikTok videos, etc.)
- gaming (Steam, Roblox, Epic Games, Riot Games, Discord, PlayStation, etc.)
- social_media (Facebook, Instagram, TikTok, Twitter/X, Reddit, Snapchat, etc.)
- gambling_adult (Betway, SportPesa, 1xBet, Betika, Casinos, etc.)
- productivity (Microsoft 365, Google Workspace, GitHub, Zoom, Slack, Jira, etc.)
- general (News, Wikipedia, standard websites)
"""

STREAMING_DOMAINS = {
    "youtube.com", "googlevideo.com", "youtu.be", "ytimg.com",
    "netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com",
    "primevideo.com", "amazonvideo.com",
    "disneyplus.com", "bamgrid.com", "disneystreaming.com",
    "hulu.com", "hulustream.com",
    "twitch.tv", "ttvnw.net", "jtvnw.net",
    "vimeo.com", "dailymotion.com",
    "showmax.com", "tubitv.com", "peacocktv.com",
    "hbomax.com", "max.com", "paramountplus.com",
    "spotify.com", "soundcloud.com", "deezer.com", "audiomack.com",
    "fmovies.to", "fmovies.se", "123movies.net", "123moviesfree.net",
    "solarmovie.pe", "myflixer.to", "soap2day.to",
}

GAMING_DOMAINS = {
    "steampowered.com", "steamcommunity.com", "steamstatic.com", "steamserver.net",
    "epicgames.com", "unrealengine.com", "fortnite.com",
    "roblox.com", "rbxcdn.com",
    "riotgames.com", "leagueoflegends.com", "valgames.com", "pvp.net",
    "blizzard.com", "battle.net", "activision.com",
    "ea.com", "origin.com", "respawn.com",
    "ubisoft.com", "uplay.com",
    "playstation.com", "playstation.net", "sonyentertainmentnetwork.com",
    "xbox.com", "xboxlive.com",
    "nintendo.com", "nintendo.net",
    "discord.com", "discordapp.com", "discord.gg", "discordapp.net",
    "minecraft.net", "mojang.com",
    "garena.com", "supercell.com", "krafton.com", "pubg.com",
}

SOCIAL_MEDIA_DOMAINS = {
    "facebook.com", "fbcdn.net", "fbsbx.com", "m.facebook.com",
    "instagram.com", "cdninstagram.com",
    "tiktok.com", "tiktokv.com", "byteoversea.com", "musical.ly",
    "twitter.com", "x.com", "twimg.com",
    "reddit.com", "redditmedia.com", "redd.it",
    "snapchat.com", "sc-cdn.net",
    "pinterest.com", "pinimg.com",
    "linkedin.com", "licdn.com",
    "threads.net", "bsky.app",
    "t.me", "telegram.org",
}

GAMBLING_ADULT_DOMAINS = {
    "betway.com", "betway.co.ke",
    "sportpesa.com", "sportpesa.co.ke",
    "betika.com", "1xbet.com", "22bet.com", "mozzartbet.co.ke",
    "pokerstars.com", "888casino.com", "bet365.com",
    "thepiratebay.org", "1337x.to", "yts.mx", "rarbg.to",
}

PRODUCTIVITY_DOMAINS = {
    "microsoft.com", "office.com", "office365.com", "live.com", "outlook.com",
    "sharepoint.com", "microsoftteams.com", "azure.com",
    "google.com", "gmail.com", "google.co.ke", "docs.google.com", "drive.google.com",
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "zoom.us", "zoom.com", "slack.com",
    "notion.so", "trello.com", "atlassian.com", "jira.com",
    "salesforce.com", "hubspot.com", "zendesk.com",
    "aws.amazon.com", "cloudflare.com", "digitalocean.com",
    "canva.com", "figma.com", "adobe.com",
    "stackoverflow.com", "superuser.com",
}


def clean_domain(raw_domain: str) -> str:
    """Normalize domain name by lowercasing and stripping trailing dots/spaces."""
    if not raw_domain:
        return ""
    d = raw_domain.strip().rstrip(".").lower()
    # Strip common leading prefix like www. or api. if needed, but preserve domain
    return d


def categorize_domain(domain: str) -> str:
    """
    Categorize a domain into:
    'streaming', 'gaming', 'social_media', 'gambling_adult', 'productivity', or 'general'.
    """
    d = clean_domain(domain)
    if not d:
        return "general"

    # Exact or suffix match
    for st_dom in STREAMING_DOMAINS:
        if d == st_dom or d.endswith("." + st_dom):
            return "streaming"

    for gm_dom in GAMING_DOMAINS:
        if d == gm_dom or d.endswith("." + gm_dom):
            return "gaming"

    for sm_dom in SOCIAL_MEDIA_DOMAINS:
        if d == sm_dom or d.endswith("." + sm_dom):
            return "social_media"

    for gb_dom in GAMBLING_ADULT_DOMAINS:
        if d == gb_dom or d.endswith("." + gb_dom):
            return "gambling_adult"

    for pr_dom in PRODUCTIVITY_DOMAINS:
        if d == pr_dom or d.endswith("." + pr_dom):
            return "productivity"

    # Pattern heuristics
    if any(k in d for k in ("video", "stream", "movie", "cinema", "tv", "flv", "anime")):
        return "streaming"
    if any(k in d for k in ("game", "play", "arcade", "mmo", "rpg", "esport")):
        return "gaming"
    if any(k in d for k in ("bet", "casino", "poker", "lotto", "gamble", "porn", "xxx")):
        return "gambling_adult"

    return "general"


def is_prohibited_during_work(category: str, policy: dict | None = None) -> bool:
    """Check if the given web activity category violates current working hours policy."""
    if not policy:
        # Default: streaming, gaming, gambling are prohibited during work
        return category in ("streaming", "gaming", "gambling_adult")

    if category == "streaming" and policy.get("block_streaming_work_hours", True):
        return True
    if category == "gaming" and policy.get("block_gaming_work_hours", True):
        return True
    if category == "social_media" and policy.get("block_social_media_work_hours", False):
        return True
    if category == "gambling_adult" and policy.get("block_adult_always", True):
        return True

    return False
