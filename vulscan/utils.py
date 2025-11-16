def extract_version_from_banner(banner):
    if "Server:" in banner:
        try:
            return banner.split("Server:")[1].split("\n")[0].strip()
        except:
            return None
    return None