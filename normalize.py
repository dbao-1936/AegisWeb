import re
import ipaddress
from urllib.parse import urlparse

# Regex cho phép chữ, số, dấu chấm, gạch nối. TLD phải >= 2 ký tự chữ cái.
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

def normalize_domain(raw: str) -> str:
    """Chuẩn hóa domain: bỏ protocol, path, port, userinfo, www, trailing dot."""
    if not raw:
        return ""
    
    clean = raw.strip().lower()
    
    # R4-5: Nếu không có scheme, thêm http:// tạm để urlparse xử lý path/port
    if "://" not in clean:
        clean = "http://" + clean
        
    parsed = urlparse(clean)
    
    # Lấy hostname (tự động bỏ port và userinfo)
    hostname = parsed.hostname or ""
    
    # Bỏ www. và trailing dot
    if hostname.startswith("www."):
        hostname = hostname[4:]
    if hostname.endswith("."):
        hostname = hostname[:-1]
        
    return hostname

def validate_domain(domain: str) -> bool:
    """Kiểm tra domain hợp lệ: FQDN, không phải IP, không phải localhost, không rỗng."""
    if not domain:
        return False
    if domain == "localhost":
        return False
    
    # Chặn IP literal (IPv4/IPv6)
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    
    # Kiểm tra định dạng FQDN
    if not DOMAIN_REGEX.match(domain):
        return False
        
    return True