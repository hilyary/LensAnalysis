from typing import Optional
from urllib.parse import urlparse

MICROSOFT_SYMBOL_SERVER = 'https://msdl.microsoft.com/download/symbols'
MIRROR_CN_SYMBOL_SERVER = 'http://msdl.blackint3.com:88/download/symbols'

SOURCE_MICROSOFT = 'microsoft'
SOURCE_MIRROR_CN = 'mirror_cn'
SOURCE_CUSTOM = 'custom'


def normalize_symbol_server(url: str) -> str:
    candidate = str(url or '').strip().rstrip('/')
    if not candidate:
        raise ValueError('符号服务器地址不能为空')

    parsed = urlparse(candidate)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        raise ValueError('地址需要以 http:// 或 https:// 开头，例如 http://msdl.example.com:88/download/symbols')

    return candidate


def resolve_symbol_server(source: Optional[str] = None, custom_url: Optional[str] = None) -> str:
    key = str(source or '').strip() or SOURCE_MICROSOFT

    if key == SOURCE_MICROSOFT:
        return MICROSOFT_SYMBOL_SERVER
    if key == SOURCE_MIRROR_CN:
        return MIRROR_CN_SYMBOL_SERVER
    if key == SOURCE_CUSTOM:
        return normalize_symbol_server(custom_url or '')

    raise ValueError(f'未知的符号表下载源: {source}')


def describe_symbol_server(url: str) -> str:
    return urlparse(url).netloc or url
