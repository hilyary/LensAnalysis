from pathlib import Path
from typing import Optional, Union


def resolve_volatility_cache_dir(
    value: Union[str, Path, None], *, create: bool = False
) -> Optional[Path]:
    raw_value = str(value or '').strip().strip('"\'')
    if not raw_value:
        return None

    path = Path(raw_value).expanduser()
    if path.exists() and path.is_file():
        if path.name.lower() == 'identifier.cache':
            path = path.parent
        else:
            raise NotADirectoryError(f'缓存路径不是目录: {path}')

    if create:
        path.mkdir(parents=True, exist_ok=True)

    if not path.is_dir():
        raise NotADirectoryError(f'缓存目录不存在: {path}')
    return path
