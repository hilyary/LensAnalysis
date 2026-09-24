import os
import sys
import logging
import hashlib
import json
import re
import uuid
import subprocess
import copy
import threading
import shutil
import time
from urllib.parse import urlparse, unquote
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from backend.cache_paths import (
    default_volatility_cache_dir,
    resolve_volatility_cache_dir,
)
from backend.symbol_sources import (
    SOURCE_CUSTOM,
    SOURCE_MICROSOFT,
    SOURCE_MIRROR_CN,
    describe_symbol_server,
    normalize_symbol_server,
    resolve_symbol_server,
)

logger = logging.getLogger(__name__)


class APIHandler:

    PROJECT_URL = 'https://github.com/hilyary/LensAnalysis'
    _SYMBOL_METADATA_FILENAMES = frozenset({'pdb_info.json'})
    VOLATILITY3_VERSION = '2.27.0'
    _CACHE_FINGERPRINT_VERSION = b'lens-cache-fingerprint-v1'
    _CACHE_FINGERPRINT_CHUNKS = 64
    _CACHE_FINGERPRINT_CHUNK_SIZE = 128 * 1024

    @staticmethod
    def _get_clean_python_env() -> Dict[str, str]:
        clean_env = os.environ.copy()
        for name in (
            'PYTHONHOME',
            'PYTHONPATH',
            'PYTHONNOUSERSITE',
            'PYTHONUSERBASE',
            'PYTHONSAFEPATH',
            'PYTHONEXECUTABLE',
            '__PYVENV_LAUNCHER__',
        ):
            clean_env.pop(name, None)
        clean_env['PYTHONIOENCODING'] = 'utf-8'
        return clean_env

    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.current_image = None
        self._cached_banner = None
        self._last_banner_scan_completed = False
        self._active_analysis_wrappers = {}
        self._active_analysis_lock = threading.Lock()
        self._active_extractions = set()
        self._active_extractions_lock = threading.Lock()
        self._ai_task_context = threading.local()
        self._plugin_task_context = threading.local()

        self._config_file = self._get_config_file_path()

        self._user_data_dir = self._get_user_data_dir()
        self._user_data_dir.mkdir(exist_ok=True)

        self._cache_dir = self._user_data_dir / 'cache'
        self._cache_dir.mkdir(exist_ok=True)

        config = self._load_config()
        settings = config.get('settings', {})
        custom_symbols = settings.get('custom_symbols_path')
        if custom_symbols and Path(custom_symbols).is_dir():
            self._symbols_dir = Path(custom_symbols)
            logger.info(f"使用自定义符号表目录: {self._symbols_dir}")
        else:
            self._symbols_dir = self._user_data_dir / 'symbols'
        self._symbols_dir.mkdir(exist_ok=True)

        self._symbols_base_windows = None
        self._symbols_base_linux = None
        self._symbols_base_mac = None
        for _os_type in ('windows', 'linux', 'mac'):
            _per_os = settings.get(f'custom_symbols_path_{_os_type}')
            if _per_os and Path(_per_os).is_dir():
                setattr(self, f'_symbols_base_{_os_type}', Path(_per_os))
                logger.info(f"使用自定义 {_os_type} 符号表目录: {_per_os}")

        custom_cache = settings.get('custom_cache_path')
        try:
            self._cache_path = resolve_volatility_cache_dir(
                custom_cache, create=bool(custom_cache)
            )
        except OSError as exc:
            logger.warning(f"自定义 vol3 缓存目录不可用，回退默认目录: {exc}")
            self._cache_path = None
        if self._cache_path:
            logger.info(f"使用自定义 vol3 缓存目录: {self._cache_path}")

        self._cleanup_old_updates()

        self.analysis_tasks = {}
        self.task_counter = 0

        self._flag_search_cache = {}

        self._ai_tasks = {}
        self._ai_task_counter = 0
        self._ai_task_lock = threading.Lock()

        config = self._load_config()
        self._proxy_config = config.get('proxy', {})

    @staticmethod
    def _normalize_os_type(os_type: str) -> str:
        os_key = str(os_type or '').strip().lower()
        if os_key in ('macos', 'darwin', 'osx'):
            os_key = 'mac'
        return os_key

    def _get_symbols_base_dir(self, os_type: str = None) -> Path:
        if os_type:
            os_key = self._normalize_os_type(os_type)
            per_os = getattr(self, f'_symbols_base_{os_key}', None)
            if per_os:
                return per_os.parent if per_os.name.lower() == os_key else per_os
        return self._symbols_dir

    def _get_os_symbols_dir(self, os_type: str) -> Path:
        os_key = self._normalize_os_type(os_type)
        per_os = getattr(self, f'_symbols_base_{os_key}', None)
        if per_os:
            return per_os if per_os.name.lower() == os_key else per_os / os_key
        return self._symbols_dir / os_key

    def _get_os_symbol_search_dirs(self, os_type: str) -> List[Path]:
        os_key = self._normalize_os_type(os_type)
        canonical = self._get_os_symbols_dir(os_key)
        directories = [canonical]
        per_os = getattr(self, f'_symbols_base_{os_key}', None)
        if per_os and per_os != canonical:
            directories.append(per_os)
        return directories

    @classmethod
    def _is_symbol_metadata_file(cls, path: Path) -> bool:
        return Path(path).name.lower() in cls._SYMBOL_METADATA_FILENAMES

    @staticmethod
    def _looks_like_volatility_isf(prefix: str) -> bool:
        lowered = str(prefix or '').lower()
        if '"metadata"' not in lowered:
            return False
        return any(
            f'"{key}"' in lowered
            for key in ('base_types', 'user_types', 'enums', 'symbols')
        )

    def _is_volatility_isf_file(self, path: Path) -> bool:
        path = Path(path)
        lowered = path.name.lower()
        if (
            self._is_symbol_metadata_file(path)
            or not path.is_file()
            or not (lowered.endswith('.json') or lowered.endswith('.json.xz'))
        ):
            return False

        try:
            stat = path.stat()
            cache_key = (str(path.resolve()), stat.st_mtime_ns, stat.st_size)
            cache = getattr(self, '_symbol_isf_validation_cache', None)
            if cache is None:
                cache = {}
                self._symbol_isf_validation_cache = cache
            if cache_key in cache:
                return cache[cache_key]
            with open(path, 'rb') as stream:
                prefix = self._read_symbol_candidate_prefix(stream, path.name)
            valid = self._looks_like_volatility_isf(prefix)
            cache[cache_key] = valid
            return valid
        except (OSError, ValueError):
            return False

    def _get_valid_symbol_files(self, os_type: str) -> List[Path]:
        files = []
        seen = set()
        for search_dir in self._get_os_symbol_search_dirs(os_type):
            if not search_dir.exists():
                continue
            for path in list(search_dir.rglob('*.json.xz')) + list(search_dir.rglob('*.json')):
                if not self._is_volatility_isf_file(path):
                    continue
                try:
                    stat = path.stat()
                    identity = (stat.st_dev, stat.st_ino)
                except OSError:
                    identity = str(path.resolve())
                if identity in seen:
                    continue
                seen.add(identity)
                files.append(path)
        return files

    def _get_os_symbols_display_dir(self, os_type: str) -> Path:
        os_key = self._normalize_os_type(os_type)
        return getattr(self, f'_symbols_base_{os_key}', None) or self._get_os_symbols_dir(os_key)

    @staticmethod
    def _materialize_symbol_compatibility_path(source: Path, target: Path) -> Path:
        source = source.resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            return target
        try:
            os.link(str(source), str(target))
        except OSError:
            try:
                target.symlink_to(source)
            except OSError:
                shutil.copy2(str(source), str(target))
        return target

    def _get_config_file_path(self) -> Path:
        import platform
        system = platform.system()

        if system == 'Windows':
            config_dir = Path('C:\\LensAnalysis')
        elif system == 'Darwin':
            config_dir = Path.home() / 'Library' / 'Application Support' / 'LensAnalysis'
        else:  
            config_dir = Path.home() / '.local' / 'share' / 'LensAnalysis'

        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / 'config.json'

    def _has_chinese_chars(self, path: str) -> bool:
        try:
            path.encode('ascii')
            return False
        except UnicodeEncodeError:
            return True

    def _create_hardlink(self, source: Path, target: Path) -> bool:
        import platform
        if platform.system() != 'Windows':
            return False

        try:
            target.parent.mkdir(parents=True, exist_ok=True)

            if target.exists():
                target.unlink()

            os.link(str(source), str(target))
            logger.info(f"创建硬链接成功: {target} -> {source}")
            return True
        except OSError as e:
            logger.warning(f"创建硬链接失败: {e}")
            return False
        except Exception as e:
            logger.error(f"创建硬链接异常: {e}")
            return False

    def _get_vol_link_path(self) -> Path:
        import platform
        if platform.system() == 'Windows':
            link_dir = Path('C:\\LensAnalysis')
            link_dir.mkdir(parents=True, exist_ok=True)
            return link_dir / 'vol.exe'
        return None

    def _cleanup_old_updates(self):
        import platform
        system = platform.system()

        try:
            if system == 'Windows':
                update_dir = Path.home() / 'LensAnalysis_updates'
            else:
                update_dir = self._user_data_dir / 'updates'

            if update_dir.exists():
                for old_file in update_dir.glob('*'):
                    try:
                        if old_file.is_file():
                            old_file.unlink()
                            logger.info(f"已清理旧更新文件: {old_file}")
                    except Exception as e:
                        logger.warning(f"清理旧文件失败: {old_file}, {e}")
        except Exception as e:
            logger.warning(f"清理更新文件时出错: {e}")

    def _get_user_data_dir(self) -> Path:
        import platform
        import sys

        system = platform.system()

        is_nuitka = hasattr(sys, 'nuitka_version') or (
            hasattr(sys, 'argv') and len(sys.argv) > 0 and sys.argv[0].endswith('.exe')
        )
        is_frozen = getattr(sys, 'frozen', False) or is_nuitka

        if system == 'Windows':  
            if is_frozen:
                exe_path = Path(sys.argv[0]).resolve()
                exe_dir = exe_path.parent
                data_dir_conf = exe_dir / 'data_dir.conf'

                if data_dir_conf.exists():
                    try:
                        configured_dir = data_dir_conf.read_text().strip()
                        if Path(configured_dir).exists():
                            logger.info(f"使用安装程序配置的数据目录: {configured_dir}")
                            return Path(configured_dir)
                    except Exception as e:
                        logger.warning(f"读取 data_dir.conf 失败: {e}")

                app_data = exe_dir / 'data'
            else:
                app_data = Path(__file__).parent.parent.parent / 'data'

            try:
                app_data.mkdir(parents=True, exist_ok=True)
                test_file = app_data / '.write_test'
                test_file.touch()
                test_file.unlink()
            except (OSError, PermissionError):
                app_data = Path(os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming')) / 'LensAnalysis'
                app_data.mkdir(parents=True, exist_ok=True)
        elif system == 'Darwin':  
            app_data = Path.home() / 'Library' / 'Application Support' / 'LensAnalysis'
        else:  
            app_data = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')) / 'LensAnalysis'

        return app_data

    def _get_subprocess_kwargs(self, **kwargs) -> Dict[str, Any]:
        import platform
        import subprocess

        if platform.system() == 'Windows':
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

        if kwargs.get('text') and platform.system() == 'Darwin':
            kwargs.setdefault('encoding', 'utf-8')
            kwargs.setdefault('errors', 'replace')

        return kwargs


    def _load_config(self) -> Dict[str, Any]:
        try:
            if self._config_file.exists():
                with open(self._config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"加载配置文件失败: {e}")
        return {}

    def _save_config(self, config: Dict[str, Any]) -> bool:
        try:
            self._config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            logger.info(f"配置已保存到: {self._config_file}")
            return True
        except Exception as e:
            logger.error(f"保存配置文件失败: {e}")
            return False

    def has_user_profile(self) -> bool:
        config = self._load_config()
        profile = config.get('profile', {})
        personal_id = profile.get('personal_id', '') if isinstance(profile, dict) else ''
        return isinstance(personal_id, str) and bool(personal_id.strip())

    def get_user_profile(self) -> Dict[str, Any]:
        config = self._load_config()
        profile = config.get('profile', {})
        personal_id = profile.get('personal_id', '') if isinstance(profile, dict) else ''
        if not isinstance(personal_id, str):
            personal_id = ''
        return {
            'status': 'success',
            'data': {'personal_id': personal_id.strip()},
        }

    def save_user_profile(self, personal_id: str) -> Dict[str, Any]:
        if not isinstance(personal_id, str):
            return {'status': 'error', 'message': '个人 ID 格式无效'}

        personal_id = personal_id.strip()
        if not personal_id:
            return {'status': 'error', 'message': '请输入您的个人 ID'}
        if len(personal_id) > 64:
            return {'status': 'error', 'message': '个人 ID 不能超过 64 个字符'}

        config = self._load_config()
        profile = config.setdefault('profile', {})
        if not isinstance(profile, dict):
            profile = {}
            config['profile'] = profile
        profile['personal_id'] = personal_id

        if not self._save_config(config):
            return {'status': 'error', 'message': '个人 ID 保存失败，请检查配置目录权限'}

        logger.info('欢迎页个人 ID 已保存')
        return {
            'status': 'success',
            'message': '个人 ID 已保存',
            'data': {'personal_id': personal_id},
        }

    def _get_python_cmd(self) -> str:
        config = self._load_config()
        custom_path = config.get('settings', {}).get('custom_python_path')
        if custom_path:
            resolved = self._resolve_python_path(custom_path)
            if resolved:
                return resolved
            logger.error(
                f"自定义 Python 路径已失效: {custom_path}，"
                "请重新选择或恢复默认"
            )
            return str(custom_path)

        import platform
        system = platform.system()
        is_frozen = getattr(sys, 'frozen', False)
        is_nuitka = '__compiled__' in globals() or hasattr(sys, '_nuitka_binary')
        executable_exists = os.path.exists(sys.executable) if sys.executable else False
        is_packaged = is_frozen or '.app' in sys.executable or '.exe' in sys.executable or is_nuitka or not executable_exists

        if is_packaged and system == 'Darwin':
            python_cmd = 'python3'
        elif is_packaged and system == 'Windows':
            python_cmd = 'python'
        elif is_packaged and system == 'Linux':
            python_cmd = 'python3'
        else:
            return sys.executable

        import shutil as _shutil
        resolved = _shutil.which(python_cmd)
        if resolved:
            return resolved
        return python_cmd

    def _resolve_python_path(self, path_str: str):
        import platform

        path = Path(path_str)
        if not path.exists():
            return None

        if path.is_file():
            return str(path)

        system = platform.system()
        if system == 'Windows':
            candidates = ['python.exe', 'python3.exe', 'pythonw.exe']
        else:
            candidates = ['python3', 'python', 'python3.13', 'python3.12', 'python3.11', 'python3.10', 'python3.9']

        for name in candidates:
            candidate = path / name
            if candidate.exists() and candidate.is_file():
                logger.info(f"在目录 {path_str} 中找到 Python: {candidate}")
                return str(candidate)

        for name in candidates:
            candidate = path / 'bin' / name
            if candidate.exists() and candidate.is_file():
                logger.info(f"在目录 {path_str}/bin 中找到 Python: {candidate}")
                return str(candidate)

        logger.warning(f"在目录 {path_str} 中未找到 Python 可执行文件")
        return None

    def _validate_python_executable(self, python_cmd: str) -> Tuple[bool, str]:
        clean_env = self._get_clean_python_env()

        probe = (
            'import platform,sys;'
            'print(sys.executable);'
            'print(platform.python_version());'
            'print(platform.machine())'
        )
        subprocess_kwargs = self._get_subprocess_kwargs(
            capture_output=True,
            text=True,
            timeout=15,
            env=clean_env,
            cwd=str(Path.home())
        )
        try:
            result = subprocess.run([python_cmd, '-c', probe], **subprocess_kwargs)
        except Exception as e:
            return False, str(e)

        if result.returncode != 0:
            return False, (result.stderr or result.stdout or '无法启动 Python').strip()

        stdout = result.stdout or ''
        if stdout.strip():
            details = [line.strip() for line in stdout.splitlines() if line.strip()]
            return True, ' / '.join(details[-3:])
        return True, 'Python 可用'

    def _get_python_version(self, python_cmd: str) -> Optional[Tuple[int, int]]:
        clean_env = self._get_clean_python_env()
        subprocess_kwargs = self._get_subprocess_kwargs(
            capture_output=True,
            text=True,
            timeout=10,
            env=clean_env,
            cwd=str(Path.home())
        )
        try:
            result = subprocess.run(
                [
                    python_cmd,
                    '-c',
                    'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")'
                ],
                **subprocess_kwargs
            )
            if result.returncode == 0:
                match = re.search(r'(\d+)\.(\d+)', result.stdout)
                if match:
                    return int(match.group(1)), int(match.group(2))
        except Exception as e:
            logger.warning(f"无法获取目标 Python 版本: {e}")
        return None

    def _get_python_platform(
        self, python_cmd: str
    ) -> Optional[Tuple[str, str]]:
        clean_env = self._get_clean_python_env()
        subprocess_kwargs = self._get_subprocess_kwargs(
            capture_output=True,
            text=True,
            timeout=10,
            env=clean_env,
            cwd=str(Path.home())
        )
        try:
            result = subprocess.run(
                [
                    python_cmd,
                    '-c',
                    'import platform,sys; print(sys.platform); print(platform.machine())'
                ],
                **subprocess_kwargs
            )
            if result.returncode == 0:
                stdout = result.stdout or ''
                details = [
                    line.strip().lower()
                    for line in stdout.splitlines()
                    if line.strip()
                ]
                if len(details) >= 2:
                    return details[-2], details[-1]
        except Exception as e:
            logger.warning(f"无法获取目标 Python 平台: {e}")
        return None

    def _get_python_package_paths(self, python_cmd: str) -> List[str]:
        probe = (
            'import json,site,sysconfig;'
            'user=site.getusersitepackages();'
            'user=[user] if isinstance(user,str) else list(user);'
            'paths=sysconfig.get_paths();'
            'print(json.dumps([paths.get("purelib"),paths.get("platlib")]+user))'
        )
        subprocess_kwargs = self._get_subprocess_kwargs(
            capture_output=True,
            text=True,
            timeout=15,
            env=self._get_clean_python_env(),
            cwd=str(Path.home())
        )
        try:
            result = subprocess.run(
                [python_cmd, '-c', probe],
                **subprocess_kwargs
            )
            if result.returncode != 0:
                logger.warning(
                    "无法读取目标 Python 的 site-packages: "
                    f"{(result.stderr or result.stdout).strip()}"
                )
                return []
            paths = json.loads(result.stdout)
            return list(dict.fromkeys(
                str(path) for path in paths if path
            ))
        except Exception as e:
            logger.warning(f"无法读取目标 Python 的 site-packages: {e}")
            return []

    def _find_vol_from_python(self, python_cmd: str):
        import platform

        if '/' not in python_cmd and '\\' not in python_cmd:
            return None

        python_path = Path(python_cmd)
        python_dir = python_path.parent
        resolve_dir = python_path.resolve().parent if python_path.is_symlink() else None
        system = platform.system()

        if system == 'Windows':
            candidates = [
                python_path.parent / 'Scripts' / 'vol.exe',
                python_path.parent / 'vol.exe',
            ]
        else:
            candidates = [
                python_path.parent / 'vol',
                python_path.parent / 'vol3',
            ]

        for candidate in candidates:
            if candidate.exists():
                return str(candidate)

        if resolve_dir and resolve_dir != python_dir:
            for candidate in candidates:
                resolved_candidate = resolve_dir / candidate.relative_to(python_dir)
                if resolved_candidate.exists():
                    return str(resolved_candidate)

        return None

    def _get_vol_path(self) -> Optional[str]:
        import shutil
        import platform

        config = self._load_config()
        settings = config.get('settings', {})
        custom_python_set = settings.get('custom_python_path')

        custom_vol_path = settings.get('custom_vol_path')
        if custom_vol_path:
            vol_path = Path(custom_vol_path).expanduser()
            if vol_path.is_file() and os.access(vol_path, os.X_OK):
                logger.info(f"使用自定义 vol 路径: {vol_path}")
                return str(vol_path)
            logger.warning(f"自定义 vol 路径无效或不可执行: {custom_vol_path}")

        python_cmd = self._get_python_cmd()
        if custom_python_set and python_cmd:
            vol_from_python = self._find_vol_from_python(python_cmd)
            if vol_from_python:
                logger.info(
                    f"从配置 Python 环境的命令入口目录找到 vol: {vol_from_python} "
                    f"(Python: {python_cmd})"
                )
                return vol_from_python

        if custom_python_set:
            logger.info("自定义 Python 已设置但未找到对应 vol，将使用该 Python 的模块方式")
            return None

        if python_cmd:
            vol_from_python = self._find_vol_from_python(python_cmd)
            if vol_from_python:
                logger.info(
                    f"从默认 Python 环境的命令入口目录找到 vol: {vol_from_python} "
                    f"(Python: {python_cmd})"
                )
                return vol_from_python

        vol_path = shutil.which('vol')
        if vol_path:
            if self._has_chinese_chars(vol_path):
                logger.warning(f"检测到 vol 路径包含中文字符: {vol_path}")

                if platform.system() == 'Windows':
                    link_path = self._get_vol_link_path()
                    if link_path:
                        logger.info(f"尝试创建硬链接: {link_path}")
                        if self._create_hardlink(Path(vol_path), link_path):
                            logger.info(f"自动创建硬链接成功，使用硬链接路径: {link_path}")
                            return str(link_path)
                        else:
                            logger.warning("硬链接创建失败，回退使用原路径")
                            logger.warning("这可能导致命令执行失败，请在设置中指定不含中文的 vol 路径")
                else:
                    logger.warning("这可能导致命令执行失败，请在设置中指定不含中文的 vol 路径")
            return vol_path

        system = platform.system()

        if system == 'Darwin':  
            home_paths = [
                Path.home() / 'Library' / 'Python' / '3.9' / 'bin' / 'vol',
                Path.home() / 'Library' / 'Python' / '3.10' / 'bin' / 'vol',
                Path.home() / 'Library' / 'Python' / '3.11' / 'bin' / 'vol',
                Path.home() / 'Library' / 'Python' / '3.12' / 'bin' / 'vol',
                Path.home() / '.local' / 'bin' / 'vol',
            ]
            for path in home_paths:
                if path.exists():
                    return str(path)
        elif system == 'Linux':
            possible_paths = [
                Path.home() / '.local' / 'bin' / 'vol',
                Path('/usr/local/bin/vol'),
                Path('/usr/bin/vol'),
            ]
            for path in possible_paths:
                if path.exists() and os.access(path, os.X_OK):
                    return str(path)
        elif system == 'Windows':
            home_paths = [
                Path.home() / 'AppData' / 'Local' / 'Programs' / 'Python' / 'Scripts' / 'vol.exe',
                Path.home() / 'AppData' / 'Roaming' / 'Python' / 'Scripts' / 'vol.exe',
            ]
            for path in home_paths:
                if path.exists():
                    return str(path)

        return None

    def get_settings(self) -> Dict[str, Any]:
        import platform

        try:
            config = self._load_config()
            settings = config.get('settings', {})

            vol_path_warning = None
            vol_path = self._get_vol_path()

            if not vol_path:
                vol_path_warning = "未找到 vol 命令，请先安装 Volatility 3"

            return {
                'status': 'success',
                'data': settings,
                'current_python_path': self._get_python_cmd(),
                'default_cache_path': str(default_volatility_cache_dir()),
                'warnings': {
                    'vol_path_chinese': vol_path_warning
                } if vol_path_warning else None
            }
        except Exception as e:
            logger.error(f"获取设置失败: {e}")
            return {
                'status': 'error',
                'message': f'获取设置失败: {str(e)}'
            }

    def save_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        try:
            config = self._load_config()

            old_python_path = config.get('settings', {}).get('custom_python_path')

            if 'custom_vol_path' in settings:
                vol_path_str = settings['custom_vol_path'].strip()
                if not vol_path_str:
                    old_path = config.get('settings', {}).get('custom_vol_path')
                    if old_path:
                        old_cache_key = f'_vol_verified_{old_path}'
                        if hasattr(self, old_cache_key):
                            delattr(self, old_cache_key)
                    config.get('settings', {}).pop('custom_vol_path', None)
                    logger.info("已清除自定义 vol 路径")
                else:
                    vol_path = Path(vol_path_str)
                    if vol_path.exists() and os.access(vol_path, os.X_OK):
                        try:
                            import subprocess as _sp
                            _r = _sp.run([str(vol_path), '--help'],
                                         capture_output=True, text=True, timeout=15)
                            _out = (_r.stdout + _r.stderr).lower()
                            if 'volatility' not in _out:
                                return {
                                    'status': 'error',
                                    'message': f'该路径不是有效的 vol 命令（输出中未包含 volatility）: {vol_path_str}'
                                }
                        except Exception as e:
                            return {
                                'status': 'error',
                                'message': f'验证 vol 路径失败: {e}'
                            }

                        old_path = config.get('settings', {}).get('custom_vol_path')
                        if old_path:
                            old_cache_key = f'_vol_verified_{old_path}'
                            if hasattr(self, old_cache_key):
                                delattr(self, old_cache_key)
                        config.setdefault('settings', {})['custom_vol_path'] = str(vol_path)
                        logger.info(f"已设置自定义 vol 路径: {vol_path}")
                    else:
                        return {
                            'status': 'error',
                            'message': f'指定的 vol 路径无效或不可执行: {settings["custom_vol_path"]}'
                        }

            if 'custom_python_path' in settings:
                python_path_str = settings['custom_python_path'].strip()
                if not python_path_str:
                    config.get('settings', {}).pop('custom_python_path', None)
                    logger.info("已清除自定义 Python 路径")
                else:
                    python_path = Path(python_path_str)
                    if not python_path.exists():
                        return {
                            'status': 'error',
                            'message': f'指定的 Python 路径不存在: {settings["custom_python_path"]}'
                        }
                    resolved = None
                    if python_path.is_dir():
                        resolved = self._resolve_python_path(python_path_str)
                        if not resolved:
                            return {
                                'status': 'error',
                                'message': f'在目录 {python_path_str} 中未找到 Python 可执行文件'
                            }
                    else:
                        resolved = str(python_path)

                    valid, python_details = self._validate_python_executable(resolved)
                    if not valid:
                        return {
                            'status': 'error',
                            'message': f'指定路径不是可用的 Python：{python_details}'
                        }

                    if python_path.is_dir():
                        config.setdefault('settings', {})['custom_python_path'] = python_path_str
                        logger.info(
                            f"已设置自定义 Python 目录: {python_path_str} -> "
                            f"{resolved} ({python_details})"
                        )
                    else:
                        config.setdefault('settings', {})['custom_python_path'] = str(python_path)
                        logger.info(
                            f"已设置自定义 Python 路径: {python_path} "
                            f"({python_details})"
                        )

            if 'custom_symbols_path' in settings:
                symbols_path_str = settings['custom_symbols_path'].strip()
                if symbols_path_str:
                    has_per_os = any(
                        settings.get(f'custom_symbols_path_{_os}', '').strip()
                        for _os in ('windows', 'linux', 'mac')
                    )
                    if has_per_os:
                        return {
                            'status': 'error',
                            'message': '不能同时设置通用符号表目录和按操作系统的符号表目录，请先清除按操作系统的目录'
                        }
                    symbols_path = Path(symbols_path_str)
                    if symbols_path.is_dir():
                        config.setdefault('settings', {})['custom_symbols_path'] = str(symbols_path)
                        for _os in ('windows', 'linux', 'mac'):
                            config.get('settings', {}).pop(f'custom_symbols_path_{_os}', None)
                        logger.info(f"已设置自定义符号表目录: {symbols_path}")
                    else:
                        return {
                            'status': 'error',
                            'message': f'指定的目录不存在: {settings["custom_symbols_path"]}'
                        }
                else:
                    config.get('settings', {}).pop('custom_symbols_path', None)
                    logger.info("已清除自定义符号表目录")

            for os_type in ('windows', 'linux', 'mac'):
                key = f'custom_symbols_path_{os_type}'
                if key in settings:
                    os_path_str = settings[key].strip()
                    if os_path_str:
                        if config.get('settings', {}).get('custom_symbols_path'):
                            return {
                                'status': 'error',
                                'message': f'不能同时设置通用符号表目录和按操作系统的符号表目录，请先清除通用目录'
                            }
                        os_path = Path(os_path_str)
                        if os_path.is_dir():
                            config.setdefault('settings', {})[key] = str(os_path)
                            logger.info(f"已设置自定义 {os_type} 符号表目录: {os_path}")
                        else:
                            return {
                                'status': 'error',
                                'message': f'指定的 {os_type} 目录不存在: {os_path_str}'
                            }
                    else:
                        config.get('settings', {}).pop(key, None)
                        logger.info(f"已清除自定义 {os_type} 符号表目录")

            if 'custom_cache_path' in settings:
                cache_path_str = settings['custom_cache_path'].strip()
                if cache_path_str:
                    try:
                        cache_dir = resolve_volatility_cache_dir(cache_path_str, create=True)
                    except OSError as exc:
                        return {
                            'status': 'error',
                            'message': f'无法使用指定的缓存目录: {exc}'
                        }
                    config.setdefault('settings', {})['custom_cache_path'] = str(cache_dir)
                    logger.info(f"已设置自定义 vol3 缓存目录: {cache_dir}")
                else:
                    config.get('settings', {}).pop('custom_cache_path', None)
                    logger.info("已清除自定义 vol3 缓存目录")

            if 'symbol_download_source' in settings or 'custom_symbol_server' in settings:
                stored_settings = config.setdefault('settings', {})
                source = str(
                    settings.get('symbol_download_source', stored_settings.get('symbol_download_source')) or ''
                ).strip() or SOURCE_MICROSOFT

                if 'custom_symbol_server' in settings:
                    raw_url = str(settings.get('custom_symbol_server') or '')
                else:
                    raw_url = str(stored_settings.get('custom_symbol_server') or '')

                try:
                    custom_url = normalize_symbol_server(raw_url) if raw_url.strip() else ''
                    if source == SOURCE_CUSTOM and not custom_url:
                        raise ValueError('选择自定义下载源时需要填写地址')
                    if source not in (SOURCE_MICROSOFT, SOURCE_MIRROR_CN, SOURCE_CUSTOM):
                        raise ValueError(f'未知的下载源: {source}')
                except ValueError as exc:
                    return {
                        'status': 'error',
                        'message': f'符号表下载源无效: {exc}'
                    }

                stored_settings['symbol_download_source'] = source
                if custom_url:
                    stored_settings['custom_symbol_server'] = custom_url
                else:
                    stored_settings.pop('custom_symbol_server', None)
                logger.info(f"已设置符号表下载源: {source}")

            _excluded_keys = {'custom_vol_path', 'custom_python_path', 'custom_symbols_path',
                              'custom_symbols_path_windows', 'custom_symbols_path_linux', 'custom_symbols_path_mac',
                              'custom_cache_path', 'symbol_download_source', 'custom_symbol_server'}
            other_settings = {k: v for k, v in settings.items()
                              if k not in _excluded_keys}
            if other_settings:
                config.setdefault('settings', {}).update(other_settings)

            self._save_config(config)

            new_python_path = config.get('settings', {}).get('custom_python_path')
            python_changed = (
                (old_python_path or '') != (new_python_path or '')
                and 'custom_python_path' in settings
            )

            result = {
                'status': 'success',
                'message': '设置已保存'
            }
            if python_changed:
                result['restart_recommended'] = True
                result['message'] = (
                    'Python 路径已切换。为避免环境状态混乱，建议重启 LensAnalysis。'
                )
            return result
        except Exception as e:
            logger.error(f"保存设置失败: {e}")
            return {
                'status': 'error',
                'message': f'保存设置失败: {str(e)}'
            }


    def _normalize_ai_profiles(self, ai_data: Dict[str, Any]) -> Dict[str, Any]:
        from backend.ai.config import AIConfig

        ai_data = ai_data or {}
        raw_profiles = ai_data.get('profiles') if isinstance(ai_data.get('profiles'), list) else []
        profiles = []
        for index, item in enumerate(raw_profiles):
            if not isinstance(item, dict):
                continue
            profile = AIConfig.from_dict(item).to_dict(mask_key=False)
            profile.update({
                'id': str(item.get('id') or f'ai_profile_{index + 1}'),
                'name': str(item.get('name') or item.get('profile_name') or item.get('provider') or f'配置 {index + 1}'),
                'verified': bool(item.get('verified', False)),
                'verified_at': item.get('verified_at') or '',
                'last_test_status': item.get('last_test_status') or '',
                'last_test_message': item.get('last_test_message') or '',
                'created_at': item.get('created_at') or datetime.now().isoformat(),
                'updated_at': item.get('updated_at') or item.get('created_at') or datetime.now().isoformat(),
            })
            profiles.append(profile)

        if not profiles:
            legacy = AIConfig.from_dict(ai_data).to_dict(mask_key=False)
            profiles.append({
                **legacy,
                'id': str(ai_data.get('active_profile_id') or 'default'),
                'name': str(ai_data.get('name') or ai_data.get('profile_name') or '默认配置'),
                'verified': bool(ai_data.get('verified', False)),
                'verified_at': ai_data.get('verified_at') or '',
                'last_test_status': ai_data.get('last_test_status') or '',
                'last_test_message': ai_data.get('last_test_message') or '',
                'created_at': ai_data.get('created_at') or datetime.now().isoformat(),
                'updated_at': ai_data.get('updated_at') or datetime.now().isoformat(),
            })

        active_id = str(ai_data.get('active_profile_id') or profiles[0]['id'])
        if not any(profile['id'] == active_id for profile in profiles):
            active_id = profiles[0]['id']

        return {
            'active_profile_id': active_id,
            'profiles': profiles,
        }

    def _active_ai_profile(self, config: Dict[str, Any]) -> Dict[str, Any]:
        ai_state = self._normalize_ai_profiles(config.get('ai', {}))
        active_id = ai_state['active_profile_id']
        return next((profile for profile in ai_state['profiles'] if profile['id'] == active_id), ai_state['profiles'][0])

    def _mask_ai_profile(self, profile: Dict[str, Any]) -> Dict[str, Any]:
        from backend.ai.config import AIConfig

        masked = AIConfig.from_dict(profile).to_dict(mask_key=True)
        for key in (
            'id', 'name', 'verified', 'verified_at', 'last_test_status',
            'last_test_message', 'created_at', 'updated_at'
        ):
            masked[key] = profile.get(key)
        return masked

    def _save_ai_state(self, config: Dict[str, Any], ai_state: Dict[str, Any]) -> None:
        config['ai'] = {
            'active_profile_id': ai_state.get('active_profile_id'),
            'profiles': ai_state.get('profiles') or [],
        }
        self._save_config(config)

    def _merge_ai_profile_settings(self, old_profile: Dict[str, Any], ai_settings: Dict[str, Any]) -> Dict[str, Any]:
        profile = dict(old_profile or {})
        for key in (
            'provider', 'base_url', 'api_key', 'model', 'temperature',
            'timeout', 'max_tool_rounds', 'enabled'
        ):
            if key not in ai_settings:
                continue
            value = ai_settings.get(key)
            if key == 'api_key' and (not value or '***' in str(value) or '...' in str(value)):
                continue
            profile[key] = value
        profile['id'] = str(ai_settings.get('profile_id') or profile.get('id') or f"ai_profile_{uuid.uuid4().hex[:8]}")
        profile['name'] = str(ai_settings.get('profile_name') or profile.get('name') or profile.get('provider') or 'AI 配置')
        profile['updated_at'] = datetime.now().isoformat()
        profile.setdefault('created_at', profile['updated_at'])
        return profile

    def get_ai_config(self) -> Dict[str, Any]:
        try:
            config = self._load_config()
            ai_state = self._normalize_ai_profiles(config.get('ai', {}))
            active = next(
                (profile for profile in ai_state['profiles'] if profile['id'] == ai_state['active_profile_id']),
                ai_state['profiles'][0],
            )
            data = self._mask_ai_profile(active)
            data['active_profile_id'] = ai_state['active_profile_id']
            data['profiles'] = [self._mask_ai_profile(profile) for profile in ai_state['profiles']]
            return {
                'status': 'success',
                'data': data
            }
        except Exception as e:
            logger.error(f"获取 AI 配置失败: {e}")
            return {
                'status': 'error',
                'message': f'获取 AI 配置失败: {str(e)}'
            }

    def get_ai_provider_presets(self) -> Dict[str, Any]:
        try:
            from backend.ai.config import get_provider_presets

            return {
                'status': 'success',
                'data': {
                    'providers': get_provider_presets()
                }
            }
        except Exception as e:
            logger.error(f"获取 AI 供应商预设失败: {e}")
            return {
                'status': 'error',
                'message': f'获取 AI 供应商预设失败: {str(e)}'
            }

    def save_ai_config(self, ai_settings: Dict[str, Any]) -> Dict[str, Any]:
        try:
            from backend.ai.config import AIConfig

            config = self._load_config()
            ai_state = self._normalize_ai_profiles(config.get('ai', {}))
            profile_id = str(ai_settings.get('profile_id') or ai_state.get('active_profile_id') or 'default')
            old_profile = next((profile for profile in ai_state['profiles'] if profile['id'] == profile_id), {})
            merged = self._merge_ai_profile_settings(old_profile, ai_settings)

            ai_config = AIConfig.from_dict(merged)
            ok, message = ai_config.validate()
            if not ok and ai_config.enabled:
                return {'status': 'error', 'message': message}

            current_active_id = ai_state['active_profile_id']
            activate_profile = bool(ai_settings.get(
                'activate_profile',
                merged['id'] == current_active_id,
            ))
            next_active_id = merged['id'] if activate_profile else current_active_id
            active_profile = next(
                (profile for profile in ai_state['profiles'] if profile['id'] == current_active_id),
                ai_state['profiles'][0],
            )
            active_endpoint_changed = (
                merged['id'] == current_active_id
                and any(
                    str(merged.get(key) or '') != str(active_profile.get(key) or '')
                    for key in ('provider', 'base_url')
                )
            )
            requires_switch_consent = (
                (activate_profile and next_active_id != current_active_id)
                or active_endpoint_changed
            )
            if requires_switch_consent and not bool(ai_settings.get('user_consent_to_switch')):
                return {
                    'status': 'consent_required',
                    'message': '切换 AI 配置档案或供应商需要用户明确确认，本次未保存。',
                    'data': {
                        'active_profile_id': current_active_id,
                        'requested_profile_id': merged['id'],
                    },
                }

            old_effective = {key: old_profile.get(key) for key in ('provider', 'base_url', 'model', 'api_key')}
            new_effective = {key: merged.get(key) for key in ('provider', 'base_url', 'model', 'api_key')}
            if old_effective != new_effective:
                merged['verified'] = False
                merged['verified_at'] = ''
                merged['last_test_status'] = '未验证'

            profiles = [profile for profile in ai_state['profiles'] if profile['id'] != merged['id']]
            profiles.append({**merged, **ai_config.to_dict(mask_key=False)})
            ai_state = {
                'active_profile_id': next_active_id,
                'profiles': profiles,
            }
            self._save_ai_state(config, ai_state)
            active = next(profile for profile in profiles if profile['id'] == next_active_id)
            data = self._mask_ai_profile(active)
            data['active_profile_id'] = next_active_id
            data['profiles'] = [self._mask_ai_profile(profile) for profile in profiles]
            return {
                'status': 'success',
                'message': 'AI 配置已保存并启用' if activate_profile else 'AI 配置已保存',
                'data': data
            }
        except Exception as e:
            logger.error(f"保存 AI 配置失败: {e}")
            return {
                'status': 'error',
                'message': f'保存 AI 配置失败: {str(e)}'
            }

    def delete_ai_profile(self, profile_id: str, user_consent_to_switch: bool = False) -> Dict[str, Any]:
        try:
            config = self._load_config()
            ai_state = self._normalize_ai_profiles(config.get('ai', {}))
            profile_id = str(profile_id or '')
            if len(ai_state['profiles']) <= 1:
                return {'status': 'error', 'message': '至少需要保留一个 AI 配置'}
            profiles = [profile for profile in ai_state['profiles'] if profile['id'] != profile_id]
            if len(profiles) == len(ai_state['profiles']):
                return {'status': 'error', 'message': '配置不存在'}
            active_id = ai_state['active_profile_id']
            if active_id == profile_id:
                if not user_consent_to_switch:
                    return {
                        'status': 'consent_required',
                        'message': '删除当前使用的 AI 配置会切换到其他档案，需要用户明确确认。',
                    }
                active_id = profiles[0]['id']
            next_state = {'active_profile_id': active_id, 'profiles': profiles}
            self._save_ai_state(config, next_state)
            active = next(profile for profile in profiles if profile['id'] == active_id)
            data = self._mask_ai_profile(active)
            data['active_profile_id'] = active_id
            data['profiles'] = [self._mask_ai_profile(profile) for profile in profiles]
            return {'status': 'success', 'message': '配置已删除', 'data': data}
        except Exception as e:
            logger.error(f"删除 AI 配置失败: {e}")
            return {'status': 'error', 'message': f'删除 AI 配置失败: {str(e)}'}

    def test_ai_connection(self, ai_settings: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            from backend.ai.config import AIConfig
            from backend.ai.client import OpenAICompatibleClient

            config = self._load_config()
            ai_state = self._normalize_ai_profiles(config.get('ai', {}))
            profile_id = str((ai_settings or {}).get('profile_id') or ai_state.get('active_profile_id') or 'default')
            old_profile = next((profile for profile in ai_state['profiles'] if profile['id'] == profile_id), self._active_ai_profile(config))
            merged = dict(old_profile)
            if ai_settings:
                for key, value in ai_settings.items():
                    if key == 'api_key' and (not value or '***' in str(value) or '...' in str(value)):
                        continue
                    merged[key] = value
            merged['id'] = profile_id
            merged['name'] = str((ai_settings or {}).get('profile_name') or old_profile.get('name') or merged.get('provider') or 'AI 配置')
            merged['enabled'] = True
            ai_config = AIConfig.from_dict(merged)
            ok, message = ai_config.validate()
            if not ok:
                return {'status': 'error', 'message': message}

            client = OpenAICompatibleClient(ai_config, self._build_proxy_url())
            response = client.chat([
                {'role': 'system', 'content': '你只需要回复 OK。'},
                {'role': 'user', 'content': '连接测试'}
            ])
            now = datetime.now().isoformat()
            profile = {
                **merged,
                **ai_config.to_dict(mask_key=False),
                'id': profile_id,
                'name': merged.get('name') or 'AI 配置',
                'verified': True,
                'verified_at': now,
                'last_test_status': '连接成功',
                'last_test_message': response.content[:200],
                'created_at': old_profile.get('created_at') or now,
                'updated_at': now,
            }
            profiles = [item for item in ai_state['profiles'] if item['id'] != profile_id]
            profiles.append(profile)
            ai_state = {
                'active_profile_id': ai_state['active_profile_id'],
                'profiles': profiles,
            }
            self._save_ai_state(config, ai_state)
            data = self._mask_ai_profile(profile)
            data['active_profile_id'] = ai_state['active_profile_id']
            data['profiles'] = [self._mask_ai_profile(item) for item in profiles]
            return {
                'status': 'success',
                'message': 'AI 接口连接成功',
                'data': {
                    'reply': response.content[:200],
                    **data,
                }
            }
        except Exception as e:
            logger.error(f"AI 连接测试失败: {e}")
            try:
                config = self._load_config()
                ai_state = self._normalize_ai_profiles(config.get('ai', {}))
                profile_id = str((ai_settings or {}).get('profile_id') or ai_state.get('active_profile_id') or 'default')
                for profile in ai_state['profiles']:
                    if profile['id'] == profile_id:
                        profile['verified'] = False
                        profile['last_test_status'] = '连接失败'
                        profile['last_test_message'] = str(e)
                        profile['updated_at'] = datetime.now().isoformat()
                        break
                self._save_ai_state(config, ai_state)
            except Exception:
                logger.debug("记录 AI 测试失败状态时出错", exc_info=True)
            return {
                'status': 'error',
                'message': f'AI 连接测试失败: {str(e)}'
            }

    def fetch_ai_models(self, ai_settings: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            import requests
            from backend.ai.config import AIConfig, get_provider_presets

            config = self._load_config()
            merged = dict(self._active_ai_profile(config))
            if ai_settings:
                for key, value in ai_settings.items():
                    if key == 'api_key' and (not value or '***' in str(value) or '...' in str(value)):
                        continue
                    merged[key] = value

            ai_config = AIConfig.from_dict(merged)
            if not ai_config.base_url.startswith(('http://', 'https://')):
                return {'status': 'error', 'message': 'Base URL 必须以 http:// 或 https:// 开头'}
            if not ai_config.api_key and 'localhost' not in ai_config.base_url and '127.0.0.1' not in ai_config.base_url:
                return {'status': 'error', 'message': '请先填写 API Key，或选择本地模型端点'}

            provider = next(
                (item for item in get_provider_presets() if item.get('id') == ai_config.provider),
                None
            )
            candidates = self._build_ai_models_url_candidates(
                ai_config.base_url,
                provider.get('models_url') if provider else None
            )
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'LensAnalysis/1.0'
            }
            if ai_config.api_key:
                headers['Authorization'] = f'Bearer {ai_config.api_key}'

            errors = []
            proxies = None
            proxy_url = self._build_proxy_url()
            if proxy_url:
                proxies = {'http': proxy_url, 'https': proxy_url}

            for url in candidates:
                try:
                    response = requests.get(
                        url,
                        headers=headers,
                        timeout=min(ai_config.timeout, 30),
                        proxies=proxies,
                    )
                    response.raise_for_status()
                    data = response.json()
                    models = self._parse_ai_models_response(data)
                    if models:
                        return {
                            'status': 'success',
                            'message': f'已获取 {len(models)} 个模型',
                            'data': {
                                'models': models,
                                'source_url': url
                            }
                        }
                    errors.append(f'{url}: 未返回模型列表')
                except Exception as e:
                    errors.append(f'{url}: {str(e)}')

            return {
                'status': 'error',
                'message': '模型列表获取失败：' + '；'.join(errors[:3])
            }
        except Exception as e:
            logger.error(f"获取 AI 模型列表失败: {e}")
            return {
                'status': 'error',
                'message': f'获取 AI 模型列表失败: {str(e)}'
            }

    def _build_ai_models_url_candidates(self, base_url: str, models_url: str = None) -> List[str]:
        candidates = []

        def add(url: str):
            if url and url not in candidates:
                candidates.append(url)

        if models_url:
            add(models_url.rstrip('/'))

        base = (base_url or '').rstrip('/')
        if not base:
            return candidates

        if base.endswith('/models'):
            add(base)
        else:
            add(f'{base}/models')

        suffixes = (
            '/chat/completions',
            '/responses',
            '/messages',
            '/api/codex/backend-api/codex',
        )
        stripped = base
        for suffix in suffixes:
            if stripped.endswith(suffix):
                stripped = stripped[:-len(suffix)].rstrip('/')
                add(f'{stripped}/models')

        if not base.endswith('/v1') and '/v1' not in base[-8:]:
            add(f'{base}/v1/models')

        return candidates

    def _parse_ai_models_response(self, data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, dict):
            raw_models = data.get('data') or data.get('models') or data.get('items') or []
        elif isinstance(data, list):
            raw_models = data
        else:
            raw_models = []

        models = []
        seen = set()
        for item in raw_models:
            if isinstance(item, str):
                model_id = item
                owned_by = None
            elif isinstance(item, dict):
                model_id = item.get('id') or item.get('model') or item.get('name')
                owned_by = item.get('owned_by') or item.get('ownedBy') or item.get('owner')
            else:
                continue

            if not model_id or model_id in seen:
                continue
            seen.add(model_id)
            models.append({
                'id': str(model_id),
                'name': str(model_id),
                'owned_by': str(owned_by) if owned_by else '',
                'badge': '在线',
                'description': '从供应商 /models 接口实时获取'
            })

        return sorted(models, key=lambda model: model['id'].lower())[:300]

    def ai_chat(self, message: str, history: List[Dict[str, str]] = None) -> Dict[str, Any]:
        try:
            assistant = self._create_ai_assistant(allow_plugin_execution=False)
            return assistant.chat(message, history or [])
        except Exception as e:
            logger.error(f"AI 对话入口失败: {e}")
            return {
                'status': 'error',
                'message': f'AI 对话失败: {str(e)}'
            }

    def submit_ai_chat(self, message: str, history: List[Dict[str, str]] = None) -> Dict[str, Any]:
        return self._submit_ai_task('chat', {
            'message': message,
            'history': history or []
        })

    def submit_ai_confirmation(self, action: Dict[str, Any], history: List[Dict[str, str]] = None) -> Dict[str, Any]:
        return self._submit_ai_task('confirm', {
            'action': action or {},
            'history': history or []
        })

    def submit_ai_analysis_plan(self) -> Dict[str, Any]:
        return self._submit_ai_task('analysis_plan', {})

    def get_ai_task_status(self, task_id: str) -> Dict[str, Any]:
        try:
            with self._ai_task_lock:
                task = self._ai_tasks.get(task_id)
                if not task:
                    return {'status': 'error', 'message': 'AI 任务不存在'}

                result = {
                    'status': 'success',
                    'data': {
                        'task_id': task_id,
                        'state': task.get('state'),
                        'created_at': task.get('created_at'),
                        'started_at': task.get('started_at'),
                'completed_at': task.get('completed_at'),
                'profile_id': task.get('profile_id'),
                'result': task.get('result'),
                'error': task.get('error'),
                'progress': task.get('progress') or {},
            }
                }
            return result
        except Exception as e:
            logger.error(f"获取 AI 任务状态失败: {e}")
            return {'status': 'error', 'message': f'获取 AI 任务状态失败: {str(e)}'}

    def cancel_ai_task(self, task_id: str) -> Dict[str, Any]:
        try:
            with self._ai_task_lock:
                task = self._ai_tasks.get(task_id)
                if not task:
                    return {'status': 'error', 'message': 'AI 任务不存在'}
                future = task.get('future')
                cancelled = bool(future and future.cancel())
                if task.get('state') in ('pending', 'running'):
                    task['state'] = 'cancelled'
                    task['completed_at'] = datetime.now().isoformat()
            self._terminate_active_analysis_wrappers(task_id)
            return {
                'status': 'success',
                'message': 'AI 任务已取消' if cancelled else 'AI 任务已标记取消'
            }
        except Exception as e:
            logger.error(f"取消 AI 任务失败: {e}")
            return {'status': 'error', 'message': f'取消 AI 任务失败: {str(e)}'}

    def _register_analysis_wrapper(self, wrapper: Any, task_id: str = None) -> None:
        task_id = task_id or (
            getattr(self._ai_task_context, 'task_id', None)
            or getattr(self._plugin_task_context, 'task_id', None)
        )
        with self._active_analysis_lock:
            self._active_analysis_wrappers[wrapper] = task_id

    def _unregister_analysis_wrapper(self, wrapper: Any) -> None:
        with self._active_analysis_lock:
            self._active_analysis_wrappers.pop(wrapper, None)

    def _terminate_active_analysis_wrappers(self, task_id: Optional[str] = None) -> None:
        with self._active_analysis_lock:
            wrappers = [
                wrapper for wrapper, owner_task_id in self._active_analysis_wrappers.items()
                if task_id is None or owner_task_id == task_id
            ]
        for wrapper in wrappers:
            cancel = getattr(wrapper, 'cancel_current_processes', None)
            if callable(cancel):
                try:
                    cancel()
                except Exception as e:
                    logger.warning(f"终止当前分析进程失败: {e}")

    def cancel_analysis_task(self, task_id: str) -> Dict[str, Any]:
        try:
            task_id = str(task_id or '').strip()
            if not task_id:
                return {'status': 'error', 'message': '缺少任务 ID'}
            self._terminate_active_analysis_wrappers(task_id)
            return {'status': 'success', 'message': '插件任务已请求取消'}
        except Exception as e:
            logger.error(f"取消插件任务失败: {e}")
            return {'status': 'error', 'message': f'取消插件任务失败: {str(e)}'}

    def _default_export_dir(self, category: str) -> str:
        path = self._user_data_dir / 'exports' / category
        path.mkdir(parents=True, exist_ok=True)
        return str(path)

    def _create_extraction_wrapper(self):
        from backend.volatility_wrapper import VolatilityWrapper
        return VolatilityWrapper(
            self.current_image['path'],
            self.current_image.get('os_type'),
            self._get_python_cmd(),
            symbols_dir=self._get_symbols_base_dir(self.current_image.get('os_type')),
            cache_path=self._cache_path,
        )

    @staticmethod
    def _extraction_response(result: Dict[str, Any]) -> Dict[str, Any]:
        nested_status = str((result or {}).get('status') or 'error').lower()
        if nested_status == 'success':
            return {'status': 'success', 'data': result}
        if nested_status in ('unsupported', 'cancelled'):
            outer_status = nested_status
        else:
            outer_status = 'error'
        return {
            'status': outer_status,
            'message': (result or {}).get('error') or '导出失败',
            'data': result or {},
        }

    @staticmethod
    def _unique_destination_path(path: Path) -> Path:
        if not path.exists():
            return path
        counter = 1
        while True:
            candidate = path.with_name(f'{path.stem}-{counter}{path.suffix}')
            if not candidate.exists():
                return candidate
            counter += 1

    def _run_extraction(
        self,
        operation,
        task_id: str = None,
        operation_key: tuple = None,
    ) -> Dict[str, Any]:
        active_extractions = getattr(self, '_active_extractions', None)
        active_lock = getattr(self, '_active_extractions_lock', None)
        if active_extractions is None or active_lock is None:
            active_extractions = set()
            active_lock = threading.Lock()
            self._active_extractions = active_extractions
            self._active_extractions_lock = active_lock

        if operation_key is not None:
            with active_lock:
                if operation_key in active_extractions:
                    return {
                        'status': 'error',
                        'message': '相同的提取任务正在执行，请勿重复提交',
                    }
                active_extractions.add(operation_key)

        wrapper = None
        try:
            wrapper = self._create_extraction_wrapper()
            self._register_analysis_wrapper(wrapper, task_id)
            return self._extraction_response(operation(wrapper))
        finally:
            if wrapper is not None:
                self._unregister_analysis_wrapper(wrapper)
            if operation_key is not None:
                with active_lock:
                    active_extractions.discard(operation_key)

    def _submit_ai_task(self, task_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(payload or {})
        if task_type in ('chat', 'confirm') and not payload.get('_profile_snapshot'):
            config = self._load_config()
            ai_state = self._normalize_ai_profiles(config.get('ai', {}))
            active_profile = next(
                profile for profile in ai_state['profiles']
                if profile['id'] == ai_state['active_profile_id']
            )
            payload['profile_id'] = active_profile['id']
            payload['_profile_snapshot'] = copy.deepcopy(active_profile)

        with self._ai_task_lock:
            self._ai_task_counter += 1
            task_id = f"ai_{self._ai_task_counter}_{uuid.uuid4().hex[:8]}"
            self._ai_tasks[task_id] = {
                'state': 'pending',
                'type': task_type,
                'created_at': datetime.now().isoformat(),
                'started_at': None,
                'completed_at': None,
                'result': None,
                'error': None,
                'profile_id': payload.get('profile_id'),
                'progress': {
                    'message': '排队中',
                    'current': 0,
                    'total': 4,
                    'updated_at': datetime.now().isoformat(),
                },
                'future': None,
            }

        future = self.executor.submit(self._run_ai_task, task_id, task_type, payload)
        with self._ai_task_lock:
            self._ai_tasks[task_id]['future'] = future

        self._cleanup_ai_tasks()
        return {
            'status': 'success',
            'data': {'task_id': task_id}
        }

    def _run_ai_task(self, task_id: str, task_type: str, payload: Dict[str, Any]):
        self._ai_task_context.task_id = task_id
        with self._ai_task_lock:
            task = self._ai_tasks.get(task_id)
            if not task or task.get('state') == 'cancelled':
                self._ai_task_context.task_id = None
                return
            task['state'] = 'running'
            task['started_at'] = datetime.now().isoformat()
            task['progress'] = {
                'message': '正在准备小析任务',
                'current': 1,
                'total': 4,
                'updated_at': datetime.now().isoformat(),
            }

        try:
            if task_type == 'chat':
                self._set_ai_task_progress(task_id, {
                    'message': '正在调用大模型',
                    'current': 2,
                    'total': 4,
                    'updated_at': datetime.now().isoformat(),
                })
                assistant = self._create_ai_assistant(
                    allow_plugin_execution=False,
                    profile_id=payload.get('profile_id'),
                    profile_snapshot=payload.get('_profile_snapshot'),
                )
                result = assistant.chat(payload.get('message') or '', payload.get('history') or [])
            elif task_type == 'confirm':
                self._set_ai_task_progress(task_id, {
                    'message': '正在执行确认动作',
                    'current': 2,
                    'total': 4,
                    'updated_at': datetime.now().isoformat(),
                })
                assistant = self._create_ai_assistant(
                    allow_plugin_execution=True,
                    profile_id=payload.get('profile_id'),
                    profile_snapshot=payload.get('_profile_snapshot'),
                )
                result = assistant.confirm_action(payload.get('action') or {}, payload.get('history') or [])
            elif task_type == 'analysis_plan':
                self._set_ai_task_progress(task_id, {
                    'message': '正在读取插件缓存',
                    'current': 2,
                    'total': 4,
                    'updated_at': datetime.now().isoformat(),
                })
                result = self.ai_generate_analysis_plan()
            else:
                result = {'status': 'error', 'message': f'未知 AI 任务类型: {task_type}'}

            with self._ai_task_lock:
                task = self._ai_tasks.get(task_id)
                if task and task.get('state') != 'cancelled':
                    task['progress'] = {
                        'message': '正在整理结果',
                        'current': 4,
                        'total': 4,
                        'updated_at': datetime.now().isoformat(),
                    }
                    task['state'] = 'completed'
                    task['completed_at'] = datetime.now().isoformat()
                    task['result'] = result
        except Exception as e:
            logger.exception("AI 后台任务失败")
            with self._ai_task_lock:
                task = self._ai_tasks.get(task_id)
                if task:
                    task['state'] = 'failed'
                    task['completed_at'] = datetime.now().isoformat()
                    task['error'] = str(e)
        finally:
            self._ai_task_context.task_id = None

    def _create_ai_assistant(
        self,
        allow_plugin_execution: bool = False,
        profile_id: Optional[str] = None,
        profile_snapshot: Optional[Dict[str, Any]] = None,
    ):
        from backend.ai.assistant import ForensicsAIAssistant
        from backend.ai.config import AIConfig

        selected_profile = copy.deepcopy(profile_snapshot) if profile_snapshot else None
        selected_id = str(
            profile_id
            or (selected_profile or {}).get('id')
            or ''
        )
        if selected_profile and selected_id != str(selected_profile.get('id') or ''):
            raise RuntimeError('AI 任务配置快照与档案标识不一致，已拒绝执行。')
        if selected_profile is None:
            config = self._load_config()
            ai_state = self._normalize_ai_profiles(config.get('ai', {}))
            selected_id = selected_id or ai_state['active_profile_id']
            selected_profile = next(
                (profile for profile in ai_state['profiles'] if profile['id'] == selected_id),
                None,
            )
        if selected_profile is None:
            raise RuntimeError(
                '任务提交时使用的 AI 配置档案已不存在，'
                '为保护用户权益，未自动切换其他供应商。请重新发起请求。'
            )
        ai_config = AIConfig.from_dict(selected_profile)
        logger.info(
            "AI 任务使用配置快照: profile_id=%s, provider=%s, model=%s",
            selected_id,
            ai_config.provider,
            ai_config.model,
        )
        return ForensicsAIAssistant(
            ai_config,
            self,
            self._build_proxy_url(),
            allow_plugin_execution=allow_plugin_execution,
        )

    def _cleanup_ai_tasks(self, keep: int = 30):
        with self._ai_task_lock:
            if len(self._ai_tasks) <= keep:
                return
            removable = [
                (task_id, task)
                for task_id, task in self._ai_tasks.items()
                if task.get('state') in ('completed', 'failed', 'cancelled')
            ]
            removable.sort(key=lambda item: item[1].get('completed_at') or item[1].get('created_at') or '')
            for task_id, _ in removable[:max(0, len(self._ai_tasks) - keep)]:
                self._ai_tasks.pop(task_id, None)

    def _sanitize_ai_chat_history(self, messages: List[Dict[str, Any]], limit: int = 80) -> List[Dict[str, str]]:
        cleaned = []
        for item in messages or []:
            if not isinstance(item, dict):
                continue
            role = str(item.get('role') or '').strip()
            if role not in ('user', 'assistant'):
                continue
            content = str(item.get('content') or '').strip()
            if not content:
                continue
            message = {
                'role': role,
                'content': content[:20000]
            }
            if item.get('id'):
                message['id'] = str(item.get('id'))[:120]
            if item.get('created_at'):
                message['created_at'] = str(item.get('created_at'))[:80]
            cleaned.append(message)
        return cleaned[-limit:]

    def _safe_project_hash(self, project_hash: str) -> str:
        project_hash = str(project_hash or '').strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]{8,128}', project_hash):
            return ''
        return project_hash

    def _get_ai_chat_history_file(self, project_hash: str = None) -> Optional[Path]:
        project_hash = self._safe_project_hash(project_hash)
        if project_hash:
            history_dir = self._cache_dir / project_hash
            return history_dir / 'ai_chat_history.json'
        if not self.current_image:
            return None
        return self._get_image_cache_dir() / 'ai_chat_history.json'

    def _load_ai_history_payload(self, project_hash: str = None) -> Tuple[Optional[Path], Dict[str, Any], List[Dict[str, str]], str]:
        history_file = self._get_ai_chat_history_file(project_hash)
        payload = {}
        messages = []
        updated_at = ''
        if history_file and history_file.exists():
            with open(history_file, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                payload = raw
                messages = raw.get('messages') or []
                updated_at = raw.get('updated_at') or ''
            elif isinstance(raw, list):
                messages = raw
        return history_file, payload, self._sanitize_ai_chat_history(messages), updated_at

    def list_ai_chat_histories(self, query: str = '') -> Dict[str, Any]:
        try:
            histories = []
            search_query = str(query or '').strip()[:200]
            search_folded = search_query.casefold()
            if not self._cache_dir.exists():
                return {'status': 'success', 'data': {'histories': [], 'query': search_query}}

            for project_dir in self._cache_dir.iterdir():
                if not project_dir.is_dir():
                    continue
                history_file = project_dir / 'ai_chat_history.json'
                if not history_file.exists():
                    continue

                try:
                    with open(history_file, 'r', encoding='utf-8') as f:
                        raw_history = json.load(f)
                    history_payload = raw_history if isinstance(raw_history, dict) else {}
                    messages = self._sanitize_ai_chat_history(
                        history_payload.get('messages') if isinstance(raw_history, dict) else raw_history
                    )
                    if not messages:
                        continue

                    info = {}
                    info_file = project_dir / 'project_info.json'
                    if info_file.exists():
                        try:
                            with open(info_file, 'r', encoding='utf-8') as f:
                                info = json.load(f)
                        except Exception:
                            info = {}

                    image_info = history_payload.get('image') or {}
                    image_name = info.get('name') or image_info.get('name') or '未知镜像'
                    image_path = info.get('path') or image_info.get('path') or ''
                    os_type = info.get('os_type') or image_info.get('os_type') or ''
                    matching_messages = []
                    if search_folded:
                        matching_messages = [
                            item for item in messages
                            if search_folded in str(item.get('content') or '').casefold()
                        ]
                        metadata = f'{image_name}\n{image_path}\n{os_type}'.casefold()
                        if search_folded not in metadata and not matching_messages:
                            continue

                    preview_candidates = matching_messages or messages
                    preview_source = next(
                        (item for item in reversed(preview_candidates) if item.get('content')),
                        preview_candidates[-1]
                    )
                    preview = str(preview_source.get('content') or '').replace('\n', ' ').strip()
                    histories.append({
                        'hash': project_dir.name,
                        'name': image_name,
                        'path': image_path,
                        'os_type': os_type,
                        'message_count': len(messages),
                        'match_count': len(matching_messages),
                        'updated_at': history_payload.get('updated_at') or datetime.fromtimestamp(history_file.stat().st_mtime).isoformat(),
                        'preview': preview[:160],
                        'is_current': bool(self.current_image and self.current_image.get('hash') == project_dir.name),
                    })
                except Exception as e:
                    logger.warning(f"读取 AI 历史摘要失败: {project_dir.name}, {e}")

            histories.sort(key=lambda item: item.get('updated_at') or '', reverse=True)
            return {
                'status': 'success',
                'data': {'histories': histories, 'query': search_query}
            }
        except Exception as e:
            logger.error(f"列出 AI 对话历史失败: {e}")
            return {
                'status': 'error',
                'message': f'列出 AI 对话历史失败: {str(e)}'
            }

    def get_ai_chat_history(self, project_hash: str = None) -> Dict[str, Any]:
        try:
            project_hash = self._safe_project_hash(project_hash)
            if not project_hash and not self.current_image:
                return {
                    'status': 'success',
                    'data': {
                        'image': None,
                        'messages': []
                    }
                }

            history_file, payload, messages, updated_at = self._load_ai_history_payload(project_hash)
            image = payload.get('image') or {}
            if project_hash:
                info_file = self._cache_dir / project_hash / 'project_info.json'
                if info_file.exists():
                    try:
                        with open(info_file, 'r', encoding='utf-8') as f:
                            image = {**image, **json.load(f)}
                    except Exception:
                        pass
            elif self.current_image:
                image = {
                    **image,
                    'name': self.current_image.get('name'),
                    'hash': self.current_image.get('hash'),
                    'path': self.current_image.get('path')
                }

            return {
                'status': 'success',
                'data': {
                    'image': {
                        'name': image.get('name'),
                        'hash': image.get('hash') or project_hash,
                        'path': image.get('path'),
                        'os_type': image.get('os_type'),
                    },
                    'messages': messages,
                    'updated_at': updated_at
                }
            }
        except Exception as e:
            logger.error(f"读取 AI 对话历史失败: {e}")
            return {
                'status': 'error',
                'message': f'读取 AI 对话历史失败: {str(e)}'
            }

    def save_ai_chat_history(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'success',
                    'message': '未加载镜像，已跳过保存',
                    'data': {'saved': False, 'messages': 0}
                }

            history_file = self._get_ai_chat_history_file()
            if not history_file:
                return {'status': 'error', 'message': '历史文件路径不可用'}

            cleaned = self._sanitize_ai_chat_history(messages)
            payload = {
                'version': 1,
                'image': {
                    'name': self.current_image.get('name'),
                    'hash': self.current_image.get('hash'),
                    'cache_fingerprint': self.current_image.get('cache_fingerprint'),
                    'path': self.current_image.get('path'),
                    'os_type': self.current_image.get('os_type')
                },
                'updated_at': datetime.now().isoformat(),
                'messages': cleaned
            }
            history_file.parent.mkdir(parents=True, exist_ok=True)
            temp_file = history_file.with_suffix('.json.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            temp_file.replace(history_file)

            return {
                'status': 'success',
                'message': 'AI 对话历史已保存',
                'data': {
                    'saved': True,
                    'messages': len(cleaned)
                }
            }
        except Exception as e:
            logger.error(f"保存 AI 对话历史失败: {e}")
            return {
                'status': 'error',
                'message': f'保存 AI 对话历史失败: {str(e)}'
            }

    def clear_ai_chat_history(self, project_hash: str = None) -> Dict[str, Any]:
        try:
            history_file = self._get_ai_chat_history_file(project_hash)
            if history_file and history_file.exists():
                history_file.unlink()
            return {
                'status': 'success',
                'message': 'AI 对话历史已清空'
            }
        except Exception as e:
            logger.error(f"清空 AI 对话历史失败: {e}")
            return {
                'status': 'error',
                'message': f'清空 AI 对话历史失败: {str(e)}'
            }

    def get_ai_context(self) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'success',
                    'data': {
                        'image': None,
                        'cached_plugins': [],
                        'cached_plugin_count': 0
                    }
                }

            cached = self.get_cached_plugins(False)
            plugins = []
            if cached.get('status') == 'success':
                for plugin in cached.get('data', {}).get('plugins', []):
                    plugins.append({
                        'pluginId': plugin.get('pluginId'),
                        'displayName': plugin.get('displayName'),
                        'count': plugin.get('count'),
                        'timestamp': plugin.get('timestamp'),
                        'isFlagSearch': bool(plugin.get('isFlagSearch'))
                    })

            return {
                'status': 'success',
                'data': {
                    'image': {
                        'name': self.current_image.get('name'),
                        'hash': self.current_image.get('hash'),
                        'size': self.current_image.get('size'),
                        'os_type': self.current_image.get('os_type'),
                        'loaded_at': self.current_image.get('loaded_at')
                    },
                    'cached_plugins': plugins[:50],
                    'cached_plugin_count': len(plugins)
                }
            }
        except Exception as e:
            logger.error(f"获取 AI 上下文失败: {e}")
            return {
                'status': 'error',
                'message': f'获取 AI 上下文失败: {str(e)}'
            }

    def _ai_get_recommended_plugin_groups(self, os_type: str) -> List[Dict[str, Any]]:
        normalized = (os_type or '').strip().lower()
        if normalized in ('mac', 'macos', 'darwin'):
            return [
                {
                    'phase': '进程与命令线',
                    'goal': '确认活跃进程、进程关系和可疑启动参数。',
                    'plugins': ['mac.pslist.PsList', 'mac_pstree', 'mac_psaux'],
                },
                {
                    'phase': '网络活动',
                    'goal': '检查网络连接、接口和套接字过滤器。',
                    'plugins': ['mac.netstat.Netstat', 'mac.ifconfig.Ifconfig', 'mac.socket_filters.Socket_filters'],
                },
                {
                    'phase': '文件与持久化',
                    'goal': '查看打开文件、文件列表、挂载信息和 Bash 历史。',
                    'plugins': ['mac.lsof.Lsof', 'mac.list_files.List_Files', 'mac.mount.Mount', 'mac.bash.Bash'],
                },
                {
                    'phase': '恶意代码与内核迹象',
                    'goal': '检查注入、内核扩展和系统调用异常。',
                    'plugins': ['mac.malfind.Malfind', 'mac.lsmod.Lsmod', 'mac.check_syscall.Check_syscall'],
                },
            ]
        if normalized == 'linux':
            return [
                {
                    'phase': '进程基线',
                    'goal': '建立进程列表、进程树和命令行基线。',
                    'plugins': ['linux_pslist', 'linux_pstree', 'linux_psscan', 'linux_psaux'],
                },
                {
                    'phase': '网络活动',
                    'goal': '确认连接、监听端口、网络接口和地址。',
                    'plugins': ['linux_sockstat', 'linux_ip_addr', 'linux_ip_link'],
                },
                {
                    'phase': '文件与用户活动',
                    'goal': '查看打开文件、挂载信息、Bash 历史和页缓存文件。',
                    'plugins': ['linux_lsof', 'linux_mountinfo', 'linux_bash', 'linux_pagecache_files'],
                },
                {
                    'phase': '恶意代码与内核迹象',
                    'goal': '检查注入、隐藏模块、系统调用和凭据异常。',
                    'plugins': ['linux_malware_malfind', 'linux_malware_hidden_modules', 'linux_malware_check_syscall', 'linux_malware_check_creds'],
                },
            ]
        return [
            {
                'phase': '进程基线',
                'goal': '建立进程列表、进程树、隐藏/终止进程和命令行基线。',
                'plugins': ['pslist', 'pstree', 'psscan', 'cmdline'],
            },
            {
                'phase': '网络与服务',
                'goal': '检查网络连接、服务、自启动痕迹和异常监听。',
                'plugins': ['netscan', 'svcscan'],
            },
            {
                'phase': '文件与注册表',
                'goal': '定位文件对象、注册表 Hive 和用户活动痕迹。',
                'plugins': ['filescan', 'hivelist', 'userassist'],
            },
            {
                'phase': '凭证与恶意代码',
                'goal': '提取凭证相关证据并检查注入或异常内存区域。',
                'plugins': ['hashdump', 'lsadump', 'malfind', 'dlllist', 'handles'],
            },
            {
                'phase': '命令历史与 CTF 线索',
                'goal': '查看控制台历史并搜索 Flag 字符串。',
                'plugins': ['cmdscan', 'search_flag'],
            },
        ]

    def _ai_cache_file_for_plugin(self, plugin_id: str) -> str:
        if plugin_id == 'search_flag' or plugin_id.startswith('flag_search_'):
            return 'flag_search_cache.json'
        return f'{self._get_cache_key(plugin_id, None)}.json'

    def ai_generate_analysis_plan(self) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {'status': 'error', 'message': '请先加载内存镜像'}

            cached = self.get_cached_plugins(False)
            cached_plugins = {}
            if cached.get('status') == 'success':
                for plugin in (cached.get('data') or {}).get('plugins', []):
                    cached_plugins[plugin.get('pluginId')] = plugin

            groups = []
            for group in self._ai_get_recommended_plugin_groups(self.current_image.get('os_type')):
                items = []
                for plugin_id in group.get('plugins', []):
                    cache_info = cached_plugins.get(plugin_id)
                    if plugin_id == 'search_flag':
                        cache_info = cached_plugins.get('flag_search_default') or cache_info
                    items.append({
                        'plugin_id': plugin_id,
                        'display_name': self._get_plugin_display_name(plugin_id),
                        'cached': bool(cache_info),
                        'count': cache_info.get('count', 0) if cache_info else 0,
                        'timestamp': cache_info.get('timestamp', '') if cache_info else '',
                        'source_file': self._ai_cache_file_for_plugin(plugin_id),
                        'reason': group.get('goal', ''),
                    })
                groups.append({
                    'phase': group.get('phase'),
                    'goal': group.get('goal'),
                    'plugins': items,
                    'cached_count': sum(1 for item in items if item.get('cached')),
                })

            plan = {
                'version': 1,
                'created_at': datetime.now().isoformat(),
                'image': {
                    'name': self.current_image.get('name'),
                    'hash': self.current_image.get('hash'),
                    'cache_fingerprint': self.current_image.get('cache_fingerprint'),
                    'path': self.current_image.get('path'),
                    'os_type': self.current_image.get('os_type'),
                    'size': self.current_image.get('size'),
                },
                'groups': groups,
                'cached_plugin_count': len(cached_plugins),
            }
            self._save_to_cache_file('ai_analysis_plan', plan)
            return {'status': 'success', 'data': plan}
        except Exception as e:
            logger.error(f"生成 AI 分析计划失败: {e}")
            return {'status': 'error', 'message': f'生成 AI 分析计划失败: {str(e)}'}

    def _set_ai_task_progress(self, task_id: Optional[str], progress: Dict[str, Any]) -> None:
        if not task_id:
            return
        with self._ai_task_lock:
            task = self._ai_tasks.get(task_id)
            if task and task.get('state') != 'cancelled':
                task['progress'] = progress

    def _is_ai_task_cancelled(self, task_id: Optional[str]) -> bool:
        if not task_id:
            return False
        with self._ai_task_lock:
            task = self._ai_tasks.get(task_id)
            return bool(task and task.get('state') == 'cancelled')

    def _ai_row_text(self, row: Any, max_length: int = 900) -> str:
        try:
            if isinstance(row, dict):
                text = json.dumps(row, ensure_ascii=False, default=str)
            else:
                text = str(row)
        except Exception:
            text = repr(row)
        text = re.sub(r'\s+', ' ', text).strip()
        return text[:max_length]

    @staticmethod
    def _row_contains_keyword(row: Any, keyword: str) -> bool:
        needle = str(keyword or '').lower()
        if not needle:
            return True

        def contains(value: Any) -> bool:
            if isinstance(value, dict):
                return any(
                    contains(key) or contains(child)
                    for key, child in value.items()
                )
            if isinstance(value, (list, tuple, set)):
                return any(contains(child) for child in value)
            return needle in str(value).lower()

        return contains(row)

    def _ai_score_evidence_row(self, plugin_id: str, row: Any) -> int:
        text = self._ai_row_text(row, 3000).lower()
        score = 0
        plugin_weights = {
            'malfind': 6,
            'hashdump': 5,
            'lsadump': 5,
            'netscan': 3,
            'svcscan': 3,
            'cmdline': 3,
            'cmdscan': 3,
            'consoles': 3,
            'psscan': 2,
            'filescan': 2,
        }
        for key, weight in plugin_weights.items():
            if key in plugin_id.lower():
                score += weight
        keywords = (
            'powershell', 'cmd.exe', 'wscript', 'cscript', 'rundll32', 'regsvr32',
            'mimikatz', 'meterpreter', 'shell', 'reverse', 'listen', 'established',
            'inject', 'vad', 'execute', 'rwx', 'hidden', 'delete', 'temp', 'appdata',
            'password', 'passwd', 'token', 'secret', 'private', 'flag{', 'ctf{',
            'lsass', 'svchost', 'autorun', 'startup', 'suspicious', 'malware',
        )
        score += sum(2 for word in keywords if word in text)
        if isinstance(row, dict):
            score += min(4, len([key for key, value in row.items() if value not in (None, '', [])]) // 5)
        return score

    def _ai_iter_cache_entries(self) -> List[Dict[str, Any]]:
        if not self.current_image:
            return []
        cache_dir = self._get_image_cache_dir()
        entries = []
        internal_cache_files = self._internal_cache_files()
        for cache_file in cache_dir.glob('*.json'):
            if cache_file.name in internal_cache_files:
                continue
            if cache_file.name == 'flag_search_cache.json':
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        flag_cache = json.load(f)
                    for search_key, search_data in (flag_cache or {}).items():
                        pattern = search_data.get('pattern')
                        plugin_id = 'flag_search_default' if pattern is None else f'flag_search_custom:{pattern}'
                        entries.append({
                            'plugin_id': plugin_id,
                            'display_name': self._get_plugin_display_name(plugin_id),
                            'source_file': cache_file.name,
                            'timestamp': search_data.get('timestamp', ''),
                            'results': search_data.get('results') or [],
                            'is_flag_search': True,
                        })
                except Exception as e:
                    logger.warning(f"读取 AI Flag 证据缓存失败 {cache_file}: {e}")
                continue
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                plugin_id = cache_file.stem
                entries.append({
                    'plugin_id': plugin_id,
                    'display_name': self._get_plugin_display_name(plugin_id),
                    'source_file': cache_file.name,
                    'timestamp': (data.get('metadata') or {}).get('timestamp', data.get('timestamp', '')) if isinstance(data, dict) else '',
                    'results': data.get('results') if isinstance(data, dict) else [],
                    'is_flag_search': False,
                })
            except Exception as e:
                logger.warning(f"读取 AI 线索缓存失败 {cache_file}: {e}")
        return entries

    def ai_build_evidence_index(self, limit: int = 12) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {'status': 'error', 'message': '请先加载内存镜像'}

            limit = max(3, min(int(limit or 12), 50))
            entries = self._ai_iter_cache_entries()
            evidence = []
            plugin_summaries = []
            for entry in entries:
                rows = entry.get('results') or []
                plugin_summaries.append({
                    'plugin_id': entry.get('plugin_id'),
                    'display_name': entry.get('display_name'),
                    'source_file': entry.get('source_file'),
                    'count': len(rows),
                    'timestamp': entry.get('timestamp', ''),
                })
                ranked = []
                for index, row in enumerate(rows[:5000]):
                    score = self._ai_score_evidence_row(entry.get('plugin_id') or '', row)
                    if score > 0:
                        ranked.append((score, index, row))
                ranked.sort(key=lambda item: item[0], reverse=True)
                if not ranked and rows:
                    ranked = [(0, index, row) for index, row in enumerate(rows[:2])]
                for score, index, row in ranked[:max(1, min(5, limit))]:
                    evidence.append({
                        'id': f"{entry.get('plugin_id')}#{index + 1}",
                        'plugin_id': entry.get('plugin_id'),
                        'display_name': entry.get('display_name'),
                        'source_file': entry.get('source_file'),
                        'row_index': index + 1,
                        'score': score,
                        'summary': self._ai_row_text(row),
                        'locator': {
                            'source_file': entry.get('source_file'),
                            'row_index': index + 1,
                        },
                    })

            evidence.sort(key=lambda item: item.get('score', 0), reverse=True)
            payload = {
                'version': 1,
                'created_at': datetime.now().isoformat(),
                'image': {
                    'name': self.current_image.get('name'),
                    'hash': self.current_image.get('hash'),
                    'path': self.current_image.get('path'),
                    'os_type': self.current_image.get('os_type'),
                },
                'plugins': plugin_summaries,
                'evidence': evidence[:limit],
                'evidence_count': min(len(evidence), limit),
                'total_candidates': len(evidence),
            }
            self._save_to_cache_file('ai_evidence_index', payload)
            return {'status': 'success', 'data': payload}
        except Exception as e:
            logger.error(f"生成 AI 线索索引失败: {e}")
            return {'status': 'error', 'message': f'生成 AI 线索索引失败: {str(e)}'}

    def _ai_parse_time_value(self, value: Any) -> Optional[datetime]:
        if value in (None, '', [], {}):
            return None
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, (int, float)):
            parsed = self._ai_parse_numeric_time(float(value))
        else:
            text = str(value).strip()
            if not text or text.lower() in ('n/a', 'none', 'null', '-'):
                return None
            parsed = None
            numeric_text = text.replace(',', '')
            if re.fullmatch(r'-?\d+(?:\.\d+)?', numeric_text):
                parsed = self._ai_parse_numeric_time(float(numeric_text))
            if parsed is None:
                normalized = text.replace('Z', '+00:00')
                for candidate in (normalized, normalized.replace('/', '-')):
                    try:
                        parsed = datetime.fromisoformat(candidate)
                        break
                    except ValueError:
                        pass
            if parsed is None:
                formats = (
                    '%Y-%m-%d %H:%M:%S.%f',
                    '%Y-%m-%d %H:%M:%S',
                    '%Y/%m/%d %H:%M:%S',
                    '%Y-%m-%dT%H:%M:%S.%f',
                    '%Y-%m-%dT%H:%M:%S',
                    '%a %b %d %H:%M:%S %Y',
                    '%b %d %H:%M:%S %Y',
                )
                for fmt in formats:
                    try:
                        parsed = datetime.strptime(text, fmt)
                        break
                    except ValueError:
                        continue
        if parsed is None:
            return None
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        if parsed.year < 1970 or parsed.year > 2100:
            return None
        return parsed

    def _ai_parse_numeric_time(self, value: float) -> Optional[datetime]:
        if value <= 0:
            return None

        candidates = []
        if value > 10**16:
            candidates.append(lambda: datetime(1601, 1, 1) + timedelta(microseconds=value / 10))
        if 10**18 <= value < 10**20:
            candidates.append(lambda: datetime.fromtimestamp(value / 1_000_000_000))
        if 10**15 <= value < 10**17:
            candidates.append(lambda: datetime.fromtimestamp(value / 1_000_000))
        if 10**12 <= value < 10**14:
            candidates.append(lambda: datetime.fromtimestamp(value / 1000))
        if 10**9 <= value < 10**11:
            candidates.append(lambda: datetime.fromtimestamp(value))

        for parse in candidates:
            try:
                parsed = parse()
            except (OverflowError, OSError, ValueError):
                continue
            if 1970 <= parsed.year <= 2100:
                return parsed
        return None

    def _ai_extract_row_times(self, row: Any) -> List[Tuple[str, datetime, Any]]:
        if not isinstance(row, dict):
            return []
        time_keywords = (
            'time', 'date', 'timestamp', 'created', 'create', 'modified', 'modify',
            'updated', 'accessed', 'access', 'written', 'write', 'changed', 'change',
            'start', 'started', 'end', 'exit', 'birth', 'install', 'login', 'last',
            'mtime', 'atime', 'ctime', 'm_time', 'a_time', 'c_time',
        )
        matches = []
        for key, value in row.items():
            lowered = str(key).lower()
            if not any(keyword in lowered for keyword in time_keywords):
                continue
            parsed = self._ai_parse_time_value(value)
            if parsed is not None:
                matches.append((str(key), parsed, value))
        return matches

    def ai_build_timeline(self, limit: int = 80) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {'status': 'error', 'message': '请先加载内存镜像'}

            limit = max(10, min(int(limit or 80), 300))
            entries = self._ai_iter_cache_entries()
            events = []
            plugin_summaries = []
            for entry in entries:
                rows = entry.get('results') or []
                plugin_summaries.append({
                    'plugin_id': entry.get('plugin_id'),
                    'display_name': entry.get('display_name'),
                    'source_file': entry.get('source_file'),
                    'count': len(rows),
                    'timestamp': entry.get('timestamp', ''),
                })
                for index, row in enumerate(rows[:8000]):
                    for field, parsed, raw_value in self._ai_extract_row_times(row):
                        events.append({
                            'time': parsed.isoformat(sep=' '),
                            'field': field,
                            'raw_time': raw_value,
                            'plugin_id': entry.get('plugin_id'),
                            'display_name': entry.get('display_name'),
                            'source_file': entry.get('source_file'),
                            'row_index': index + 1,
                            'summary': self._ai_row_text(row, 700),
                            'locator': {
                                'source_file': entry.get('source_file'),
                                'row_index': index + 1,
                            },
                        })

            events.sort(key=lambda item: item.get('time') or '')
            selected_events = events[-limit:] if len(events) > limit else events
            payload = {
                'version': 1,
                'created_at': datetime.now().isoformat(),
                'image': {
                    'name': self.current_image.get('name'),
                    'hash': self.current_image.get('hash'),
                    'path': self.current_image.get('path'),
                    'os_type': self.current_image.get('os_type'),
                },
                'plugins': plugin_summaries,
                'events': selected_events,
                'event_count': len(selected_events),
                'total_events': len(events),
            }
            self._save_to_cache_file('ai_timeline', payload)
            return {'status': 'success', 'data': payload}
        except Exception as e:
            logger.error(f"生成 AI 时间线失败: {e}")
            return {'status': 'error', 'message': f'生成 AI 时间线失败: {str(e)}'}

    def _ai_markdown_table_escape(self, value: Any) -> str:
        text = '' if value is None else str(value)
        return text.replace('|', '\\|').replace('\n', ' ')[:500]

    def _ai_generate_report_markdown(self, plan: Dict[str, Any], evidence_index: Dict[str, Any], timeline: Optional[Dict[str, Any]] = None) -> str:
        image = plan.get('image') or {}
        lines = [
            '# 小析内存取证分析报告',
            '',
            '## 镜像信息',
            '',
            f"- 镜像名称：{image.get('name') or '-'}",
            f"- 系统类型：{image.get('os_type') or '-'}",
            f"- 缓存指纹：{image.get('cache_fingerprint') or image.get('hash') or '-'}",
            f"- 镜像路径：{image.get('path') or '-'}",
            f"- 生成时间：{datetime.now().isoformat()}",
            '',
            '## 分析计划',
            '',
        ]
        for group in plan.get('groups') or []:
            lines.extend([
                f"### {group.get('phase') or '未命名阶段'}",
                '',
                group.get('goal') or '',
                '',
                '| 插件 | 状态 | 记录数 | 证据文件 |',
                '|---|---:|---:|---|',
            ])
            for plugin in group.get('plugins') or []:
                status = '已缓存' if plugin.get('cached') else '待执行'
                lines.append(
                    f"| {self._ai_markdown_table_escape(plugin.get('display_name') or plugin.get('plugin_id'))} "
                    f"| {status} | {plugin.get('count', 0)} | {self._ai_markdown_table_escape(plugin.get('source_file'))} |"
                )
            lines.append('')

        lines.extend([
            '## 线索索引',
            '',
            '以下线索来自本地插件 JSON 缓存，保留原始字段，不做脱敏。',
            '',
        ])
        evidence = evidence_index.get('evidence') or []
        if evidence:
            lines.extend(['| 来源 | 记录 | 评分 | 摘要 |', '|---|---:|---:|---|'])
            for item in evidence:
                source = f"{item.get('display_name') or item.get('plugin_id')} / {item.get('source_file')}"
                lines.append(
                    f"| {self._ai_markdown_table_escape(source)} "
                    f"| {item.get('row_index')} | {item.get('score')} | {self._ai_markdown_table_escape(item.get('summary'))} |"
                )
            lines.append('')
        else:
            lines.extend(['当前没有可整理的插件缓存。', ''])

        lines.extend([
            '## 案件时间线',
            '',
            '以下时间线从插件缓存中的时间字段自动提取，按时间升序展示。',
            '',
        ])
        timeline_events = (timeline or {}).get('events') or []
        if timeline_events:
            lines.extend(['| 时间 | 来源 | 记录 | 字段 | 摘要 |', '|---|---|---:|---|---|'])
            for item in timeline_events[:80]:
                source = f"{item.get('display_name') or item.get('plugin_id')} / {item.get('source_file')}"
                lines.append(
                    f"| {self._ai_markdown_table_escape(item.get('time'))} "
                    f"| {self._ai_markdown_table_escape(source)} "
                    f"| {item.get('row_index')} | {self._ai_markdown_table_escape(item.get('field'))} "
                    f"| {self._ai_markdown_table_escape(item.get('summary'))} |"
                )
            lines.append('')
        else:
            lines.extend(['当前没有从插件缓存中提取到可用时间字段。', ''])

        lines.extend([
            '## 缓存概览',
            '',
            '| 插件 | 缓存文件 | 记录数 | 时间 |',
            '|---|---|---:|---|',
        ])
        for plugin in evidence_index.get('plugins') or []:
            lines.append(
                f"| {self._ai_markdown_table_escape(plugin.get('display_name') or plugin.get('plugin_id'))} "
                f"| {self._ai_markdown_table_escape(plugin.get('source_file'))} "
                f"| {plugin.get('count', 0)} | {self._ai_markdown_table_escape(plugin.get('timestamp'))} |"
            )
        lines.extend([
            '',
            '## 使用说明',
            '',
            '- “已缓存”表示该插件已有本地 JSON 结果，可被小析直接读取。',
            '- “待执行”表示该项仍需用户确认后运行对应插件。',
            '- 报告中的证据来源格式为：插件 / 缓存文件 / 记录序号。',
        ])
        return '\n'.join(lines)

    def ai_generate_report(self, format_type: str = 'markdown') -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {'status': 'error', 'message': '请先加载内存镜像'}

            plan_result = self.ai_generate_analysis_plan()
            if plan_result.get('status') != 'success':
                return plan_result
            evidence_result = self.ai_build_evidence_index(30)
            if evidence_result.get('status') != 'success':
                return evidence_result
            timeline_result = self.ai_build_timeline(80)
            timeline_data = timeline_result.get('data') if timeline_result.get('status') == 'success' else {'events': []}

            format_type = (format_type or 'markdown').lower()
            if format_type not in ('markdown', 'md', 'html'):
                return {'status': 'error', 'message': f'不支持的小析报告格式: {format_type}'}

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            reports_dir = self._user_data_dir / 'reports'
            reports_dir.mkdir(parents=True, exist_ok=True)
            markdown = self._ai_generate_report_markdown(plan_result['data'], evidence_result['data'], timeline_data)
            if format_type == 'html':
                import html
                body = html.escape(markdown)
                content = (
                    '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
                    '<title>小析内存取证分析报告</title>'
                    '<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;'
                    'max-width:980px;margin:40px auto;padding:0 24px;line-height:1.7;color:#0f172a;}'
                    'pre{white-space:pre-wrap;background:#f8fafc;border:1px solid #e2e8f0;'
                    'border-radius:8px;padding:18px;}</style></head><body><pre>'
                    f'{body}</pre></body></html>'
                )
                report_path = reports_dir / f'ai_forensics_report_{timestamp}.html'
            else:
                content = markdown
                report_path = reports_dir / f'ai_forensics_report_{timestamp}.md'

            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(content)

            return {
                'status': 'success',
                'message': '小析报告已生成',
                'data': {
                    'path': str(report_path),
                    'format': 'html' if format_type == 'html' else 'markdown',
                    'evidence_count': evidence_result['data'].get('evidence_count', 0),
                    'timeline_count': timeline_data.get('event_count', 0),
                    'plugin_count': len(evidence_result['data'].get('plugins') or []),
                    'plan': plan_result['data'],
                    'evidence_index': evidence_result['data'],
                    'timeline': timeline_data,
                }
            }
        except Exception as e:
            logger.error(f"生成小析报告失败: {e}")
            return {'status': 'error', 'message': f'生成小析报告失败: {str(e)}'}

    def get_proxy_config(self) -> Dict[str, Any]:
        return {
            'status': 'success',
            'data': self._proxy_config
        }

    def test_proxy(self) -> Dict[str, Any]:
        import urllib.request
        import urllib.error
        import time
        import socket as socket_module

        try:
            proxy_url = self._build_proxy_url()
            if not proxy_url:
                return {
                    'status': 'error',
                    'message': '未配置代理'
                }

            test_urls = [
                ('GitHub API', 'https://api.github.com'),
                ('Google', 'https://www.google.com'),
                ('百度', 'https://www.baidu.com')
            ]

            results = []
            proxy_type = self._proxy_config.get('type', 'http')

            original_socket = socket_module.socket

            for name, url in test_urls:
                try:
                    start_time = time.time()

                    if proxy_url.startswith('socks'):
                        try:
                            import socks

                            sock_type = socks.PROXY_TYPE_SOCKS5 if 'socks5' in proxy_url else socks.PROXY_TYPE_SOCKS4
                            proxy_host = self._proxy_config.get('host')
                            proxy_port = self._proxy_config.get('port')

                            socks.set_default_proxy(sock_type, proxy_host, proxy_port)
                            socket_module.socket = socks.socksocket

                            req = urllib.request.Request(url, method='HEAD')
                            req.add_header('User-Agent', 'Mozilla/5.0')
                            urllib.request.urlopen(req, timeout=10)

                            elapsed = time.time() - start_time
                            results.append({'name': name, 'status': 'success', 'time': f'{elapsed:.2f}s'})

                        except ImportError:
                            results.append({'name': name, 'status': 'error', 'message': '需要安装 PySocks'})
                        finally:
                            socket_module.socket = original_socket
                    else:
                        import ssl
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE

                        https_handler = urllib.request.HTTPSHandler(context=ctx)
                        proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                        opener = urllib.request.build_opener(proxy_handler, https_handler)

                        req = urllib.request.Request(url, method='HEAD')
                        req.add_header('User-Agent', 'Mozilla/5.0')
                        opener.open(req, timeout=10)

                        elapsed = time.time() - start_time
                        results.append({'name': name, 'status': 'success', 'time': f'{elapsed:.2f}s'})

                except urllib.error.HTTPError as e:
                    results.append({'name': name, 'status': 'http_error', 'code': e.code})
                except urllib.error.URLError as e:
                    results.append({'name': name, 'status': 'error', 'message': str(e.reason)})
                except Exception as e:
                    results.append({'name': name, 'status': 'error', 'message': str(e)})

            success_count = sum(1 for r in results if r['status'] == 'success')

            return {
                'status': 'success',
                'message': f'代理测试完成：{success_count}/{len(results)} 个连接成功',
                'data': {
                    'proxy_type': proxy_type,
                    'proxy_address': f"{self._proxy_config.get('host')}:{self._proxy_config.get('port')}",
                    'results': results
                }
            }

        except Exception as e:
            logger.error(f"测试代理失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'测试代理失败: {str(e)}'
            }

    def set_proxy_config(self, proxy_type: str, proxy_host: str, proxy_port: int,
                         proxy_username: str = None, proxy_password: str = None) -> Dict[str, Any]:
        try:
            if not proxy_host:
                return {
                    'status': 'error',
                    'message': '代理地址不能为空'
                }

            if not proxy_port or proxy_port <= 0 or proxy_port > 65535:
                return {
                    'status': 'error',
                    'message': '代理端口无效（范围: 1-65535）'
                }

            if proxy_type not in ['http', 'https', 'socks5']:
                return {
                    'status': 'error',
                    'message': '不支持的代理类型，请选择 http、https 或 socks5'
                }

            proxy_config = {
                'type': proxy_type,
                'host': proxy_host,
                'port': proxy_port
            }

            if proxy_username and proxy_password:
                proxy_config['username'] = proxy_username
                proxy_config['password'] = proxy_password

            self._proxy_config = proxy_config

            config = self._load_config()
            config['proxy'] = proxy_config
            self._save_config(config)

            auth_part = f"{proxy_username}@"
            proxy_url = f"{proxy_type}://{proxy_host}:{proxy_port}"

            logger.info(f"代理配置已更新: {proxy_type}://{proxy_host}:{proxy_port}")

            return {
                'status': 'success',
                'message': f'代理配置已保存：{proxy_type}://{proxy_host}:{proxy_port}',
                'data': {
                    'type': proxy_type,
                    'host': proxy_host,
                    'port': proxy_port,
                    'has_auth': bool(proxy_username and proxy_password)
                }
            }

        except Exception as e:
            logger.error(f"设置代理配置失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'设置代理配置失败: {str(e)}'
            }

    def delete_proxy_config(self) -> Dict[str, Any]:
        try:
            self._proxy_config = {}

            config = self._load_config()
            if 'proxy' in config:
                del config['proxy']
                self._save_config(config)

            logger.info("代理配置已删除")

            return {
                'status': 'success',
                'message': '代理配置已删除'
            }

        except Exception as e:
            logger.error(f"删除代理配置失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'删除代理配置失败: {str(e)}'
            }

    def _build_proxy_url(self) -> Optional[str]:
        if not self._proxy_config:
            return None

        proxy_type = self._proxy_config.get('type', 'http')
        host = self._proxy_config.get('host')
        port = self._proxy_config.get('port')
        username = self._proxy_config.get('username')
        password = self._proxy_config.get('password')

        if not host or not port:
            return None

        if username and password:
            auth = f"{username}:{password}@"
        else:
            auth = ""

        if proxy_type == 'socks5':
            return f"socks5://{auth}{host}:{port}"
        else:
            return f"{proxy_type}://{auth}{host}:{port}"


    def _show_loading(self, text: str = '加载中...', hint: str = None):
        import webview
        try:
            import json
            text_js = json.dumps(text)
            hint_js = json.dumps(hint) if hint else 'null'

            js_code = f"""
                if (document.getElementById('loadingText')) document.getElementById('loadingText').textContent = {text_js};
                if (document.getElementById('loadingHint')) {{
                    const hint = {hint_js};
                    document.getElementById('loadingHint').textContent = hint ? hint : '请稍候，正在处理...';
                }}
                if (document.getElementById('loadingOverlay')) document.getElementById('loadingOverlay').classList.remove('hidden');
            """
            webview.windows[0].evaluate_js(js_code)
        except Exception as e:
            logger.warning(f"无法显示加载动画: {e}")

    def _hide_loading(self):
        import webview
        try:
            js_code = """
                if (document.getElementById('loadingOverlay')) document.getElementById('loadingOverlay').classList.add('hidden');
            """
            webview.windows[0].evaluate_js(js_code)
        except Exception as e:
            logger.warning(f"无法隐藏加载动画: {e}")


    def load_memory_image_dialog(self, os_type: str = None) -> Dict[str, Any]:
        try:
            import webview
            from webview import FileDialog
            logger.info(f"打开文件选择对话框 (用户指定OS类型: {os_type or '自动检测'})")

            file_types = (
                '所有文件 (*.*)',
                '内存镜像文件 (*.raw;*.vmem;*.dmp;*.mem;*.lime)'
            )

            result = webview.windows[0].create_file_dialog(
                FileDialog.OPEN,
                file_types=file_types
            )

            if result and len(result) > 0:
                file_path = result[0]
                self._show_loading(
                    '正在加载内存镜像...',
                    '正在读取文件并计算哈希值，大文件可能需要较长时间...'
                )
                try:
                    result = self.load_memory_image(file_path, user_specified_os=os_type)
                    return result
                finally:
                    self._hide_loading()
            else:
                return {
                    'status': 'cancelled',
                    'message': '用户取消了文件选择'
                }

        except Exception as e:
            self._hide_loading()
            logger.error(f"文件选择对话框失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def select_directory_dialog(self) -> Dict[str, Any]:
        try:
            import webview
            logger.info("打开目录选择对话框")

            result = webview.windows[0].create_file_dialog(
                webview.FileDialog.FOLDER
            )

            if result and len(result) > 0:
                selected_dir = result[0]
                logger.info(f"用户选择目录: {selected_dir}")
                return {
                    'status': 'success',
                    'data': {
                        'path': selected_dir
                    }
                }
            else:
                return {
                    'status': 'cancelled',
                    'message': '用户取消了目录选择'
                }

        except Exception as e:
            logger.error(f"目录选择对话框失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def select_file_dialog(self) -> Dict[str, Any]:
        try:
            import webview
            logger.info("打开文件选择对话框")

            result = webview.windows[0].create_file_dialog(
                webview.FileDialog.OPEN
            )

            if result and len(result) > 0:
                selected_file = result[0]
                logger.info(f"用户选择文件: {selected_file}")
                return {
                    'status': 'success',
                    'data': {
                        'path': selected_file
                    }
                }
            else:
                return {
                    'status': 'cancelled',
                    'message': '用户取消了文件选择'
                }

        except Exception as e:
            logger.error(f"文件选择对话框失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def create_directory(self, path: str) -> Dict[str, Any]:
        try:
            os.makedirs(path, exist_ok=True)
            logger.info(f"目录已创建: {path}")
            return {
                'status': 'success',
                'message': f'目录已创建: {path}'
            }
        except Exception as e:
            logger.error(f"创建目录失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }


    def get_system_info(self) -> Dict[str, Any]:
        import platform
        import volatility3
        from volatility3.framework import constants

        try:
            vol_version = volatility3.__version__
        except AttributeError:
            import pkg_resources
            try:
                vol_version = pkg_resources.get_distribution('volatility3').version
            except:
                vol_version = 'unknown'

        return {
            'status': 'success',
            'data': {
                'system': platform.system(),
                'python_version': platform.python_version(),
                'volatility_version': vol_version,
                'os_release': platform.release(),
                'machine': platform.machine(),
                'cache_dir': str(self._cache_dir)
            }
        }

    def quit_app(self) -> Dict[str, Any]:
        import sys
        import os

        logger.info('用户拒绝使用条款，退出应用')

        def delayed_exit():
            logger.info('正在退出应用...')
            if hasattr(self, '_window') and self._window:
                try:
                    self._window.destroy()
                except:
                    pass
            os._exit(0)

        import threading
        threading.Timer(0.5, delayed_exit).start()

        return {'status': 'success', 'message': '应用即将退出'}

    def restart_app(self) -> Dict[str, Any]:
        import subprocess
        import sys
        import os
        import platform

        logger.info('正在重启应用...')

        def delayed_restart():
            try:
                system = platform.system()
                is_frozen = getattr(sys, 'frozen', False)
                is_nuitka = '__compiled__' in globals() or hasattr(sys, '_nuitka_binary')
                is_macos_app = '.app/Contents/MacOS' in (sys.executable or '')
                is_packaged = is_frozen or is_nuitka or is_macos_app

                if is_macos_app:
                    app_path = sys.executable
                    if 'Contents/MacOS' in app_path:
                        app_path = app_path.split('Contents/MacOS')[0].rstrip('/')
                    subprocess.Popen(['open', '-n', app_path])
                elif is_packaged:
                    subprocess.Popen([sys.argv[0]])
                else:
                    subprocess.Popen([sys.executable] + sys.argv)

                if hasattr(self, '_window') and self._window:
                    try:
                        self._window.destroy()
                    except:
                        pass
                os._exit(0)
            except Exception as e:
                logger.error(f'重启失败: {e}')
                os._exit(1)

        import threading
        threading.Timer(0.5, delayed_restart).start()

        return {'status': 'success', 'message': '应用即将重启'}

    def set_window(self, window):
        self._window = window

    def resize_window(self, width: int, height: int) -> Dict[str, Any]:
        if hasattr(self, '_window') and self._window:
            try:
                self._window.resize(width, height)
                logger.info(f'窗口大小已调整为: {width}x{height}')
                return {'status': 'success', 'message': f'窗口已调整为 {width}x{height}'}
            except Exception as e:
                logger.error(f'调整窗口大小失败: {e}')
                return {'status': 'error', 'message': f'调整窗口大小失败: {str(e)}'}
        return {'status': 'error', 'message': '窗口引用不存在'}

    def set_window_title(self, title: str) -> Dict[str, Any]:
        if hasattr(self, '_window') and self._window:
            try:
                self._window.set_title(str(title))
                return {'status': 'success'}
            except Exception as e:
                logger.error(f'设置窗口标题失败: {e}')
                return {'status': 'error', 'message': str(e)}
        return {'status': 'error', 'message': '窗口引用不存在'}

    def open_source_project(self) -> Dict[str, Any]:
        try:
            import webbrowser
            opened = webbrowser.open(self.PROJECT_URL, new=2)
            if opened is False:
                return {'status': 'error', 'message': '系统浏览器未能打开项目地址'}
            return {'status': 'success', 'url': self.PROJECT_URL}
        except Exception as e:
            logger.error(f'打开开源项目失败: {e}')
            return {'status': 'error', 'message': str(e)}

    def set_license_manager(self, license_manager):
        self._license_manager = license_manager

    def set_app(self, app):
        self._app = app

    def activate_license(self, license_key: str) -> Dict[str, Any]:
        return {
            'status': 'success',
            'message': '当前版本已开源，无需激活',
            'require_restart': False,
        }

        if hasattr(self, '_license_manager') and self._license_manager:
            success, message = self._license_manager.activate_license(license_key)
            if success:
                return {
                    'status': 'success',
                    'message': message,
                    'require_restart': True
                }
            return {
                'status': 'error',
                'message': message
            }
        return {
            'status': 'error',
            'message': '许可证管理器未初始化'
        }

    def get_license_status(self) -> Dict[str, Any]:
        return {
            'status': 'success',
            'data': {'valid': True, 'open_source': True},
        }

        logger.info("=========== get_license_status 被调用 ===========")
        if hasattr(self, '_app') and self._app:
            status = self._app.get_license_status()
            logger.info(f"许可证状态: {status}")
            return {
                'status': 'success',
                'data': status
            }
        logger.warning("app 未初始化")
        return {
            'status': 'success',
            'data': {'valid': False}
        }

    def test_api(self) -> Dict[str, Any]:
        logger.info("=========== test_api 被调用 ===========")
        return {
            'status': 'success',
            'message': 'API工作正常',
            'timestamp': int(time.time())
        }

    def get_machine_code(self) -> Dict[str, Any]:
        return {
            'status': 'error',
            'message': '当前版本已开源，不再使用机器码',
        }

        logger.info("get_machine_code 被调用")
        if hasattr(self, '_license_manager') and self._license_manager:
            machine_code = self._license_manager.get_machine_code()
            logger.info(f"机器码获取成功: {machine_code}")
            return {
                'status': 'success',
                'data': {
                    'machine_code': machine_code
                }
            }
        logger.error("license_manager 未初始化")
        return {
            'status': 'error',
            'message': '无法获取机器码'
        }

    def _get_config_dir(self) -> Path:
        import platform
        home = Path.home()
        system = platform.system()

        if system == 'Windows':
            config_dir = home / 'AppData' / 'Roaming' / 'LensAnalysis'
        elif system == 'Darwin':
            config_dir = home / 'Library' / 'Application Support' / 'LensAnalysis'
        else:
            config_dir = home / '.config' / 'LensAnalysis'

        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir

    def save_terms_accepted(self) -> Dict[str, Any]:
        try:
            terms_file = self._get_config_dir() / 'terms_accepted.json'
            terms_file.write_text(json.dumps({
                'accepted': True,
                'date': datetime.now().isoformat()
            }), encoding='utf-8')
            logger.info(f"已保存用户同意条款状态到 {terms_file}")
            return {'status': 'success'}
        except Exception as e:
            logger.error(f"保存条款同意状态失败: {e}")
            return {'status': 'error', 'message': str(e)}

    def check_terms_accepted(self) -> Dict[str, Any]:
        try:
            terms_file = self._get_config_dir() / 'terms_accepted.json'
            if terms_file.exists():
                data = json.loads(terms_file.read_text(encoding='utf-8'))
                logger.info(f"用户已同意条款，日期: {data.get('date')}")
                return {'status': 'success', 'accepted': True, 'date': data.get('date')}
            else:
                logger.info("用户未同意条款")
                return {'status': 'success', 'accepted': False}
        except Exception as e:
            logger.error(f"检查条款同意状态失败: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_available_plugins(self) -> Dict[str, Any]:
        plugins = {
            'Windows': {
                'process': [
                    {'id': 'pslist', 'name': '进程列表', 'description': '列出所有正在运行的进程'},
                    {'id': 'pstree', 'name': '进程树', 'description': '以树形结构显示进程关系'},
                    {'id': 'psscan', 'name': '进程扫描', 'description': '扫描隐藏/终止的进程'},
                    {'id': 'dlllist', 'name': 'DLL列表', 'description': '列出进程加载的DLL'},
                    {'id': 'handles', 'name': '句柄列表', 'description': '列出进程打开的句柄'}
                ],
                'network': [
                    {'id': 'netscan', 'name': '网络连接', 'description': '扫描网络连接'},
                    {'id': 'netstat', 'name': '网络状态', 'description': '显示网络统计信息'}
                ],
                'registry': [
                    {'id': 'hivelist', 'name': '注册表配置单元', 'description': '列出注册表配置单元'},
                    {'id': 'printkey', 'name': '打印注册表键', 'description': '显示注册表键值'}
                ],
                'filesystem': [
                    {'id': 'filescan', 'name': '文件扫描', 'description': '扫描文件对象'}
                ],
                'malware': [
                    {'id': 'malfind', 'name': '恶意代码查找', 'description': '查找注入的代码'},
                    {'id': 'ldrmodules', 'name': '加载模块', 'description': '检测未加载的DLL'}
                ],
                'cmdline': [
                    {'id': 'cmdline', 'name': '命令行参数', 'description': '显示进程命令行'},
                    {'id': 'consoles', 'name': '控制台历史', 'description': '提取控制台命令历史'}
                ],
                'crypto': [
                    {'id': 'hashdump', 'name': '哈希转储', 'description': '提取Windows密码哈希（含明文密码）'},
                    {'id': 'lsadump', 'name': 'LSA密钥', 'description': '提取LSA密钥'},
                    {'id': 'cachedump', 'name': '域缓存', 'description': '提取域缓存凭据(mimikatz)'}
                ],
                'system': [
                    {'id': 'getsids', 'name': '获取SIDs', 'description': '获取进程安全标识符'},
                    {'id': 'envars', 'name': '环境变量', 'description': '显示进程环境变量'},
                    {'id': 'svcscan', 'name': '服务扫描', 'description': '扫描Windows服务'},
                    {'id': 'ssdt', 'name': 'SSDT', 'description': '显示系统服务描述符表'},
                    {'id': 'timers', 'name': '定时器', 'description': '显示内核定时器'},
                    {'id': 'callbacks', 'name': '回调', 'description': '显示内核回调'},
                    {'id': 'verinfo', 'name': '版本信息', 'description': '显示版本信息'},
                    {'id': 'deskscan', 'name': '桌面扫描', 'description': '扫描桌面线程'},
                ]
            },

            'Linux': {
                'process': [
                    {'id': 'linux_pslist', 'name': '进程列表', 'description': '列出所有正在运行的进程'},
                    {'id': 'linux_pstree', 'name': '进程树', 'description': '以树形结构显示进程关系'},
                    {'id': 'linux_psscan', 'name': '进程扫描', 'description': '扫描隐藏/终止的进程'},
                    {'id': 'linux_psaux', 'name': '进程参数', 'description': '显示进程命令行参数'},
                ],
                'network': [
                    {'id': 'linux_netstat', 'name': '网络状态', 'description': '显示网络统计信息'},
                    {'id': 'linux_sockstat', 'name': '进程网络连接', 'description': '显示网络连接信息'},
                    {'id': 'linux_ip_addr', 'name': '网络地址', 'description': '显示网络接口地址信息'},
                    {'id': 'linux_ip_link', 'name': '网络接口', 'description': '显示网络接口信息'},
                ],
                'filesystem': [
                    {'id': 'linux_elfs', 'name': 'ELF文件列表', 'description': '列出所有进程的所有内存映射 ELF 文件'},
                    {'id': 'linux_lsof', 'name': '打开文件列表', 'description': '列出每个进程的打开文件'},
                    {'id': 'linux_mountinfo', 'name': '挂载信息', 'description': '显示文件系统挂载信息'},
                    {'id': 'linux_pagecache_files', 'name': '页缓存文件', 'description': '列出页缓存中的文件'},
                    {'id': 'linux_pagecache_recoverfs', 'name': '恢复文件系统', 'description': '将缓存的文件系统恢复为压缩的 tar 包'},
                ],
                'malware': [
                    {'id': 'linux_malfind', 'name': '恶意代码查找', 'description': '查找注入的代码'},
                ],
                'cmdline': [
                    {'id': 'linux_bash', 'name': 'Bash历史', 'description': '提取Bash命令历史'},
                    {'id': 'linux_envars', 'name': '环境变量', 'description': '显示进程环境变量'},
                ],
                'kernel': [
                    {'id': 'linux_lsmod', 'name': '内核模块', 'description': '列出已加载的内核模块'},
                    {'id': 'linux_check_modules', 'name': '模块检查', 'description': '检查内核模块完整性'},
                    {'id': 'linux_iomem', 'name': 'IO内存', 'description': '显示IO内存映射'},
                    {'id': 'linux_kmsg', 'name': '内核消息', 'description': '提取内核日志消息'},
                ],
                'system': [
                    {'id': 'linux_capabilities', 'name': '权限检查', 'description': '检查进程权限'},
                    {'id': 'linux_check_afinfo', 'name': 'AFINFO检查', 'description': '检查地址族信息'},
                    {'id': 'linux_check_creds', 'name': '凭据检查', 'description': '检查凭据结构'},
                    {'id': 'linux_check_idt', 'name': 'IDT检查', 'description': '检查中断描述符表'},
                    {'id': 'linux_check_syscall', 'name': '系统调用检查', 'description': '检查系统调用表'},
                    {'id': 'linux_tty_check', 'name': 'TTY检查', 'description': '检查TTY设备'},
                    {'id': 'linux_keyboard_notifiers', 'name': '键盘监听器', 'description': '检查键盘通知器'},
                    {'id': 'linux_maps', 'name': '内存映射', 'description': '显示进程内存映射'},
                ]
            },

            'macOS': {
                'process': [
                    {'id': 'mac.pslist.PsList', 'name': '进程列表', 'description': '列出所有正在运行的进程'},
                    {'id': 'mac_pstree', 'name': '进程树', 'description': '以树形结构显示进程关系'},
                    {'id': 'mac_psaux', 'name': '进程参数', 'description': '显示进程命令行参数'},
                ],
                'network': [
                    {'id': 'mac.netstat.Netstat', 'name': '网络状态', 'description': '显示网络统计信息'},
                    {'id': 'mac.ifconfig.Ifconfig', 'name': '网络接口', 'description': '显示网络接口配置'},
                    {'id': 'mac.socket_filters.Socket_filters', 'name': '套接字过滤器', 'description': '显示套接字过滤器'},
                ],
                'filesystem': [
                    {'id': 'mac.lsof.Lsof', 'name': '打开文件', 'description': '列出进程打开的文件'},
                    {'id': 'mac.list_files.List_Files', 'name': '文件列表', 'description': '列出文件系统文件'},
                    {'id': 'mac.mount.Mount', 'name': '挂载信息', 'description': '显示文件系统挂载信息'},
                ],
                'malware': [
                    {'id': 'mac.malfind.Malfind', 'name': '恶意代码查找', 'description': '查找注入的代码'},
                ],
                'cmdline': [
                    {'id': 'mac.bash.Bash', 'name': 'Bash历史', 'description': '提取Bash命令历史'},
                ],
                'kernel': [
                    {'id': 'mac.lsmod.Lsmod', 'name': '内核扩展', 'description': '列出已加载的内核扩展(Kext)'},
                ],
                'system': [
                    {'id': 'mac.check_syscall.Check_syscall', 'name': '系统调用检查', 'description': '检查系统调用表'},
                    {'id': 'mac.check_sysctl.Check_sysctl', 'name': 'Sysctl检查', 'description': '检查sysctl表'},
                    {'id': 'mac.check_trap_table.Check_trap_table', 'name': '陷阱表检查', 'description': '检查陷阱表'},
                    {'id': 'mac.dmesg.Dmesg', 'name': '内核消息', 'description': '提取内核日志消息'},
                    {'id': 'mac.kevents.Kevents', 'name': '内核事件', 'description': '显示内核事件'},
                    {'id': 'mac.timers.Timers', 'name': '定时器', 'description': '显示内核定时器'},
                    {'id': 'mac.kauth_listeners.Kauth_listeners', 'name': 'Kauth监听器', 'description': '显示Kauth授权监听器'},
                    {'id': 'mac.kauth_scopes.Kauth_scopes', 'name': 'Kauth范围', 'description': '显示Kauth授权范围'},
                    {'id': 'mac.trustedbsd.Trustedbsd', 'name': 'TrustedBSD', 'description': '显示TrustedBSD信息'},
                    {'id': 'mac.proc_maps.Maps', 'name': '内存映射', 'description': '显示进程内存映射'},
                    {'id': 'mac.vfsevents.VFSevents', 'name': '文件系统事件', 'description': '显示文件系统事件'},
                ],
                'flags': [
                    {'id': 'search_flag', 'name': 'Flag搜索', 'description': '搜索CTF Flag字符串'},
                ]
            }
        }

        flat_plugins = {}
        for os_type, os_plugins in plugins.items():
            os_key = os_type.lower()
            flat_plugins[os_key] = {}
            for category, plugin_list in os_plugins.items():
                for plugin in plugin_list:
                    flat_plugins[os_key][plugin['id']] = {
                        'display_name': plugin['name'],
                        'description': plugin['description']
                    }

        return {
            'status': 'success',
            'data': flat_plugins
        }


    def _find_matching_windows_symbol(
        self, pdb_name: str, guid: str, age: Any, allow_deep_scan: bool = True
    ) -> Optional[Path]:
        pdb_name = str(pdb_name or '').strip()
        guid = str(guid or '').strip()
        age_text = str(age)
        if not pdb_name or not guid:
            return None

        canonical_dir = self._get_os_symbols_dir('windows') / pdb_name
        expected_stem = f'{guid}-{age_text}'
        search_dirs = self._get_os_symbol_search_dirs('windows')
        def materialize(source: Path) -> Optional[Path]:
            suffix = '.json.xz' if source.name.lower().endswith('.json.xz') else '.json'
            target = canonical_dir / f'{expected_stem}{suffix}'
            if source.resolve() != target.resolve(strict=False):
                try:
                    target = self._materialize_symbol_compatibility_path(source, target)
                    logger.info(f'已兼容平铺 Windows 符号表: {source} -> {target}')
                except OSError as exc:
                    logger.warning(f'匹配到平铺 Windows 符号表，但无法建立标准兼容入口: {source}, {exc}')
                    return None
            return target if target.exists() else source

        for root in search_dirs:
            if not root.exists():
                continue
            preferred = [
                root / pdb_name / f'{expected_stem}.json.xz',
                root / pdb_name / f'{expected_stem}.json',
                root / f'{expected_stem}.json.xz',
                root / f'{expected_stem}.json',
            ]
            for candidate in preferred:
                if self._is_volatility_isf_file(candidate):
                    return materialize(candidate)

        if not allow_deep_scan:
            return None

        candidates = []
        seen = set()
        for root in search_dirs:
            if not root.exists():
                continue
            for pattern in (f'**/{expected_stem}.json.xz', f'**/{expected_stem}.json'):
                for candidate in root.glob(pattern):
                    resolved = str(candidate.resolve())
                    if self._is_volatility_isf_file(candidate) and resolved not in seen:
                        seen.add(resolved)
                        candidates.append(candidate)
            if candidates:
                return materialize(candidates[0])

        metadata_info = {'pdb_info': {'name': pdb_name, 'guid': guid, 'age': age}}
        if not candidates:
            for root in search_dirs:
                if not root.exists():
                    continue
                for candidate in list(root.rglob('*.json.xz')) + list(root.rglob('*.json')):
                    resolved = str(candidate.resolve())
                    if resolved in seen or not self._is_volatility_isf_file(candidate):
                        continue
                    seen.add(resolved)
                    try:
                        with open(candidate, 'rb') as stream:
                            prefix = self._read_symbol_candidate_prefix(stream, candidate.name)
                        if self._symbol_candidate_matches_current(
                            str(candidate.relative_to(root)), prefix, 'windows', metadata_info
                        ):
                            candidates.append(candidate)
                            break
                    except (OSError, ValueError):
                        continue
                if candidates:
                    break

        if not candidates:
            return None
        return materialize(candidates[0])

    def get_symbol_status(self) -> Dict[str, Any]:
        try:
            symbol_status = {}
            for os_name in ('windows', 'linux', 'mac'):
                os_dir = self._get_os_symbols_dir(os_name)
                os_base = self._get_symbols_base_dir(os_name)
                if not os_base.exists():
                    os_base.mkdir(parents=True, exist_ok=True)
                count = len(self._get_valid_symbol_files(os_name))
                symbol_status[os_name] = {
                    'installed': count > 0,
                    'count': count,
                    'path': str(self._get_os_symbols_display_dir(os_name)),
                    'volatility_path': str(os_dir),
                }
                logger.info(
                    f"符号表状态 {os_name}: installed={count > 0}, count={count}, "
                    f"path={self._get_os_symbols_display_dir(os_name)}, volatility_path={os_dir}"
                )

            if self.current_image:
                os_type = self.current_image.get('os_type', '').lower()

                if os_type == 'macos':
                    os_type = 'mac'

                if os_type == 'windows':
                    try:
                        from volatility3.framework.symbols.windows import pdbutil
                        from volatility3.framework import contexts
                        from volatility3.framework.layers import physical

                        context = contexts.Context()
                        file_path = self.current_image['path']

                        import urllib.request
                        import urllib.parse
                        file_url = 'file://' + urllib.request.pathname2url(file_path)

                        context.config['FileLayer.location'] = file_url

                        layer = physical.FileLayer(context, 'FileLayer', name="FileLayer")
                        context.add_layer(layer)

                        layer_name = layer.name
                        page_size = 0x1000  

                        pdb_names = [b'ntkrnlmp.pdb', b'ntoskrnl.pdb', b'krnl.pdb', b'ntkrpamp.pdb']

                        found = False
                        for result in pdbutil.PDBUtility.pdbname_scan(
                            context, layer_name, page_size, pdb_names
                        ):
                            guid = result.get('GUID', '')
                            age = result.get('age', 0)
                            pdb_name = result.get('pdb_name', '')

                            if guid and pdb_name:
                                symbol_path = self._find_matching_windows_symbol(pdb_name, guid, age)
                                is_match = bool(symbol_path and symbol_path.exists())

                                symbol_status['windows']['pdb_info'] = {
                                    'name': pdb_name,
                                    'guid': guid,
                                    'age': age,
                                    'symbol_exists': is_match,
                                    'symbol_path': str(symbol_path) if is_match else None
                                }

                                logger.info(f"Windows镜像PDB信息: {pdb_name} - {guid}-{age}, 符号表匹配: {is_match}")
                                found = True
                                break

                        if not found:
                            logger.info("Volatility3 扫描未找到 PDB 信息，尝试从 pdb_info.json 读取")
                            self._load_pdb_info_from_file(symbol_status)
                    except ImportError as e:
                        logger.info(f"打包后无法使用 volatility3 模块获取 PDB 信息（功能正常）: {e}")
                        found = self._load_pdb_info_from_file(symbol_status)
                        if not found:
                            self._scan_pdb_and_save(symbol_status)
                    except Exception as e:
                        logger.warning(f"获取Windows PDB信息失败: {e}")

                elif os_type in ['linux', 'mac']:
                    banner = self.current_image.get('banner', '')
                    logger.info(f"{os_type} 镜像 banner 内容: {banner[:200] if banner else '(空)'}")
                    if banner:
                        kernel_version = self._extract_kernel_version(banner, os_type)
                        logger.info(f"{os_type} 从 banner 提取的内核版本: '{kernel_version}'")
                        if kernel_version:
                            symbol_status[os_type]['kernel_version'] = kernel_version
                            symbol_exists = self._check_symbol_exists(os_type, kernel_version)
                            symbol_status[os_type]['kernel_symbol_exists'] = symbol_exists
                            logger.info(f"{os_type}镜像内核版本: {kernel_version}, 符号表匹配: {symbol_exists}")
                        else:
                            logger.warning(f"{os_type} 无法从 banner 提取内核版本")
                    else:
                        logger.warning(f"{os_type} 镜像没有 banner 信息")

            logger.info(f"返回符号表状态: current_os={self.current_image.get('os_type') if self.current_image else None}, os_types keys={list(symbol_status.keys())}")
            for os_name, os_info in symbol_status.items():
                logger.info(f"  {os_name}: installed={os_info.get('installed')}, kernel_symbol_exists={os_info.get('kernel_symbol_exists')}, kernel_version={os_info.get('kernel_version')}")

            return {
                'status': 'success',
                'data': {
                    'symbols_dir': str(self._symbols_dir),
                    'current_os': self.current_image.get('os_type') if self.current_image else None,
                    'os_types': symbol_status
                }
            }

        except Exception as e:
            logger.error(f"获取符号表状态失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'获取符号表状态失败: {str(e)}'
            }

    def upload_symbol_file(self) -> Dict[str, Any]:
        try:
            import webview
            from webview import FileDialog
            logger.info("打开符号表文件选择对话框")

            file_types = (
                'Symbol archives (*.zip)',
                'All files (*.*)'
            )

            result = webview.windows[0].create_file_dialog(
                FileDialog.OPEN,
                file_types=file_types
            )

            if result and len(result) > 0:
                file_path = result[0]

                if not file_path.endswith('.zip'):
                    return {
                        'status': 'error',
                        'message': '请选择 .zip 格式的符号表文件'
                    }

                self._show_loading(
                    '正在安装符号表...',
                    '正在解压并安装符号表文件，请稍候...'
                )

                try:
                    install_result = self.install_symbols(file_path)
                    return install_result
                finally:
                    self._hide_loading()
            else:
                return {
                    'status': 'cancelled',
                    'message': '用户取消了文件选择'
                }

        except Exception as e:
            self._hide_loading()
            logger.error(f"符号表上传失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'符号表上传失败: {str(e)}'
            }

    def _read_symbol_candidate_prefix(self, stream, filename: str, raw_limit: int = 4 * 1024 * 1024) -> str:
        import lzma

        raw = stream.read(raw_limit)
        if str(filename).lower().endswith('.xz'):
            try:
                raw = lzma.LZMADecompressor().decompress(raw, max_length=2 * 1024 * 1024)
            except lzma.LZMAError:
                return ''
        return raw.decode('utf-8', errors='ignore')

    def _symbol_candidate_matches_current(self, filename: str, prefix: str,
                                          os_type: str, symbol_info: Dict[str, Any]) -> bool:
        candidate_text = f'{filename}\n{prefix}'
        candidate_lower = candidate_text.lower()
        if os_type == 'windows':
            pdb_info = symbol_info.get('pdb_info') or {}
            pdb_name = str(pdb_info.get('name') or '').lower()
            guid = re.sub(r'[^0-9a-f]', '', str(pdb_info.get('guid') or '').lower())
            age = str(pdb_info.get('age') if pdb_info.get('age') is not None else '')
            compact = re.sub(r'[^0-9a-z]', '', candidate_lower)
            if not pdb_name or not guid:
                return False
            pdb_matches = pdb_name in candidate_lower or pdb_name.replace('.pdb', '') in candidate_lower
            guid_matches = guid in compact
            age_matches = not age or bool(re.search(rf'["\']?age["\']?\s*[:=_-]\s*{re.escape(age)}\b', candidate_lower))
            path_matches = f'{guid}-{age}'.lower() in candidate_lower if age else guid in candidate_lower
            return pdb_matches and guid_matches and (age_matches or path_matches)

        kernel_version = str(symbol_info.get('kernel_version') or '').strip()
        if not kernel_version:
            return False
        versions = {kernel_version, kernel_version.replace('_', '-').replace(' ', '-')}
        if os_type == 'mac':
            darwin_to_macos = {
                '16.': '10.12', '17.': '10.13', '18.': '10.14',
                '19.': '10.15', '20.': '11.0', '21.': '12.0',
                '22.': '13.0', '23.': '14.0', '24.': '15.0',
            }
            for darwin_prefix, macos_version in darwin_to_macos.items():
                if kernel_version.startswith(darwin_prefix):
                    versions.add(macos_version)
                    break
        return any(version.lower() in candidate_lower for version in versions if version)

    def select_and_install_symbol_for_current_image(self, file_path: str = None) -> Dict[str, Any]:
        import lzma
        import shutil
        import zipfile

        if not self.current_image:
            return {'status': 'error', 'message': '请先加载内存镜像'}

        os_type = str(self.current_image.get('os_type') or '').lower()
        os_type = 'mac' if os_type in ('macos', 'darwin') else os_type
        if os_type not in ('windows', 'linux', 'mac'):
            return {'status': 'error', 'message': '无法识别当前镜像系统类型'}

        status_result = self.get_symbol_status()
        if status_result.get('status') != 'success':
            return status_result
        symbol_info = ((status_result.get('data') or {}).get('os_types') or {}).get(os_type) or {}
        if os_type == 'windows':
            pdb_info = symbol_info.get('pdb_info') or {}
            expected = f"{pdb_info.get('name') or '未知 PDB'} / {pdb_info.get('guid') or '未知 GUID'}-{pdb_info.get('age', '?')}"
            if not pdb_info.get('name') or not pdb_info.get('guid'):
                return {'status': 'error', 'message': '尚未识别当前 Windows 镜像的 PDB 信息，无法安全校验本地符号表'}
        else:
            expected = symbol_info.get('kernel_version') or ''
            if not expected:
                return {'status': 'error', 'message': '尚未识别当前镜像内核版本，无法安全校验本地符号表'}

        if file_path:
            selected = (str(Path(str(file_path)).expanduser()),)
        else:
            try:
                import webview
                from webview import FileDialog
                selected = webview.windows[0].create_file_dialog(
                    FileDialog.OPEN,
                    file_types=('All files (*.*)',),
                )
            except Exception as exc:
                return {'status': 'error', 'message': f'打开符号表选择器失败: {exc}'}
        if not selected:
            return {'status': 'cancelled', 'message': '用户取消了符号表选择'}

        source_path = Path(selected[0])
        if not source_path.is_file():
            return {'status': 'error', 'message': f'符号表文件不存在: {source_path}'}
        source_lower = source_path.name.lower()
        if not (source_lower.endswith('.zip') or source_lower.endswith('.json') or source_lower.endswith('.json.xz')):
            return {'status': 'error', 'message': '请选择 .zip、.json 或 .json.xz 格式的 Volatility 符号表'}

        zip_member = None
        candidate_name = source_path.name
        try:
            if source_lower.endswith('.zip'):
                with zipfile.ZipFile(source_path, 'r') as archive:
                    for member in archive.infolist():
                        member_lower = member.filename.lower()
                        if member.is_dir() or not (member_lower.endswith('.json') or member_lower.endswith('.json.xz')):
                            continue
                        with archive.open(member, 'r') as stream:
                            prefix = self._read_symbol_candidate_prefix(stream, member.filename)
                        if (
                            self._looks_like_volatility_isf(prefix)
                            and self._symbol_candidate_matches_current(
                                member.filename, prefix, os_type, symbol_info
                            )
                        ):
                            zip_member = member.filename
                            candidate_name = Path(member.filename).name
                            break
                if not zip_member:
                    return {
                        'status': 'error',
                        'error_type': 'symbol_mismatch',
                        'message': f'所选压缩包中没有匹配当前镜像的符号表。当前需要：{expected}',
                    }
            else:
                with open(source_path, 'rb') as stream:
                    prefix = self._read_symbol_candidate_prefix(stream, source_path.name)
                if (
                    not self._looks_like_volatility_isf(prefix)
                    or not self._symbol_candidate_matches_current(
                        source_path.name, prefix, os_type, symbol_info
                    )
                ):
                    return {
                        'status': 'error',
                        'error_type': 'symbol_mismatch',
                        'message': f'所选符号表与当前镜像不匹配。当前需要：{expected}；所选文件：{source_path.name}',
                    }

            target_dir = self._get_os_symbols_dir(os_type)
            if os_type == 'windows':
                pdb_info = symbol_info['pdb_info']
                target_dir = target_dir / str(pdb_info['name'])
                target_name = f"{pdb_info['guid']}-{pdb_info['age']}.json.xz"
            else:
                target_name = candidate_name
            target_dir.mkdir(parents=True, exist_ok=True)
            target_path = target_dir / target_name
            backup_path = None
            if target_path.exists():
                backup_path = target_path.with_name(f'.{target_path.name}.{uuid.uuid4().hex}.bak')
                shutil.move(str(target_path), str(backup_path))

            try:
                if zip_member:
                    with zipfile.ZipFile(source_path, 'r') as archive:
                        with archive.open(zip_member, 'r') as source_stream:
                            if os_type == 'windows' and not zip_member.lower().endswith('.xz'):
                                with lzma.open(target_path, 'wb') as target_stream:
                                    shutil.copyfileobj(source_stream, target_stream)
                            else:
                                with open(target_path, 'wb') as target_stream:
                                    shutil.copyfileobj(source_stream, target_stream)
                elif os_type == 'windows' and not source_lower.endswith('.xz'):
                    with open(source_path, 'rb') as source_stream, lzma.open(target_path, 'wb') as target_stream:
                        shutil.copyfileobj(source_stream, target_stream)
                else:
                    shutil.copy2(str(source_path), str(target_path))

                verification = self.get_symbol_status()
                verified_info = ((verification.get('data') or {}).get('os_types') or {}).get(os_type) or {}
                verified = bool(
                    (verified_info.get('pdb_info') or {}).get('symbol_exists')
                    if os_type == 'windows'
                    else verified_info.get('kernel_symbol_exists')
                )
                if not verified:
                    target_path.unlink(missing_ok=True)
                    if backup_path and backup_path.exists():
                        shutil.move(str(backup_path), str(target_path))
                    return {
                        'status': 'error',
                        'error_type': 'symbol_mismatch',
                        'message': f'符号表校验未通过，未保留所选文件。当前需要：{expected}',
                    }
                if backup_path and backup_path.exists():
                    backup_path.unlink()
                return {
                    'status': 'success',
                    'message': f'已安装并验证匹配的 {os_type} 符号表',
                    'data': {'os_type': os_type, 'path': str(target_path), 'verified': True},
                }
            except Exception:
                target_path.unlink(missing_ok=True)
                if backup_path and backup_path.exists():
                    shutil.move(str(backup_path), str(target_path))
                raise
        except zipfile.BadZipFile:
            return {'status': 'error', 'message': '所选 ZIP 文件已损坏或格式无效'}
        except (OSError, lzma.LZMAError) as exc:
            return {'status': 'error', 'message': f'读取或安装符号表失败: {exc}'}
        except Exception as exc:
            logger.error(f'导入当前镜像符号表失败: {exc}', exc_info=True)
            return {'status': 'error', 'message': f'导入符号表失败: {exc}'}

    def install_symbols(self, zip_file_path: str) -> Dict[str, Any]:
        try:
            import zipfile

            symbols_dir = self._symbols_dir
            symbols_dir.mkdir(parents=True, exist_ok=True)

            logger.info(f"开始安装符号表: {zip_file_path}")

            detected_os = None

            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()

                for filename in file_list:
                    filename_lower = filename.lower()

                    if ('kerneldebugkit' in filename_lower or 'debugkit' in filename_lower) and ('10.' in filename or 'build' in filename):
                        detected_os = 'mac'
                        break
                    elif 'ntkrnl' in filename_lower or filename_lower.startswith('windows-'):
                        detected_os = 'windows'
                        break
                    elif filename_lower.startswith('linux/') or filename_lower.startswith('linux\\') or 'linux' in filename_lower:
                        detected_os = 'linux'
                        break

            if not detected_os:
                logger.warning("无法自动检测操作系统类型，默认安装到 mac 目录")
                detected_os = 'mac'

            target_dir = self._get_os_symbols_dir(detected_os)
            target_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                for member in zip_ref.infolist():
                    filename = member.filename

                    parts = filename.replace('\\', '/').split('/')
                    if len(parts) > 1:
                        if parts[0].lower() in ['linux', 'windows', 'mac']:
                            actual_filename = '/'.join(parts[1:]) if len(parts) > 2 else parts[1]
                        else:
                            actual_filename = parts[-1]  
                    else:
                        actual_filename = filename

                    if not actual_filename or actual_filename.endswith('/'):
                        continue

                    if not (actual_filename.endswith('.json') or actual_filename.endswith('.json.xz')):
                        continue

                    target_path = target_dir / actual_filename

                    target_path.parent.mkdir(parents=True, exist_ok=True)

                    with open(target_path, 'wb') as f:
                        f.write(zip_ref.read(member))

                    logger.info(f"已提取: {actual_filename}")

            installed_count = len(list(target_dir.glob('*.json.xz'))) + len(list(target_dir.glob('*.json')))

            if detected_os == 'mac':
                try:
                    self._fix_macos_symbol_files(target_dir)
                except Exception as e:
                    logger.warning(f"创建 macOS 符号链接失败: {e}")

            logger.info(f"符号表安装成功: {detected_os} -> {target_dir}, 共 {installed_count} 个文件")

            return {
                'status': 'success',
                'message': f'符号表安装成功！已安装到 {detected_os.upper()} 目录，共 {installed_count} 个符号表文件。',
                'data': {
                    'os_type': detected_os,
                    'target_dir': str(target_dir),
                    'file_count': installed_count
                }
            }

        except zipfile.BadZipFile:
            logger.error("无效的 ZIP 文件")
            return {
                'status': 'error',
                'message': '无效的 ZIP 文件，请检查文件是否损坏'
            }
        except Exception as e:
            logger.error(f"符号表安装失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'符号表安装失败: {str(e)}'
            }

    def _open_directory(self, dir_path: str) -> Dict[str, Any]:
        import platform
        import subprocess

        current_os = platform.system()

        if current_os == 'Windows':
            subprocess.run(['explorer', str(dir_path)])
        elif current_os == 'Darwin':
            subprocess.run(['open', str(dir_path)])
        elif current_os == 'Linux':
            subprocess.run(['xdg-open', str(dir_path)])
        else:
            return {
                'status': 'error',
                'message': f'不支持的操作系统: {current_os}'
            }

        return {
            'status': 'success',
            'message': '目录已打开'
        }

    def _open_system_path(self, target_path: Path, reveal: bool = False) -> Dict[str, Any]:
        import platform
        import subprocess

        target_path = target_path.expanduser()
        if not target_path.exists():
            return {
                'status': 'error',
                'message': f'路径不存在: {target_path}'
            }

        current_os = platform.system()
        try:
            if current_os == 'Windows':
                if reveal and target_path.is_file():
                    subprocess.Popen(['explorer', f'/select,{str(target_path)}'])
                else:
                    os.startfile(str(target_path))  
            elif current_os == 'Darwin':
                cmd = ['open', '-R', str(target_path)] if reveal else ['open', str(target_path)]
                subprocess.Popen(cmd)
            elif current_os == 'Linux':
                open_target = target_path.parent if reveal and target_path.is_file() else target_path
                subprocess.Popen(['xdg-open', str(open_target)])
            else:
                return {
                    'status': 'error',
                    'message': f'不支持的操作系统: {current_os}'
                }

            return {
                'status': 'success',
                'message': '已在文件管理器中定位' if reveal else '路径已打开',
                'data': {
                    'path': str(target_path),
                    'revealed': reveal
                }
            }
        except Exception as e:
            logger.error(f"打开路径失败: {e}")
            return {
                'status': 'error',
                'message': f'打开路径失败: {str(e)}'
            }

    def open_directory(self, path: str) -> Dict[str, Any]:
        try:
            dir_path = Path(path)
            if not dir_path.exists():
                dir_path.mkdir(parents=True, exist_ok=True)
            return self._open_directory(str(dir_path))
        except Exception as e:
            logger.error(f"打开目录失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'打开目录失败: {str(e)}'
            }

    def open_path(self, path: str) -> Dict[str, Any]:
        try:
            if not path:
                return {'status': 'error', 'message': '缺少路径'}
            return self._open_system_path(Path(path), reveal=False)
        except Exception as e:
            logger.error(f"打开路径失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'打开路径失败: {str(e)}'
            }

    def reveal_path(self, path: str) -> Dict[str, Any]:
        try:
            if not path:
                return {'status': 'error', 'message': '缺少路径'}
            return self._open_system_path(Path(path), reveal=True)
        except Exception as e:
            logger.error(f"定位路径失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'定位路径失败: {str(e)}'
            }

    def open_cache_directory(self, path: str = None) -> Dict[str, Any]:
        try:
            typed = str(path or '').strip()
            if typed:
                cache_dir = resolve_volatility_cache_dir(typed, create=True)
            else:
                cache_dir = self._cache_path or default_volatility_cache_dir()
                cache_dir.mkdir(parents=True, exist_ok=True)
            return self._open_directory(str(cache_dir))
        except Exception as e:
            logger.error(f"打开缓存目录失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'打开缓存目录失败: {str(e)}'
            }

    def open_symbol_directory(self, os_type: str) -> Dict[str, Any]:
        try:
            symbols_dir = self._get_os_symbols_display_dir(os_type)
            if not symbols_dir.exists():
                symbols_dir.mkdir(parents=True, exist_ok=True)
            return self._open_directory(str(symbols_dir))
        except Exception as e:
            logger.error(f"打开符号表目录失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'打开目录失败: {str(e)}'
            }

    def download_symbols_from_github(self, os_type: str, kernel_version: str = None) -> Dict[str, Any]:
        import urllib.request
        import urllib.error
        import json as json_lib
        import os
        import re

        try:
            logger.info(f"开始从 GitHub 下载 {os_type} 符号表...")

            if not kernel_version and self.current_image:
                kernel_version = self._extract_kernel_version_from_banner()
                if not kernel_version:
                    return {
                        'status': 'error',
                        'message': '无法从镜像中提取内核版本信息，请手动指定内核版本'
                    }

            if os_type.lower() == 'mac':
                return self._download_macos_symbols(kernel_version)

            distro = self._detect_linux_distro_from_banner()
            if not distro:
                return {
                    'status': 'error',
                    'message': '无法从 banner 中检测 Linux 发行版类型（仅支持 Ubuntu/Debian 等）'
                }

            logger.info(f"检测到发行版: {distro}")

            parsed = self._parse_linux_kernel_version(kernel_version)
            if not parsed:
                return {
                    'status': 'error',
                    'message': f'无法解析内核版本格式: {kernel_version}'
                }

            major_version, abi, flavor = parsed['major'], parsed['abi'], parsed['flavor']
            logger.info(f"解析内核版本: major={major_version}, abi={abi}, flavor={flavor}")

            symbol_path = f"{distro}/amd64/{major_version}/{abi}/{flavor}"

            api_url = f"https://api.github.com/repos/Abyss-W4tcher/volatility3-symbols/contents/{symbol_path}"

            logger.info(f"获取符号表列表: {api_url}")

            proxy_url = self._build_proxy_url()
            if proxy_url:
                logger.info(f"使用代理下载: {proxy_url.split('@')[0] if '@' in proxy_url else proxy_url}")

            req = urllib.request.Request(api_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            req.add_header('Accept', 'application/vnd.github.v3+json')

            try:
                if proxy_url:
                    if proxy_url.startswith('socks'):
                        try:
                            import socks
                            import socket as socket_module
                            import ssl

                            _original_create_context = ssl._create_default_https_context

                            def _create_unverified_context():
                                ctx = ssl.create_default_context()
                                ctx.check_hostname = False
                                ctx.verify_mode = ssl.CERT_NONE
                                return ctx

                            ssl._create_default_https_context = _create_unverified_context

                            sock_type = socks.PROXY_TYPE_SOCKS5 if 'socks5' in proxy_url else socks.PROXY_TYPE_SOCKS4
                            proxy_host = self._proxy_config.get('host')
                            proxy_port = self._proxy_config.get('port')
                            proxy_user = self._proxy_config.get('username')
                            proxy_pass = self._proxy_config.get('password')

                            socks.set_default_proxy(sock_type, proxy_host, proxy_port, proxy_user, proxy_pass)
                            socket_module.socket = socks.socksocket

                            response = urllib.request.urlopen(req, timeout=30)

                            ssl._create_default_https_context = _original_create_context
                        except ImportError:
                            logger.warning("未安装 PySocks 库，SOCKS 代理不可用。请运行: pip install PySocks")
                            return {
                                'status': 'error',
                                'message': 'SOCKS 代理需要安装 PySocks 库。\n\n请运行: pip install PySocks\n\n或者使用 HTTP 代理（端口 7890）'
                            }
                        finally:
                            try:
                                import socket as socket_module
                                socket_module.socket = socket_module._socket.socket
                            except:
                                pass
                    else:
                        import ssl
                        ssl_context = ssl.create_default_context()
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE

                        proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                        https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                        opener = urllib.request.build_opener(proxy_handler, https_handler)
                        response = opener.open(req, timeout=30)
                else:
                    response = urllib.request.urlopen(req, timeout=30)

                data = json_lib.loads(response.read().decode('utf-8'))
            except urllib.error.HTTPError as e:
                logger.error(f"GitHub API 请求失败: {e.code} - {e.reason}")
                error_msg = str(e)
                try:
                    error_body = e.read().decode('utf-8')
                    logger.error(f"GitHub API 错误详情: {error_body}")
                except:
                    pass

                if e.code == 403:
                    proxy_hint = f"\n\n提示: GitHub API 请求被限制 (403)。\n\n可能的解决方案：\n1. 检查代理是否正常工作\n2. 尝试更换代理类型（如 SOCKS5）\n3. 稍后重试（GitHub 对未认证请求有限制）\n4. 手动下载符号表文件后使用【安装符号表】功能"
                    if proxy_url:
                        proxy_hint += f"\n\n当前代理: {proxy_url.split('@')[0] if '@' in proxy_url else proxy_url}"
                    return {
                        'status': 'error',
                        'message': f'GitHub API 访问被限制 (403)。\n\n这可能是由于：\n- GitHub API 速率限制\n- 代理配置问题\n- 网络连接问题{proxy_hint}'
                    }
                elif e.code == 404:
                    return {
                        'status': 'error',
                        'message': f'未找到匹配的符号表。\n\n路径: {symbol_path}\n\n该内核版本的符号表可能尚未收录到仓库中。\n\n请访问 https://github.com/Abyss-W4tcher/volatility3-symbols 查看可用版本'
                    }
                else:
                    return {
                        'status': 'error',
                        'message': f'GitHub API 请求失败 (HTTP {e.code})\n\n{error_msg}'
                    }
            except urllib.error.URLError as e:
                logger.error(f"网络请求失败: {str(e)}")
                proxy_hint = f"\n\n提示: 当前{'使用' if proxy_url else '未使用'}代理。"
                if proxy_url:
                    proxy_hint += f"\n代理地址: {proxy_url.split('@')[0] if '@' in proxy_url else proxy_url}\n\n请检查：\n1. 代理服务是否正常运行\n2. 代理地址和端口是否正确\n3. 尝试更换代理类型（HTTP/HTTPS/SOCKS5）"
                else:
                    proxy_hint += "\n如果访问 GitHub 较慢，可以在符号表管理中设置代理。"
                return {
                    'status': 'error',
                    'message': f'网络请求失败，请检查网络连接或代理设置。\n\n错误详情: {str(e)}{proxy_hint}'
                }
            except Exception as e:
                logger.error(f"获取符号表列表失败: {str(e)}")
                proxy_hint = f"\n\n提示: 当前{'使用' if proxy_url else '未使用'}代理。如果下载慢，可以在符号表管理中设置代理。"
                return {
                    'status': 'error',
                    'message': f'获取符号表列表失败: {str(e)}{proxy_hint}'
                }

            matching_files = []
            for item in data:
                if item.get('type') == 'file' and item.get('name', '').endswith('.json.xz'):
                    matching_files.append({
                        'name': item.get('name'),
                        'download_url': item.get('download_url'),
                        'size': item.get('size', 0)
                    })

            if not matching_files:
                return {
                    'status': 'error',
                    'message': f'该目录下没有找到符号表文件。\n路径: {symbol_path}'
                }

            target_file = matching_files[0]
            file_name = target_file['name']
            download_url = target_file['download_url']

            logger.info(f"找到匹配的符号表: {file_name}")
            logger.info(f"下载地址: {download_url}")

            target_dir = self._get_os_symbols_dir(os_type)
            target_dir.mkdir(parents=True, exist_ok=True)
            target_path = target_dir / file_name

            if target_path.exists():
                current_kernel = self._extract_kernel_version_from_banner()
                if current_kernel:
                    if current_kernel in file_name:
                        return {
                            'status': 'success',
                            'message': f'当前镜像已有匹配的符号表，可以正常使用需要符号表的插件。\n\n内核版本: {current_kernel}\n已安装匹配的符号表: {file_name}',
                            'file_name': file_name,
                            'already_exists': True
                        }
                    else:
                        return {
                            'status': 'error',
                            'message': f'符号表文件已存在，但版本可能不匹配。\n\n当前内核: {current_kernel}\n已安装: {file_name}\n\n如需重新下载，请先删除现有文件。'
                        }
                else:
                    return {
                        'status': 'error',
                        'message': f'符号表文件已存在：\n{file_name}\n\n如需重新下载，请先删除现有文件。'
                    }

            proxy_hint_text = f'\n(使用代理: {proxy_url.split("@")[0] if proxy_url and "@" in proxy_url else proxy_url})' if proxy_url else ''
            self._show_loading('正在下载符号表...', f'从 GitHub 下载 {file_name}...{proxy_hint_text}\n\n文件较大时可能需要几分钟，请耐心等待。')

            try:
                if proxy_url:
                    import ssl
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

                    proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                    opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ssl_context))

                    file_req = urllib.request.Request(download_url)
                    file_req.add_header('User-Agent', 'LensAnalysis-Forensics-Tool')

                    with opener.open(file_req, timeout=120) as response:
                        with open(target_path, 'wb') as f:
                            block_size = 8192
                            downloaded = 0
                            total_size = response.getheader('Content-Length')
                            if total_size:
                                total_size = int(total_size)

                            while True:
                                block = response.read(block_size)
                                if not block:
                                    break
                                f.write(block)
                                downloaded += len(block)
                else:
                    urllib.request.urlretrieve(download_url, str(target_path))
            except Exception as e:
                logger.error(f"下载失败: {str(e)}")
                if target_path.exists():
                    try:
                        target_path.unlink()
                    except:
                        pass
                self._hide_loading()
                proxy_hint = f"\n\n提示: 当前{'使用' if proxy_url else '未使用'}代理。如果下载慢，可以在符号表管理中设置代理。"
                return {
                    'status': 'error',
                    'message': f'下载符号表失败: {str(e)}{proxy_hint}'
                }

            logger.info(f"下载完成，文件大小: {target_path.stat().st_size} bytes")
            logger.info(f"符号表已安装到: {target_path}")

            self._hide_loading()

            return {
                'status': 'success',
                'message': f'符号表下载成功！\n文件: {file_name}\n已安装到: {target_dir}',
                'file_name': file_name,
                'os_type': os_type,
                'kernel_version': kernel_version,
                'update_ui': True  
            }

        except Exception as e:
            self._hide_loading()
            logger.error(f"下载符号表失败: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'message': f'下载符号表失败: {str(e)}'
            }

    def _download_macos_symbols(self, darwin_version: str) -> Dict[str, Any]:
        import urllib.request
        import urllib.error
        import json as json_lib

        darwin_to_macos = {
            '16.': '10.12',
            '17.': '10.13',
            '18.': '10.14',
            '19.': '10.15',
            '20.': '11.0',
            '21.': '12.0',
            '22.': '13.0',
            '23.': '14.0',
        }

        macos_version = None
        for darwin_prefix, macos in darwin_to_macos.items():
            if darwin_version.startswith(darwin_prefix):
                macos_version = macos
                break

        if not macos_version:
            return {
                'status': 'error',
                'message': f'不支持的 Darwin 版本: {darwin_version}\n\n请确保是 macOS 10.12 (Sierra) 或更高版本'
            }

        symbol_path = f"macOS/{macos_version}"

        api_url = f"https://api.github.com/repos/Abyss-W4tcher/volatility3-symbols/contents/{symbol_path}"

        logger.info(f"Darwin {darwin_version} -> macOS {macos_version}")
        logger.info(f"获取 macOS 符号表列表: {api_url}")

        proxy_url = self._build_proxy_url()
        if proxy_url:
            logger.info(f"使用代理下载: {proxy_url.split('@')[0] if '@' in proxy_url else proxy_url}")

        req = urllib.request.Request(api_url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        req.add_header('Accept', 'application/vnd.github.v3+json')

        try:
            if proxy_url:
                if proxy_url.startswith('socks'):
                    try:
                        import socks
                        import socket as socket_module
                        import ssl

                        _original_create_context = ssl._create_default_https_context

                        def _create_unverified_context():
                            ctx = ssl.create_default_context()
                            ctx.check_hostname = False
                            ctx.verify_mode = ssl.CERT_NONE
                            return ctx

                        ssl._create_default_https_context = _create_unverified_context

                        sock_type = socks.PROXY_TYPE_SOCKS5 if 'socks5' in proxy_url else socks.PROXY_TYPE_SOCKS4
                        proxy_host = self._proxy_config.get('host')
                        proxy_port = self._proxy_config.get('port')
                        proxy_user = self._proxy_config.get('username')
                        proxy_pass = self._proxy_config.get('password')
                        socks.set_default_proxy(sock_type, proxy_host, proxy_port, proxy_user, proxy_pass)
                        socket_module.socket = socks.socksocket

                        response = urllib.request.urlopen(req, timeout=30)

                        ssl._create_default_https_context = _original_create_context
                    except ImportError:
                        return {
                            'status': 'error',
                            'message': 'SOCKS 代理需要安装 PySocks 库。请运行: pip install PySocks'
                        }
                    finally:
                        try:
                            import socket as socket_module
                            socket_module.socket = socket_module._socket.socket
                        except:
                            pass
                else:
                    import ssl
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                    https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                    opener = urllib.request.build_opener(proxy_handler, https_handler)
                    response = opener.open(req, timeout=30)
            else:
                response = urllib.request.urlopen(req, timeout=30)

            data = json_lib.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            logger.error(f"GitHub API 请求失败: {e.code} - {e.reason}")
            if e.code == 404:
                return {
                    'status': 'error',
                    'message': f'未找到 macOS {macos_version} (Darwin {darwin_version}) 的符号表。\n\n请访问 https://github.com/Abyss-W4tcher/volatility3-symbols/tree/main/macOS 查看可用版本'
                }
            else:
                return {
                    'status': 'error',
                    'message': f'GitHub API 请求失败 (HTTP {e.code})'
                }
        except urllib.error.URLError as e:
            return {
                'status': 'error',
                'message': f'网络请求失败: {str(e)}'
            }
        except Exception as e:
            logger.error(f"获取符号表列表失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'获取符号表列表失败: {str(e)}'
            }

        matching_files = []
        for item in data:
            if item.get('type') == 'file' and item.get('name', '').endswith('.json.xz'):
                matching_files.append({
                    'name': item.get('name'),
                    'download_url': item.get('download_url'),
                    'size': item.get('size', 0)
                })

        if not matching_files:
            return {
                'status': 'error',
                'message': f'该目录下没有找到符号表文件。\n路径: {symbol_path}'
            }

        matching_files.sort(key=lambda x: x['name'])

        priority_builds = []
        for f in matching_files:
            name = f['name']
            if '16G29' in name or '16G1408' in name or '16G1618' in name:
                if name not in priority_builds:
                    priority_builds.append(f)

        if priority_builds:
            files_to_download = priority_builds[:3]  
        else:
            files_to_download = matching_files[:5]  

        logger.info(f"准备下载 {len(files_to_download)} 个 macOS 符号表文件")

        target_dir = self._get_os_symbols_dir('mac')
        target_dir.mkdir(parents=True, exist_ok=True)

        downloaded_files = []
        skipped_files = []

        for target_file in files_to_download:
            file_name = target_file['name']
            download_url = target_file['download_url']
            target_path = target_dir / file_name

            if target_path.exists():
                logger.info(f"符号表已存在，跳过: {file_name}")
                skipped_files.append(file_name)
                continue

            logger.info(f"开始下载: {file_name}")

            req = urllib.request.Request(download_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')

            try:
                if proxy_url:
                    if proxy_url.startswith('socks'):
                        try:
                            import socks
                            import socket as socket_module
                            import ssl

                            _original_create_context = ssl._create_default_https_context

                            def _create_unverified_context():
                                ctx = ssl.create_default_context()
                                ctx.check_hostname = False
                                ctx.verify_mode = ssl.CERT_NONE
                                return ctx

                            ssl._create_default_https_context = _create_unverified_context

                            sock_type = socks.PROXY_TYPE_SOCKS5 if 'socks5' in proxy_url else socks.PROXY_TYPE_SOCKS4
                            proxy_host = self._proxy_config.get('host')
                            proxy_port = self._proxy_config.get('port')
                            proxy_user = self._proxy_config.get('username')
                            proxy_pass = self._proxy_config.get('password')
                            socks.set_default_proxy(sock_type, proxy_host, proxy_port, proxy_user, proxy_pass)
                            socket_module.socket = socks.socksocket

                            response = urllib.request.urlopen(req, timeout=60)

                            ssl._create_default_https_context = _original_create_context
                        except ImportError:
                            return {
                                'status': 'error',
                                'message': 'SOCKS 代理需要安装 PySocks 库'
                            }
                        finally:
                            try:
                                import socket as socket_module
                                socket_module.socket = socket_module._socket.socket
                            except:
                                pass
                    else:
                        import ssl
                        ssl_context = ssl.create_default_context()
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE
                        proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                        https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                        opener = urllib.request.build_opener(proxy_handler, https_handler)
                        response = opener.open(req, timeout=60)
                else:
                    response = urllib.request.urlopen(req, timeout=60)

                with open(target_path, 'wb') as f:
                    f.write(response.read())

                logger.info(f"macOS 符号表下载完成: {file_name}")
                downloaded_files.append(file_name)

            except Exception as e:
                logger.error(f"下载文件失败 {file_name}: {str(e)}")

        if downloaded_files:
            try:
                self._fix_macos_symbol_files(target_dir)
            except Exception as e:
                logger.warning(f"创建符号链接失败: {e}")

        message_parts = []
        if downloaded_files:
            message_parts.append(f"已下载 {len(downloaded_files)} 个符号表文件:")
            for f in downloaded_files:
                message_parts.append(f"  • {f}")
        if skipped_files:
            message_parts.append(f"\n已存在 {len(skipped_files)} 个文件（跳过）:")
            for f in skipped_files:
                message_parts.append(f"  • {f}")

        message = '\n'.join(message_parts) if message_parts else '没有下载新文件'

        return {
            'status': 'success',
            'message': message,
            'downloaded_count': len(downloaded_files),
            'skipped_count': len(skipped_files)
        }

    def _detect_linux_distro_from_banner(self) -> str:
        if not self.current_image:
            return None

        banner = self.current_image.get('banner', '')
        if not banner:
            return None

        banner_lower = banner.lower()

        if 'ubuntu' in banner_lower:
            return 'Ubuntu'
        elif 'debian' in banner_lower:
            return 'Debian'
        elif 'kali' in banner_lower:
            return 'KaliLinux'
        elif 'almalinux' in banner_lower or 'alma' in banner_lower:
            return 'AlmaLinux'
        elif 'rocky' in banner_lower:
            return 'RockyLinux'

        return None

    def _parse_linux_kernel_version(self, kernel_version: str):
        import re

        match = re.match(r'^(\d+\.\d+\.\d+)-(\d+)-(\w+)', kernel_version)
        if match:
            return {
                'major': match.group(1),  
                'abi': match.group(2),     
                'flavor': match.group(3)  
            }

        match = re.match(r'^(\d+\.\d+\.\d+)-(\d+)', kernel_version)
        if match:
            return {
                'major': match.group(1),
                'abi': match.group(2),
                'flavor': 'generic'  
            }

        return None

    def build_linux_symbol_table(self, banner: str = None) -> Dict[str, Any]:
        try:
            from backend.symbol_table_builder import SymbolTableBuilder

            if not banner:
                if not self.current_image:
                    return {
                        'status': 'error',
                        'message': '未加载镜像，请先加载内存镜像'
                    }
                banner = self.current_image.get('banner', '')
                if not banner:
                    banner = self._get_image_banner(self.current_image['path'], 'linux')
                    if not banner:
                        return {
                            'status': 'error',
                            'message': '无法获取内核 banner 信息'
                        }

            if 'Linux version' not in banner:
                return {
                    'status': 'error',
                    'message': '当前镜像不是 Linux 系统镜像'
                }

            logger.info(f"开始构建 Linux 符号表, banner: {banner[:100]}...")

            builder = SymbolTableBuilder(
                symbols_dir=self._get_symbols_base_dir('linux'),
                progress_callback=self._symbol_build_progress_callback,
                proxy_config=self._proxy_config,
                data_dir=self._user_data_dir
            )

            result = builder.build(banner)

            return result

        except ImportError as e:
            logger.error(f"导入 symbol_table_builder 失败: {e}")
            return {
                'status': 'error',
                'message': f'符号表构建模块加载失败: {str(e)}'
            }
        except Exception as e:
            logger.error(f"构建符号表失败: {e}", exc_info=True)
            return {
                'status': 'error',
                'message': f'构建失败: {str(e)}'
            }

    def _symbol_build_progress_callback(self, stage: str, progress: int, message: str):
        if progress == 0 or progress == 100:
            logger.info(f"[符号表构建] {stage}: {progress}% - {message}")
        else:
            logger.debug(f"[符号表构建] {stage}: {progress}% - {message}")

    def check_dwarf2json_available(self) -> Dict[str, Any]:
        try:
            from backend.symbol_table_builder import SymbolTableBuilder

            builder = SymbolTableBuilder(self._symbols_dir, data_dir=self._user_data_dir)

            if builder.dwarf2json_path:
                path = builder.dwarf2json_path
                if path.exists() and path.stat().st_size > 1000000:  
                    try:
                        import platform
                        subprocess_kwargs = self._get_subprocess_kwargs(capture_output=True, text=True, timeout=10)
                        result = subprocess.run(
                            [str(path), '--help'],
                            **subprocess_kwargs
                        )
                        output = result.stdout + result.stderr
                        if output:
                            return {
                                'available': True,
                                'path': str(path),
                                'message': 'dwarf2json 工具可用'
                            }
                        else:
                            return {
                                'available': True,
                                'path': str(path),
                                'message': 'dwarf2json 工具已就绪'
                            }
                    except subprocess.TimeoutExpired:
                        return {
                            'available': True,
                            'path': str(path),
                            'message': 'dwarf2json 工具已就绪'
                        }
                    except Exception as e:
                        logger.warning(f"dwarf2json 执行异常，但文件存在: {e}")
                        return {
                            'available': True,
                            'path': str(path),
                            'message': 'dwarf2json 工具已安装'
                        }
                else:
                    return {
                        'available': False,
                        'path': str(path) if path.exists() else None,
                        'message': 'dwarf2json 文件不完整，请重新下载'
                    }
            else:
                return {
                    'available': False,
                    'path': None,
                    'message': '未找到 dwarf2json 工具，点击"下载工具"按钮自动下载'
                }

        except Exception as e:
            logger.error(f"检查 dwarf2json 失败: {e}")
            return {
                'available': False,
                'path': None,
                'message': f'检查失败: {str(e)}'
            }

    def download_dwarf2json(self) -> Dict[str, Any]:
        import platform
        import urllib.request
        import ssl

        try:
            system = platform.system()
            machine = platform.machine()

            if system == 'Windows':
                download_name = 'dwarf2json-windows-amd64.exe'
                target_name = 'dwarf2json.exe'
            elif system == 'Darwin':
                if machine == 'arm64':
                    download_name = 'dwarf2json-MacOS-arm64'
                else:
                    download_name = 'dwarf2json-MacOS-amd64'
                target_name = 'dwarf2json'
            else:  
                download_name = 'dwarf2json-linux-amd64'
                target_name = 'dwarf2json'

            base_url = "https://gitee.com/hilyary/LensAnalysis/releases/download/dwarf2json-v0.9.0"
            download_url = f"{base_url}/{download_name}"

            logger.info(f"开始下载 dwarf2json: {download_url}")

            tools_dir = self._user_data_dir / 'tools'
            tools_dir.mkdir(parents=True, exist_ok=True)
            target_path = tools_dir / target_name

            if target_path.exists():
                target_path.unlink()

            request = urllib.request.Request(download_url)
            request.add_header('User-Agent', 'LensAnalysis-dwarf2json-downloader')

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if self._proxy_config:
                proxy_type = self._proxy_config.get('type', 'http')
                host = self._proxy_config.get('host')
                port = self._proxy_config.get('port')
                username = self._proxy_config.get('username')
                password = self._proxy_config.get('password')

                if host and port:
                    if username and password:
                        proxy_url = f"{proxy_type}://{username}:{password}@{host}:{port}"
                    else:
                        proxy_url = f"{proxy_type}://{host}:{port}"

                    if proxy_type in ['http', 'https']:
                        os.environ['HTTP_PROXY'] = proxy_url
                        os.environ['HTTPS_PROXY'] = proxy_url

            with urllib.request.urlopen(request, timeout=120, context=ctx) as response:
                total_size = int(response.headers.get('Content-Length', 0))
                downloaded = 0
                chunk_size = 8192
                last_progress = -10  

                with open(target_path, 'wb') as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            current_progress = int(downloaded * 100 / total_size)
                            if current_progress - last_progress >= 10:
                                logger.info(f"下载进度: {current_progress}%")
                                last_progress = current_progress

            if system != 'Windows':
                os.chmod(target_path, 0o755)

            if target_path.exists() and target_path.stat().st_size > 1000000:
                logger.info(f"dwarf2json 下载成功: {target_path}")
                return {
                    'status': 'success',
                    'message': f'dwarf2json 下载成功 ({target_path.stat().st_size / 1024 / 1024:.1f} MB)',
                    'path': str(target_path)
                }
            else:
                return {
                    'status': 'error',
                    'message': '下载的文件不完整，请重试'
                }

        except urllib.error.HTTPError as e:
            logger.error(f"下载失败: HTTP {e.code} - {e.reason}")
            return {
                'status': 'error',
                'message': f'下载失败: HTTP {e.code} - {e.reason}\n可能是该平台版本暂未提供'
            }
        except urllib.error.URLError as e:
            logger.error(f"下载失败: {e.reason}")
            return {
                'status': 'error',
                'message': f'下载失败: {e.reason}\n请检查网络连接'
            }
        except Exception as e:
            logger.error(f"下载失败: {e}", exc_info=True)
            return {
                'status': 'error',
                'message': f'下载失败: {str(e)}'
            }
        finally:
            for var in ['HTTP_PROXY', 'HTTPS_PROXY']:
                if var in os.environ:
                    del os.environ[var]

    def get_linux_distro_info(self) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '未加载镜像'
                }

            os_type = self.current_image.get('os_type', '').lower()
            if 'linux' not in os_type:
                return {
                    'status': 'error',
                    'message': '当前镜像不是 Linux 系统'
                }

            banner = self.current_image.get('banner', '')
            if not banner:
                banner = self._get_image_banner(self.current_image['path'], 'linux')

            if not banner:
                return {
                    'status': 'error',
                    'message': '无法获取 banner 信息'
                }

            from backend.symbol_table_builder import LinuxVersionInfo
            version_info = LinuxVersionInfo(banner)

            return {
                'status': 'success',
                'distro': version_info.distro,
                'distro_codename': version_info.distro_codename,
                'kernel_version': version_info.kernel_version,
                'package_version': version_info.package_version,
                'arch': version_info.arch,
                'banner': banner
            }

        except Exception as e:
            logger.error(f"获取发行版信息失败: {e}", exc_info=True)
            return {
                'status': 'error',
                'message': f'获取失败: {str(e)}'
            }

    def _install_single_symbol(self, file_path: str, os_type: str) -> Dict[str, Any]:
        try:
            import lzma
            import shutil

            symbols_dir = self._get_os_symbols_dir(os_type)
            symbols_dir.mkdir(parents=True, exist_ok=True)

            if file_path.endswith('.xz'):
                json_xz_path = Path(file_path)
                json_filename = json_xz_path.stem  
                output_path = symbols_dir / json_filename

                with lzma.open(file_path, 'rb') as f_in:
                    with open(output_path, 'wb') as f_out:
                        f_out.write(f_in.read())

                logger.info(f"符号表已安装到: {output_path}")

                if os_type == 'mac':
                    original_xz_path = symbols_dir / Path(file_path).name
                    shutil.copy(file_path, original_xz_path)
                    self._fix_macos_symbol_files(symbols_dir)

                return {
                    'status': 'success',
                    'message': f'符号表安装成功',
                    'data': {
                        'path': str(output_path),
                        'os_type': os_type
                    }
                }
            else:
                output_path = symbols_dir / Path(file_path).name
                shutil.copy(file_path, output_path)

                if os_type == 'mac':
                    self._fix_macos_symbol_files(symbols_dir)

                return {
                    'status': 'success',
                    'message': f'符号表安装成功',
                    'data': {
                        'path': str(output_path),
                        'os_type': os_type
                    }
                }

        except Exception as e:
            logger.error(f"安装符号表失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'安装失败: {str(e)}'
            }


    def _detect_os_type(self, file_path: str) -> str:
        from backend.volatility_wrapper import VolatilityWrapper
        wrapper = VolatilityWrapper(
            file_path,
            symbols_dir=str(self._get_symbols_base_dir(None)),
            cache_path=self._cache_path,
        )
        logger.info(f"开始检测镜像文件: {file_path}")

        self._cached_banner = None

        try:
            logger.info("使用 banners 插件检测操作系统...")
            result = wrapper._run_volatility('banners.Banners', [], use_symbols=False)

            if result and isinstance(result, list) and len(result) > 0:
                first_banner = str(result[0].get('banner', ''))
                logger.info(f"Banner 内容: {first_banner[:200]}")

                self._cached_banner = first_banner

                first_banner_lower = first_banner.lower()

                if 'windows' in first_banner_lower or 'microsoft' in first_banner_lower:
                    logger.info("✅ 通过 Banner 检测到 Windows 内存镜像")
                    return 'Windows'
                elif 'darwin kernel' in first_banner_lower or 'mac os x' in first_banner_lower:
                    logger.info("✅ 通过 Banner 检测到 macOS 内存镜像")
                    return 'macOS'
                elif 'linux' in first_banner_lower and 'version' in first_banner_lower:
                    logger.info("✅ 通过 Banner 检测到 Linux 内存镜像")
                    return 'Linux'
                else:
                    logger.warning(f"Banner 无法识别系统类型: {first_banner[:100]}")
            else:
                logger.info("Banners 插件未返回结果（空）")
        except Exception as e:
            logger.warning(f"Banners 检测失败: {str(e)}")

        logger.info("✅ Banners 为空，默认识别为 Windows 内存镜像")
        return 'Windows'

    def _check_plugin_compatibility(self, plugin_id: str, os_type: str) -> tuple[bool, str]:
        plugin_os_support = {
            'imageinfo': ['Windows'],
            'pslist': ['Windows'],
            'pstree': ['Windows'],
            'psscan': ['Windows'],
            'dlllist': ['Windows'],
            'handles': ['Windows'],
            'cmdline': ['Windows'],
            'cmdscan': ['Windows'],
            'envars': ['Windows'],
            'getsids': ['Windows'],
            'netscan': ['Windows'],
            'netstat': ['Windows'],
            'svcscan': ['Windows'],
            'filescan': ['Windows'],
            'hivelist': ['Windows'],
            'printkey': ['Windows'],
            'malfind': ['Windows'],
            'hashdump': ['Windows'],
            'lsadump': ['Windows'],
            'cachedump': ['Windows'],
            'svcscan_reg': ['Windows'],
            'certificates': ['Windows'],
            'drivermodule': ['Windows'],
            'hollowprocesses': ['Windows'],
            'ldrmodules': ['Windows'],
            'svcdiff': ['Windows'],
            'unhooked_system_calls': ['Windows'],
            'processghosting': ['Windows'],
            'malware_psxview': ['Windows'],
            'pebmasquerade': ['Windows'],

            'linux_pslist': ['Linux'],
            'linux_pstree': ['Linux'],
            'linux_psscan': ['Linux'],
            'linux_psaux': ['Linux'],
            'linux_netstat': ['Linux'],
            'linux_sockstat': ['Linux'],
            'linux_ip_addr': ['Linux'],
            'linux_ip_link': ['Linux'],
            'linux_lsof': ['Linux'],
            'linux_elfs': ['Linux'],
            'linux_mountinfo': ['Linux'],
            'linux_pagecache_files': ['Linux'],
            'linux_bash': ['Linux'],
            'linux_envars': ['Linux'],
            'linux_malfind': ['Linux'],
            'linux_vmayarascan': ['Linux'],
            'linux_lsmod': ['Linux'],
            'linux_check_modules': ['Linux'],
            'linux_capabilities': ['Linux'],
            'linux_check_afinfo': ['Linux'],
            'linux_check_creds': ['Linux'],
            'linux_check_idt': ['Linux'],
            'linux_check_syscall': ['Linux'],
            'linux_tty_check': ['Linux'],
            'linux_iomem': ['Linux'],
            'linux_keyboard_notifiers': ['Linux'],
            'linux_kmsg': ['Linux'],
            'linux_maps': ['Linux'],

            'mac.pslist.PsList': ['macOS', 'mac'],
            'mac.pstree.PsTree': ['macOS', 'mac'],
            'mac.psaux.Psaux': ['macOS', 'mac'],
            'mac.netstat.Netstat': ['macOS', 'mac'],
            'mac.ifconfig.Ifconfig': ['macOS', 'mac'],
            'mac.socket_filters.Socket_filters': ['macOS', 'mac'],
            'mac.lsof.Lsof': ['macOS', 'mac'],
            'mac.list_files.List_Files': ['macOS', 'mac'],
            'mac.mount.Mount': ['macOS', 'mac'],
            'mac.bash.Bash': ['macOS', 'mac'],
            'mac.malfind.Malfind': ['macOS', 'mac'],
            'mac.lsmod.Lsmod': ['macOS', 'mac'],
            'mac.check_syscall.Check_syscall': ['macOS', 'mac'],
            'mac.check_sysctl.Check_sysctl': ['macOS', 'mac'],
            'mac.check_trap_table.Check_trap_table': ['macOS', 'mac'],
            'mac.dmesg.Dmesg': ['macOS', 'mac'],
            'mac.kevents.Kevents': ['macOS', 'mac'],
            'mac.timers.Timers': ['macOS', 'mac'],
            'mac.kauth_listeners.Kauth_listeners': ['macOS', 'mac'],
            'mac.kauth_scopes.Kauth_scopes': ['macOS', 'mac'],
            'mac.trustedbsd.Trustedbsd': ['macOS', 'mac'],
            'mac.proc_maps.Maps': ['macOS', 'mac'],
            'mac.vfsevents.VFSevents': ['macOS', 'mac'],

            'mac_pslist': ['macOS', 'mac'],
            'mac_pstree': ['macOS', 'mac'],
            'mac_psaux': ['macOS', 'mac'],
            'mac_netstat': ['macOS', 'mac'],
            'mac_ifconfig': ['macOS', 'mac'],
            'mac_socket_filters': ['macOS', 'mac'],
            'mac_lsof': ['macOS', 'mac'],
            'mac_list_files': ['macOS', 'mac'],
            'mac_mount': ['macOS', 'mac'],
            'mac_bash': ['macOS', 'mac'],
            'mac_malfind': ['macOS', 'mac'],
            'mac_lsmod': ['macOS', 'mac'],
            'mac_check_syscall': ['macOS', 'mac'],
            'mac_check_sysctl': ['macOS', 'mac'],
            'mac_check_trap_table': ['macOS', 'mac'],
            'mac_dmesg': ['macOS', 'mac'],
            'mac_kevents': ['macOS', 'mac'],
            'mac_timers': ['macOS', 'mac'],
            'mac_kauth_listeners': ['macOS', 'mac'],
            'mac_kauth_scopes': ['macOS', 'mac'],
            'mac_trustedbsd': ['macOS', 'mac'],
            'mac_maps': ['macOS', 'mac'],
            'mac_vfsevents': ['macOS', 'mac'],
            'mac_envars': ['macOS', 'mac'],

            'search_flag': ['Windows', 'Linux', 'macOS', 'mac'],
            'mac_search_flag': ['macOS', 'mac'],
        }

        supported_os = plugin_os_support.get(plugin_id, ['Windows', 'Linux', 'macOS', 'mac'])

        if os_type in supported_os or os_type == 'Unknown':
            return True, ''
        else:
            return False, f'此插件仅支持 {", ".join(supported_os)} 系统，当前镜像为 {os_type} 系统'

    @staticmethod
    def _normalized_image_path(file_path: str) -> str:
        return os.path.normcase(os.path.abspath(os.path.expanduser(str(file_path))))

    def _resolve_image_project_cache(
        self, cache_fingerprint: str
    ) -> Tuple[Path, Optional[Dict[str, Any]]]:
        project_dir = self._cache_dir / cache_fingerprint
        info_file = project_dir / 'project_info.json'
        if not info_file.exists():
            return project_dir, None
        try:
            with open(info_file, 'r', encoding='utf-8') as stream:
                info = json.load(stream)
            return project_dir, info if isinstance(info, dict) else None
        except (OSError, ValueError):
            return project_dir, None

    def load_memory_image(self, file_path: str, user_specified_os: str = None) -> Dict[str, Any]:
        try:
            file_path = os.path.expanduser(str(file_path or '').strip().strip('"\'`“”‘’'))
            if self.current_image and self.current_image.get('path') != file_path:
                logger.info(f"切换镜像，清空 banner 缓存")
                self._cached_banner = None

            if not os.path.exists(file_path):
                return {
                    'status': 'error',
                    'message': f'文件不存在: {file_path}'
                }

            file_size = os.path.getsize(file_path)
            cache_fingerprint = self._calculate_file_hash(file_path)

            project_cache_dir, cached_info = self._resolve_image_project_cache(cache_fingerprint)
            project_key = project_cache_dir.name
            project_info_file = project_cache_dir / 'project_info.json'

            os_type = None
            banner = None
            from_cache = False
            cache_dirty = False
            self._last_banner_scan_completed = False

            if project_info_file.exists():
                try:
                    if cached_info is None:
                        with open(project_info_file, 'r', encoding='utf-8') as f:
                            cached_info = json.load(f)
                    cache_identity_matches = (
                        cached_info.get('cache_fingerprint') == cache_fingerprint
                        and cached_info.get('hash') == project_key
                    )
                    if cache_identity_matches:
                        os_type = cached_info.get('os_type')
                        banner = cached_info.get('banner')
                        from_cache = True
                        logger.info(f"从缓存加载镜像信息: {cached_info.get('name')}, os_type={os_type}, banner={'有' if banner else '无'}")

                        user_os = self._normalize_os_type(user_specified_os)
                        if user_os and user_os != self._normalize_os_type(os_type):
                            logger.info(
                                f"用户指定 {user_specified_os}，缓存记录为 {os_type}，"
                                f"改用用户指定的 {user_os} 并更正缓存"
                            )
                            os_type = user_os
                            banner = ''
                            cached_info.pop('banner_scanned', None)
                            cache_dirty = True

                        if not banner and os_type and ('linux' in os_type.lower() or 'mac' in os_type.lower()):
                            if cached_info.get('banner_scanned'):
                                logger.info(f"缓存记录该镜像没有 banner，跳过重复扫描")
                            else:
                                logger.info(f"缓存中没有 banner，且OS类型为 {os_type}，需要重新获取...")
                                banner = self._get_image_banner(file_path, os_type)
                                cache_dirty = True
                                if not banner and self._last_banner_scan_completed:
                                    cached_info['banner_scanned'] = True

                        if banner:
                            self._cached_banner = banner

                        if cache_dirty:
                            cached_info['os_type'] = os_type
                            cached_info['banner'] = banner or ''
                            try:
                                with open(project_info_file, 'w', encoding='utf-8') as f:
                                    json.dump(cached_info, f, indent=2, ensure_ascii=False)
                                logger.info("已更新缓存中的镜像信息")
                            except Exception as e:
                                logger.warning(f"更新缓存失败: {e}")
                except Exception as e:
                    logger.warning(f"读取缓存失败: {e}")

            if from_cache:
                logger.info(f"缓存命中，跳过检测和 banner 执行")

                needs_symbol = False
                symbol_info = None
                os_type_lower = os_type.lower() if os_type else 'unknown'
                current_pdb = {}
                kernel_version = None
                kernel_symbol_exists = None
                symbol_dir_name = os_type_lower

                self.current_image = {
                    'path': file_path,
                    'name': cached_info.get('name'),
                    'hash': project_key,
                    'cache_fingerprint': cache_fingerprint,
                    'hash_type': 'sampled-cache-fingerprint-v1',
                    'size': file_size,
                    'os_type': os_type,
                    'banner': banner,
                    'loaded_at': cached_info.get('loaded_at', datetime.now().isoformat())
                }

                if ('linux' in os_type_lower or 'mac' in os_type_lower) and banner:
                    kernel_version = self._extract_kernel_version(banner, os_type_lower)
                    if kernel_version:
                        kernel_symbol_exists = self._check_symbol_exists(os_type_lower, kernel_version)
                        if not kernel_symbol_exists:
                            needs_symbol = True
                            symbol_info = {
                                'os_type': os_type_lower,
                                'kernel_version': kernel_version
                            }
                elif os_type_lower == 'windows':
                    windows_info = self._get_windows_symbol_info_fast(cached_info)
                    current_pdb = windows_info.get('pdb_info') or {}
                    if not current_pdb.get('symbol_exists'):
                        needs_symbol = True
                        symbol_info = {
                            'os_type': 'windows',
                            'kernel_version': None,
                            'pdb_info': current_pdb,
                        }

                has_symbols = False
                symbol_count = 0
                if 'linux' in os_type_lower or 'mac' in os_type_lower:
                    symbol_dir_name = 'mac' if 'mac' in os_type_lower else 'linux'
                    symbol_dir = self._get_os_symbols_dir(symbol_dir_name)
                    if symbol_dir.exists():
                        symbol_count = len(self._get_valid_symbol_files(symbol_dir_name))
                        has_symbols = symbol_count > 0
                elif 'windows' in os_type_lower:
                    has_symbols = bool(current_pdb.get('symbol_exists'))
                    symbol_count = 1 if has_symbols else 0

                if os_type_lower == 'windows' and current_pdb.get('symbol_exists'):
                    symbol_file = (
                        f"{current_pdb.get('name')} "
                        f"({current_pdb.get('guid')}-{current_pdb.get('age')})"
                    )
                elif os_type_lower == 'windows':
                    symbol_file = None
                else:
                    symbol_file = self._get_symbol_file_name()
                if symbol_file:
                    self.current_image['symbol_file'] = symbol_file
                else:
                    self.current_image['symbol_file'] = '未安装'

                self._load_flag_search_cache_from_file()

                cached_info.update({
                    'name': os.path.basename(file_path),
                    'path': file_path,
                    'hash': project_key,
                    'cache_fingerprint': cache_fingerprint,
                    'hash_type': 'sampled-cache-fingerprint-v1',
                    'last_accessed': datetime.now().isoformat(),
                })
                if current_pdb:
                    cached_info['pdb_info'] = current_pdb
                self.current_image['name'] = cached_info['name']
                with open(project_info_file, 'w', encoding='utf-8') as f:
                    json.dump(cached_info, f, ensure_ascii=False, indent=2)

                logger.info(f"成功从缓存加载镜像: {self.current_image['name']}")

                os_types = {}
                if 'linux' in os_type_lower or 'mac' in os_type_lower or 'windows' in os_type_lower:
                    os_types[symbol_dir_name] = {
                        'installed': has_symbols,
                        'count': symbol_count
                    }
                    if os_type_lower == 'windows':
                        os_types[symbol_dir_name]['pdb_info'] = current_pdb
                    elif kernel_version:
                        os_types[symbol_dir_name]['kernel_version'] = kernel_version
                        os_types[symbol_dir_name]['kernel_symbol_exists'] = bool(kernel_symbol_exists)

                response_data = {
                    'name': self.current_image['name'],
                    'size': self._format_size(file_size),
                    'hash': project_key,
                    'cache_fingerprint': cache_fingerprint,
                    'hash_type': 'sampled-cache-fingerprint-v1',
                    'path': file_path,
                    'os_type': os_type,
                    'banner': banner,
                    'has_symbols': has_symbols,
                    'symbol_count': symbol_count,
                    'from_cache': True,
                    'os_types': os_types
                }

                if needs_symbol and symbol_info:
                    response_data['needs_symbol'] = True
                    response_data['symbol_info'] = symbol_info

                return {
                    'status': 'success',
                    'data': response_data
                }

            if user_specified_os:
                logger.info(f"用户指定系统类型: {user_specified_os}，使用指定类型（跳过OS自动检测）")
                os_type = user_specified_os
                os_type_lower = os_type.lower()
                if os_type_lower == 'macos':
                    os_type = 'mac'
                    os_type_lower = 'mac'
                    logger.info(f"统一 OS 类型名称: macOS -> mac")
                logger.info(f"os_type_lower = {os_type_lower}, 检查是否需要获取 banner")
                if 'linux' in os_type_lower or 'mac' in os_type_lower:
                    logger.info(f"进入 Linux/macOS banner 获取分支，准备调用 _get_image_banner")
                    banner = self._get_image_banner(file_path, os_type)
                    logger.info(f"_get_image_banner 返回，banner={'有' if banner else '无'}")
                    if banner:
                        self._cached_banner = banner
                        logger.info(f"获取到 banner: {banner[:100]}...")
                    else:
                        logger.warning(f"未能获取 {os_type} 的 banner")
                elif 'windows' in os_type_lower:
                    logger.info(f"进入 Windows 分支，banner 设为 None")
                    banner = None
                else:
                    logger.warning(f"未知的 os_type_lower: {os_type_lower}")
            elif not os_type:
                logger.info("缓存未命中，执行检测...")
                os_type = self._detect_os_type(file_path)

                if os_type and os_type.lower() not in ['windows']:
                    banner = self._get_image_banner(file_path, os_type)
                    if banner:
                        self._cached_banner = banner
                elif os_type and os_type.lower() == 'windows':
                    banner = None

            needs_symbol = False
            symbol_info = None
            kernel_version = None
            kernel_symbol_exists = None

            os_type_lower = os_type.lower() if os_type else 'unknown'

            if ('linux' in os_type_lower or 'mac' in os_type_lower) and banner:
                kernel_version = self._extract_kernel_version(banner, os_type_lower)

                if kernel_version:
                    kernel_symbol_exists = self._check_symbol_exists(os_type_lower, kernel_version)

                    if not kernel_symbol_exists:
                        needs_symbol = True
                        symbol_info = {
                            'os_type': os_type_lower,
                            'kernel_version': kernel_version
                        }
                        logger.info(f"检测到需要符号表: {os_type_lower} {kernel_version}")
            self.current_image = {
                'path': file_path,
                'name': os.path.basename(file_path),
                'hash': project_key,
                'cache_fingerprint': cache_fingerprint,
                'hash_type': 'sampled-cache-fingerprint-v1',
                'size': file_size,
                'os_type': os_type,
                'banner': banner,
                'loaded_at': datetime.now().isoformat()
            }

            current_windows_pdb = {}
            if 'windows' in os_type_lower:
                windows_info = self._get_windows_symbol_info_fast()
                current_windows_pdb = windows_info.get('pdb_info') or {}
                windows_match = bool(current_windows_pdb.get('symbol_exists'))
                needs_symbol = not windows_match
                if needs_symbol:
                    symbol_info = {
                        'os_type': 'windows',
                        'kernel_version': None,
                        'pdb_info': current_windows_pdb,
                    }
                    logger.info("检测到 Windows 镜像，但当前 PDB 没有匹配的本地符号表")

            if 'windows' in os_type_lower and current_windows_pdb.get('symbol_exists'):
                symbol_file = (
                    f"{current_windows_pdb.get('name')} "
                    f"({current_windows_pdb.get('guid')}-{current_windows_pdb.get('age')})"
                )
            elif 'windows' in os_type_lower:
                symbol_file = None
            else:
                symbol_file = self._get_symbol_file_name()
            if symbol_file:
                self.current_image['symbol_file'] = symbol_file
            else:
                self.current_image['symbol_file'] = '未安装'

            self._load_flag_search_cache_from_file()

            project_cache_dir = self._get_image_cache_dir()
            project_info_file = project_cache_dir / 'project_info.json'
            project_info = {
                'name': self.current_image['name'],
                'path': file_path,
                'hash': project_key,
                'cache_fingerprint': cache_fingerprint,
                'hash_type': 'sampled-cache-fingerprint-v1',
                'size': self._format_size(file_size),
                'os_type': os_type,
                'banner': banner,
                'banner_scanned': bool(
                    not banner
                    and os_type
                    and ('linux' in os_type.lower() or 'mac' in os_type.lower())
                    and self._last_banner_scan_completed
                ),
                'pdb_info': current_windows_pdb or None,
                'loaded_at': self.current_image['loaded_at'],
                'last_accessed': datetime.now().isoformat()
            }
            with open(project_info_file, 'w', encoding='utf-8') as f:
                json.dump(project_info, f, ensure_ascii=False, indent=2)

            logger.info(f"成功加载镜像: {self.current_image['name']} ({file_size} bytes), from_cache={from_cache}")

            has_symbols = False
            symbol_count = 0
            if 'linux' in os_type_lower or 'mac' in os_type_lower or 'windows' in os_type_lower:
                if 'mac' in os_type_lower:
                    symbol_dir_name = 'mac'
                elif 'windows' in os_type_lower:
                    symbol_dir_name = 'windows'
                else:
                    symbol_dir_name = 'linux'
                symbol_dir = self._get_os_symbols_dir(symbol_dir_name)
                if 'windows' in os_type_lower:
                    has_symbols = bool(current_windows_pdb.get('symbol_exists'))
                    symbol_count = 1 if has_symbols else 0
                elif symbol_dir.exists():
                    symbol_files = self._get_valid_symbol_files(symbol_dir_name)
                    symbol_count = len(symbol_files)
                    has_symbols = symbol_count > 0
                logger.info(f"符号表检查: OS={os_type_lower}, has_symbols={has_symbols}, count={symbol_count}")

            os_types = {}
            if 'linux' in os_type_lower or 'mac' in os_type_lower or 'windows' in os_type_lower:
                os_types_key = symbol_dir_name  
                os_types[os_types_key] = {
                    'installed': has_symbols,
                    'count': symbol_count
                }
                if 'windows' in os_type_lower:
                    os_types[os_types_key]['pdb_info'] = current_windows_pdb
                elif kernel_version:
                    os_types[os_types_key]['kernel_version'] = kernel_version
                    os_types[os_types_key]['kernel_symbol_exists'] = bool(kernel_symbol_exists)

            response_data = {
                'name': self.current_image['name'],
                'size': self._format_size(file_size),
                'hash': project_key,
                'cache_fingerprint': cache_fingerprint,
                'hash_type': 'sampled-cache-fingerprint-v1',
                'path': file_path,
                'os_type': os_type,
                'banner': banner,
                'has_symbols': has_symbols,
                'symbol_count': symbol_count,
                'from_cache': from_cache,  
                'os_types': os_types  
            }

            if needs_symbol and symbol_info:
                response_data['needs_symbol'] = True
                response_data['symbol_info'] = symbol_info

            return {
                'status': 'success',
                'data': response_data
            }

        except Exception as e:
            logger.error(f"加载镜像失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_current_image(self) -> Dict[str, Any]:
        if self.current_image:
            return {
                'status': 'success',
                'data': self.current_image
            }
        return {
            'status': 'error',
            'message': '未加载镜像'
        }

    def _get_image_banner(self, file_path: str, os_type: str) -> str:
        logger.info(f"_get_image_banner 被调用: file_path={file_path}, os_type={os_type}")
        self._last_banner_scan_completed = False

        if self._cached_banner:
            is_valid = (
                self._cached_banner and
                self._cached_banner not in ['Banner', 'banner', '有'] and
                len(self._cached_banner) > 20 and  
                ('Linux' in self._cached_banner or 'Darwin' in self._cached_banner or 'Windows' in self._cached_banner)
            )
            if is_valid:
                logger.info(f"使用缓存的 banner: {self._cached_banner[:100]}...")
                return self._cached_banner
            else:
                logger.warning(f"缓存的 banner 无效，重新获取: {self._cached_banner}")
                self._cached_banner = None  

        banner, completed = self._get_banner_streaming(file_path)
        self._last_banner_scan_completed = completed
        if banner:
            self._cached_banner = banner
            return banner

        return ''

    def _get_banner_streaming(self, file_path: str) -> tuple:
        import subprocess
        import os
        import platform
        import threading

        try:
            vol_path = self._get_vol_path()
            if not vol_path:
                logger.warning("找不到 vol 命令")
                return '', False

            logger.info(f"使用流式读取获取 banner: {file_path}")

            cmd = [str(vol_path), '-f', file_path, 'banners.Banners']

            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'

            if platform.system() == 'Windows':
                import subprocess
                try:
                    from win32api import GetShortPathName
                    cmd = [GetShortPathName(arg) if isinstance(arg, str) and ('\\' in arg or '/' in arg) else arg for arg in cmd]
                except ImportError:
                    pass

            popen_kwargs = {
                'stdout': subprocess.PIPE,
                'stderr': subprocess.STDOUT,
                'text': True,
                'encoding': 'utf-8',
                'errors': 'replace',
                'env': env
            }
            if platform.system() == 'Windows':
                popen_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            process = subprocess.Popen(cmd, **popen_kwargs)

            banner = None

            for line in process.stdout:
                if line.strip().startswith('0x'):
                    parts = line.strip().split('\t', 1)
                    if len(parts) >= 2:
                        banner = parts[1].strip()
                        if banner and len(banner) > 10:
                            logger.info(f"流式读取获取到 banner: {banner[:100]}...")
                            process.terminate()
                            try:
                                process.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                process.kill()
                            return banner, True

            process.wait(timeout=10)

            if not banner:
                logger.warning("流式读取未获取到 banner")

            return banner or '', True

        except Exception as e:
            logger.warning(f"流式获取 banner 失败: {str(e)}", exc_info=True)
            return '', False

    def _extract_kernel_version(self, banner: str, os_type: str) -> str:
        import re

        os_type_lower = os_type.lower()
        if 'mac' in os_type_lower:
            os_type_for_check = 'mac'
        elif 'linux' in os_type_lower:
            os_type_for_check = 'linux'
        elif 'windows' in os_type_lower:
            os_type_for_check = 'windows'
        else:
            os_type_for_check = os_type_lower

        if os_type_for_check == 'linux':
            match = re.search(r'Linux version\s+(\S+)', banner)
            if match:
                return match.group(1)

        elif os_type_for_check == 'windows':
            match = re.search(r'Windows Version\s+(\d+)', banner)
            if match:
                return match.group(1)

        elif os_type_for_check == 'mac':
            match = re.search(r'Darwin Kernel Version\s+([\d.]+)', banner)
            if match:
                return match.group(1)

        return ''

    def _extract_kernel_version_from_banner(self) -> str:
        try:
            import re

            if not self.current_image:
                return None

            banner = self._cached_banner or self.current_image.get('banner', '')

            if not banner:
                from backend.volatility_wrapper import VolatilityWrapper
                logger.info("缓存中无 banner，执行 banners 获取...")
                wrapper = VolatilityWrapper(self.current_image['path'], self.current_image.get('os_type'), self._get_python_cmd(), symbols_dir=self._get_symbols_base_dir(self.current_image.get('os_type')), cache_path=self._cache_path)
                result = wrapper._run_volatility('banners.Banners', [], use_custom_plugins=False, use_symbols=False)

                if result and len(result) > 0:
                    banner = result[0].get('banner', '')
                    logger.info(f"提取内核版本，Banner: {banner[:200]}...")
                    if banner:
                        self._cached_banner = banner
                else:
                    return None
            else:
                logger.info(f"使用缓存的 banner 提取内核版本")

            if 'Linux version' in banner:
                match = re.search(r'Linux version\s+(\S+)', banner)
                if match:
                    version = match.group(1)
                    logger.info(f"提取到 Linux 内核版本: {version}")
                    return version

            elif 'Darwin Kernel Version' in banner:
                match = re.search(r'Darwin Kernel Version\s+([\d.]+)', banner)
                if match:
                    version = match.group(1)
                    logger.info(f"提取到 macOS 内核版本: {version}")
                    return version

            return None
        except Exception as e:
            logger.warning(f"提取内核版本失败: {str(e)}")
            return None

    def _load_pdb_info_from_file(
        self,
        symbol_status: dict,
        allow_deep_scan: bool = True,
        image_paths: Optional[List[str]] = None,
    ) -> bool:
        try:
            pdb_info_path = self._get_os_symbols_dir('windows') / 'pdb_info.json'
            logger.info(f"尝试读取 pdb_info.json: {pdb_info_path}, 存在: {pdb_info_path.exists()}")

            if not pdb_info_path.exists():
                return False

            import json
            saved_data = json.loads(pdb_info_path.read_text())
            logger.info(f"pdb_info.json 内容已读取，顶层键: {list(saved_data.keys())}")

            if 'pdbs' in saved_data:
                current_image_path = self.current_image.get('path') if self.current_image else None
                if not current_image_path:
                    logger.info("没有当前镜像信息，无法匹配 PDB")
                    return False

                matching_paths = {
                    self._normalized_image_path(path)
                    for path in ([current_image_path] + list(image_paths or []))
                    if path
                }

                logger.info(f"当前镜像路径 = {current_image_path}")
                logger.info(f"pdb_info.json 中的键 = {list(saved_data.get('pdbs', {}).keys())}")

                for key, pdb_info in saved_data.get('pdbs', {}).items():
                    logger.info(f"检查键 '{key}' 是否匹配当前镜像")
                    if self._normalized_image_path(key) in matching_paths:
                        pdb_name = pdb_info.get('pdb_name')
                        guid = pdb_info.get('guid')
                        age = pdb_info.get('age')

                        symbol_path = self._find_matching_windows_symbol(
                            pdb_name, guid, age, allow_deep_scan=allow_deep_scan
                        )
                        is_match = bool(symbol_path and symbol_path.exists())

                        symbol_status['windows']['pdb_info'] = {
                            'name': pdb_name,
                            'guid': guid,
                            'age': age,
                            'symbol_exists': is_match,
                            'symbol_path': str(symbol_path) if is_match else None
                        }
                        logger.info(f"从文件读取 PDB 信息（新格式）: {pdb_name} - {guid}-{age}, 符号表匹配: {is_match}")
                        return True
                    elif (
                        pdb_info.get('image_path')
                        and self._normalized_image_path(pdb_info.get('image_path')) in matching_paths
                    ):
                        guid = pdb_info.get('guid')
                        age = pdb_info.get('age')

                        symbol_path = self._find_matching_windows_symbol(
                            key, guid, age, allow_deep_scan=allow_deep_scan
                        )
                        is_match = bool(symbol_path and symbol_path.exists())

                        symbol_status['windows']['pdb_info'] = {
                            'name': key,
                            'guid': guid,
                            'age': age,
                            'symbol_exists': is_match,
                            'symbol_path': str(symbol_path) if is_match else None
                        }
                        logger.info(f"从文件读取 PDB 信息（旧格式）: {key} - {guid}-{age}, 符号表匹配: {is_match}")
                        return True

                logger.info("未找到匹配的 PDB 信息")
                return False

            elif (
                saved_data.get('image_path')
                and self._normalized_image_path(saved_data.get('image_path'))
                in {
                    self._normalized_image_path(path)
                    for path in (
                        [self.current_image.get('path') if self.current_image else None]
                        + list(image_paths or [])
                    )
                    if path
                }
            ):
                pdb_name = saved_data.get('name')
                guid = saved_data.get('guid')
                age = saved_data.get('age')

                symbol_path = self._find_matching_windows_symbol(
                    pdb_name, guid, age, allow_deep_scan=allow_deep_scan
                )
                is_match = bool(symbol_path and symbol_path.exists())

                symbol_status['windows']['pdb_info'] = {
                    'name': pdb_name,
                    'guid': guid,
                    'age': age,
                    'symbol_exists': is_match,
                    'symbol_path': str(symbol_path) if is_match else None
                }
                logger.info(f"从文件读取旧格式 PDB 信息: {pdb_name} - {guid}-{age}, 符号表匹配: {is_match}")
                return True

            return False

        except Exception as e:
            logger.warning(f"从文件读取 PDB 信息失败: {e}")
            return False

    def _scan_pdb_and_save(self, symbol_status: dict, allow_deep_scan: bool = True) -> bool:
        try:
            if not self.current_image:
                return False

            python_cmd = self._get_python_cmd()
            image_path = self.current_image['path']
            logger.info(f"通过子进程扫描 PDB 信息: {image_path}")

            scan_script = '''
import sys, os, json
from pathlib import Path

try:
    from volatility3.framework.symbols.windows import pdbutil
    from volatility3.framework import contexts
    from volatility3.framework.layers import physical
except ImportError:
    print("IMPORT_ERROR")
    sys.exit(1)

image_path = os.environ.get("LENS_IMAGE_PATH")
if not image_path or not os.path.exists(image_path):
    print("NO_IMAGE")
    sys.exit(1)

try:
    context = contexts.Context()
    try:
        file_url = Path(image_path).absolute().as_uri()
    except Exception:
        import urllib.request
        file_url = 'file://' + urllib.request.pathname2url(image_path)

    context.config['FileLayer.location'] = file_url
    layer = physical.FileLayer(context, 'FileLayer', name="FileLayer")
    context.add_layer(layer)

    pdb_names = [b'ntkrnlmp.pdb', b'ntoskrnl.pdb', b'krnl.pdb', b'ntkrpamp.pdb']
    for result in pdbutil.PDBUtility.pdbname_scan(
        context, layer.name, 0x1000, pdb_names, maximum_invalid_count=10000
    ):
        guid = result.get('GUID', '')
        age = result.get('age', 0)
        pdb_name = result.get('pdb_name', '')
        if guid and pdb_name:
            print(json.dumps({"pdb_name": pdb_name, "guid": guid, "age": age}))
            sys.exit(0)

    print("NOT_FOUND")
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
'''

            import subprocess
            import tempfile

            script_path = Path(tempfile.gettempdir()) / f'lens_pdb_scan_{os.getpid()}.py'
            script_path.write_text(scan_script, encoding='utf-8')

            try:
                subprocess_kwargs = self._get_subprocess_kwargs(
                    capture_output=True, text=True, timeout=60,
                    env={**os.environ, 'LENS_IMAGE_PATH': image_path}
                )

                result = subprocess.run(
                    [python_cmd, str(script_path)],
                    **subprocess_kwargs
                )

                if result.returncode != 0 or not result.stdout.strip():
                    logger.info(f"PDB 扫描子进程未返回结果: {result.stdout.strip()[:100] if result.stdout.strip() else '(empty)'}")
                    return False

                output = result.stdout.strip().split('\n')[-1]

                if output in ('IMPORT_ERROR', 'NO_IMAGE', 'NOT_FOUND'):
                    logger.info(f"PDB 扫描结果: {output}")
                    return False

                if output.startswith('ERROR:'):
                    logger.warning(f"PDB 扫描出错: {output}")
                    return False

                pdb_data = json.loads(output)
                pdb_name = pdb_data['pdb_name']
                guid = pdb_data['guid']
                age = pdb_data['age']

                symbol_path = self._find_matching_windows_symbol(
                    pdb_name, guid, age, allow_deep_scan=allow_deep_scan
                )
                is_match = bool(symbol_path and symbol_path.exists())

                logger.info(f"子进程扫描 PDB: {pdb_name} - {guid}-{age}, 符号表匹配: {is_match}")

                symbol_status['windows']['pdb_info'] = {
                    'name': pdb_name,
                    'guid': guid,
                    'age': age,
                    'symbol_exists': is_match,
                    'symbol_path': str(symbol_path) if is_match else None
                }

                self._save_pdb_info(image_path, pdb_name, guid, age)

                return True

            finally:
                try:
                    script_path.unlink()
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"子进程扫描 PDB 失败: {e}")
            return False

    def _save_pdb_info(self, image_path: str, pdb_name: str, guid: str, age: int):
        try:
            import json as _json
            pdb_info_path = self._get_os_symbols_dir('windows') / 'pdb_info.json'

            saved_data = {}
            if pdb_info_path.exists():
                try:
                    saved_data = _json.loads(pdb_info_path.read_text(encoding='utf-8'))
                except Exception:
                    saved_data = {}

            if 'pdbs' not in saved_data:
                saved_data['pdbs'] = {}

            saved_data['pdbs'][image_path] = {
                'pdb_name': pdb_name,
                'guid': guid,
                'age': age,
                'image_path': image_path
            }

            pdb_info_path.parent.mkdir(parents=True, exist_ok=True)
            pdb_info_path.write_text(_json.dumps(saved_data, indent=2, ensure_ascii=False), encoding='utf-8')
            logger.info(f"已保存 PDB 信息到: {pdb_info_path}")

        except Exception as e:
            logger.warning(f"保存 PDB 信息失败: {e}")

    def _get_windows_symbol_info_fast(
        self, cached_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        status = {
            'windows': {
                'installed': False,
                'count': 0,
            }
        }
        cached_info = cached_info or {}
        cached_pdb = cached_info.get('pdb_info')
        if isinstance(cached_pdb, dict):
            pdb_name = cached_pdb.get('name') or cached_pdb.get('pdb_name')
            guid = cached_pdb.get('guid')
            age = cached_pdb.get('age')
            if pdb_name and guid and age is not None:
                symbol_path = self._find_matching_windows_symbol(
                    pdb_name, guid, age, allow_deep_scan=False
                )
                is_match = bool(symbol_path and symbol_path.exists())
                status['windows']['pdb_info'] = {
                    'name': pdb_name,
                    'guid': guid,
                    'age': age,
                    'symbol_exists': is_match,
                    'symbol_path': str(symbol_path) if is_match else None,
                }
                status['windows']['installed'] = is_match
                status['windows']['count'] = 1 if is_match else 0
                return status['windows']

        previous_path = cached_info.get('path')
        found = self._load_pdb_info_from_file(
            status,
            allow_deep_scan=False,
            image_paths=[previous_path] if previous_path else None,
        )
        if not found:
            self._scan_pdb_and_save(status, allow_deep_scan=False)

        pdb_info = status['windows'].get('pdb_info') or {}
        is_match = bool(pdb_info.get('symbol_exists'))
        status['windows']['installed'] = is_match
        status['windows']['count'] = 1 if is_match else 0
        return status['windows']

    def _check_windows_symbols(self) -> bool:
        try:
            symbol_files = self._get_valid_symbol_files('windows')
            has_symbols = bool(symbol_files)

            if has_symbols:
                logger.info(f"找到 {len(symbol_files)} 个 Windows 符号表文件")

            return has_symbols
        except Exception as e:
            logger.warning(f"检查 Windows 符号表失败: {str(e)}")
            return False

    def _find_matching_kernel_symbol(self, os_type: str, kernel_version: str) -> Optional[Path]:
        try:
            os_type = self._normalize_os_type(os_type)
            symbol_dir = self._get_os_symbols_dir(os_type)
            search_dirs = self._get_os_symbol_search_dirs(os_type)
            if not any(path.exists() for path in search_dirs):
                return None

            search_versions = [kernel_version]
            if os_type == 'mac':
                self._fix_macos_symbol_files(symbol_dir)

                darwin_to_macos = {
                    '16.': '10.12', '17.': '10.13', '18.': '10.14',
                    '19.': '10.15', '20.': '11.0', '21.': '12.0',
                    '22.': '13.0', '23.': '14.0'
                }
                for darwin_prefix, macos in darwin_to_macos.items():
                    if kernel_version.startswith(darwin_prefix):
                        search_versions.append(macos)
                        break

            kernel_version_normalized = kernel_version.replace('_', '-').replace(' ', '-')

            candidates = self._get_valid_symbol_files(os_type)
            symbol_info = {'kernel_version': kernel_version}
            matching = []
            for file_path in candidates:
                file_name = file_path.name
                if any(version in file_name or kernel_version_normalized in file_name for version in search_versions):
                    matching.append(file_path)
                    continue
                try:
                    with open(file_path, 'rb') as stream:
                        prefix = self._read_symbol_candidate_prefix(stream, file_path.name)
                    if self._symbol_candidate_matches_current(file_name, prefix, os_type, symbol_info):
                        matching.append(file_path)
                except (OSError, ValueError):
                    continue

            seen = set()
            for search_dir in search_dirs:
                if not search_dir.exists():
                    continue
                for file_path in matching:
                    try:
                        file_path.relative_to(search_dir)
                    except ValueError:
                        continue
                    resolved = str(file_path.resolve())
                    if resolved in seen:
                        continue
                    seen.add(resolved)
                    target = symbol_dir / file_path.name
                    if file_path.resolve() != target.resolve(strict=False):
                        target = self._materialize_symbol_compatibility_path(file_path, target)
                        logger.info(f'已兼容平铺 {os_type} 符号表: {file_path} -> {target}')
                    if os_type == 'mac':
                        self._fix_macos_symbol_files(symbol_dir)
                    logger.info(f"找到匹配的符号表: {target.name}")
                    return target

            logger.info(f"未找到匹配内核版本 {kernel_version} 的符号表")
            return None

        except Exception as e:
            logger.warning(f"检查符号表失败: {str(e)}")
            return None

    def _check_symbol_exists(self, os_type: str, kernel_version: str) -> bool:
        try:
            return self._find_matching_kernel_symbol(os_type, kernel_version) is not None
        except Exception as e:
            logger.warning(f"检查符号表失败: {str(e)}")
            return False


    @staticmethod
    def normalize_plugin_id(plugin_id: str) -> str:
        from backend.plugin_registry import normalize_plugin_id
        return normalize_plugin_id(plugin_id)

    @staticmethod
    def get_plugin_full_name(plugin_id: str) -> str:
        from backend.plugin_registry import resolve_plugin
        _, full_name = resolve_plugin(plugin_id)
        return full_name

    def run_analysis(self, plugin_id: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            requested_plugin_id = plugin_id
            plugin_id = self.normalize_plugin_id(plugin_id)
            if plugin_id != requested_plugin_id:
                logger.info(f"归一化分析插件 ID: {requested_plugin_id} -> {plugin_id}")

            os_type = self.current_image.get('os_type', 'Unknown')
            is_compatible, error_msg = self._check_plugin_compatibility(plugin_id, os_type)

            if not is_compatible:
                logger.warning(f"插件 {plugin_id} 与 {os_type} 系统不兼容")
                return {
                    'status': 'error',
                    'message': error_msg,
                    'code': 'INCOMPATIBLE_PLUGIN'
                }

            logger.info(f"开始执行分析: {plugin_id} (系统: {os_type})")

            self.task_counter += 1
            task_id = f"task_{self.task_counter}"

            self.analysis_tasks[task_id] = {
                'id': task_id,
                'plugin': plugin_id,
                'params': params or {},
                'status': 'running',
                'started_at': datetime.now().isoformat()
            }

            cache_key = self._get_cache_key(plugin_id, params)

            cached_result = self._load_from_cache_file(cache_key)
            filescan_cache_plugins = {'filescan', 'eventlog'}
            netscan_cache_plugins = {'netscan'}
            if cached_result:
                if plugin_id in filescan_cache_plugins and cached_result.get('_cache_format_version') != 'filescan_utf8_json_v1':
                    logger.info(f"忽略旧版 {plugin_id} 缓存，将重新执行以避免 Windows 文本编码导致的半截结果")
                elif plugin_id in netscan_cache_plugins and cached_result.get('_cache_format_version') != 'netscan_netstat_fallback_v2':
                    logger.info("忽略旧版 netscan 缓存，将重新执行以支持 netstat 后备解析")
                else:
                    logger.info(f"从缓存加载结果: {plugin_id}")
                    self.analysis_tasks[task_id]['status'] = 'completed'
                    self.analysis_tasks[task_id]['from_cache'] = True
                    self.analysis_tasks[task_id]['completed_at'] = datetime.now().isoformat()

                    return {
                        'status': 'success',
                        'task_id': task_id,
                        'data': cached_result,
                        'cached': True
                    }

            ai_task_id = getattr(self._ai_task_context, 'task_id', None)
            if ai_task_id:
                self._set_ai_task_progress(ai_task_id, {
                    'message': f'正在执行 {plugin_id}',
                    'current': 3,
                    'total': 4,
                    'updated_at': datetime.now().isoformat(),
                })
            result = self._execute_plugin(plugin_id, params)

            if result.get('success') is False and result.get('error_type') == 'dependency_missing':
                error_msg = result.get('error', '依赖缺失')
                missing_dep = result.get('missing_dependency', 'unknown')
                logger.warning(f"插件 {plugin_id} 缺少依赖: {missing_dep}")
                self.analysis_tasks[task_id]['status'] = 'failed'
                self.analysis_tasks[task_id]['completed_at'] = datetime.now().isoformat()
                return {
                    'status': 'error',
                    'task_id': task_id,
                    'message': error_msg,
                    'error_type': 'dependency_missing',
                    'missing_dependency': missing_dep
                }

            results = result.get('results', [])
            if result.get('error') and not results:
                error_msg = str(result.get('error'))
                logger.warning(f"插件执行失败: {plugin_id}, {error_msg}")
                self.analysis_tasks[task_id]['status'] = 'failed'
                self.analysis_tasks[task_id]['completed_at'] = datetime.now().isoformat()
                return {
                    'status': 'error',
                    'task_id': task_id,
                    'message': error_msg,
                    'error_type': 'plugin_error',
                }
            if results and results[0].get('_error'):
                error_type = results[0].get('_error')
                error_msg = results[0].get('_message', '未知错误')
                logger.warning(f"插件执行失败: {plugin_id}, 错误类型: {error_type}")
                self.analysis_tasks[task_id]['status'] = 'failed'
                self.analysis_tasks[task_id]['completed_at'] = datetime.now().isoformat()

                if error_type in ['pycryptodome_missing', 'pypykatz_missing', 'dependency_missing']:
                    missing_dep = error_type.replace('_missing', '')
                    return {
                        'status': 'error',
                        'task_id': task_id,
                        'message': error_msg,
                        'error_type': 'dependency_missing',
                        'missing_dependency': missing_dep
                    }

                return {
                    'status': 'error',
                    'task_id': task_id,
                    'message': error_msg,
                    'error_type': error_type
                }

            logger.info(f"分析完成: {plugin_id}, 结果数量: {len(results)}")

            if plugin_id == 'svcscan' and len(results) == 0:
                logger.warning("svcscan 返回空结果，尝试使用注册表方式获取服务列表")
                registry_result = self._get_services_from_registry()
                if registry_result:
                    result = registry_result
                    result['_info'] = '通过注册表获取服务列表'
                    results = result.get('results', [])

            if plugin_id == 'netscan' and len(results) == 0:
                logger.info("netscan 返回空结果，尝试使用 netstat 作为网络连接后备")
                fallback_result = self._execute_plugin('netstat', params)
                fallback_results = fallback_result.get('results') or []
                fallback_error = None
                if fallback_results and fallback_results[0].get('_error'):
                    fallback_error = fallback_results[0].get('_message') or fallback_results[0].get('_error')
                    fallback_results = []

                if fallback_results:
                    result = fallback_result
                    result['plugin'] = 'netscan'
                    result['_source_plugin'] = 'netstat'
                    result['_info'] = (
                        'netscan 未恢复出连接记录，已自动使用 netstat 后备解析。'
                        '该结果依赖 tcpip.pdb 符号，通常对 Windows 11 24H2/26100 等较新镜像更可靠。'
                    )
                    results = fallback_results
                    logger.info(f"netstat 后备解析成功，恢复网络连接记录: {len(results)} 条")
                elif fallback_error:
                    result['_fallback_error'] = fallback_error
                    logger.info(f"netstat 后备解析未获得结果: {fallback_error}")

            if plugin_id in filescan_cache_plugins:
                result['_cache_format_version'] = 'filescan_utf8_json_v1'
            if plugin_id in netscan_cache_plugins:
                result['_cache_format_version'] = 'netscan_netstat_fallback_v2'
                if len(result.get('results') or []) == 0 and not result.get('_info'):
                    result['_info'] = (
                        'netscan 执行成功，但 Volatility 只输出了表头，没有发现网络连接记录。'
                        '这不一定表示系统没有联网，也可能是该系统版本/采集时机下 netscan 无法可靠恢复网络对象。'
                    )

            self._save_to_cache_file(cache_key, result)

            self.analysis_tasks[task_id]['status'] = 'completed'
            self.analysis_tasks[task_id]['from_cache'] = False
            self.analysis_tasks[task_id]['completed_at'] = datetime.now().isoformat()

            return {
                'status': 'success',
                'task_id': task_id,
                'data': result,
                'cached': False
            }

        except Exception as e:
            logger.error(f"分析失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def run_analysis_with_params(self, plugin_id: str, params: Dict) -> Dict[str, Any]:
        return self.run_analysis(plugin_id, params)

    def run_analysis_paged(
        self,
        plugin_id: str,
        params: Optional[Dict] = None,
        offset: int = 0,
        limit: int = 200,
        keyword: str = '',
        frontend_task_id: str = ''
    ) -> Dict[str, Any]:
        try:
            offset = max(0, int(offset or 0))
            limit = max(1, min(int(limit or 200), 500))
            keyword = str(keyword or '').strip()
            task_id = str(frontend_task_id or '').strip()
            cache_key = self._get_cache_key(plugin_id, params)
            source_file = f'{cache_key}.json'

            cached = self._load_from_cache_file(cache_key)
            if cached:
                rows = cached.get('results') if isinstance(cached, dict) else []
                rows = rows or []
                if keyword:
                    rows = [
                        row for row in rows
                        if self._row_contains_keyword(row, keyword)
                    ]
                total = len(rows)
                page = rows[offset:offset + limit]
                return {
                    'status': 'success',
                    'task_id': '',
                    'cached': True,
                    'data': {
                        **cached,
                        'results': page,
                        'paged': True,
                        'offset': offset,
                        'limit': limit,
                        'total_count': total,
                        'source_file': source_file,
                        'keyword': keyword,
                    }
                }

            if offset > 0:
                return {'status': 'error', 'message': '结果尚未生成，请先执行插件'}

            self._plugin_task_context.task_id = task_id
            try:
                result = self.run_analysis(plugin_id, params)
            finally:
                self._plugin_task_context.task_id = None

            if result.get('status') != 'success':
                return result

            data = result.get('data') or {}
            rows = data.get('results') or []
            if keyword:
                rows = [
                    row for row in rows
                    if self._row_contains_keyword(row, keyword)
                ]
            total = len(rows)
            page = rows[offset:offset + limit]
            return {
                **result,
                'data': {
                    **data,
                    'results': page,
                    'paged': True,
                    'offset': offset,
                    'limit': limit,
                    'total_count': total,
                    'source_file': source_file,
                    'keyword': keyword,
                }
            }
        except Exception as e:
            logger.error(f"分页执行插件失败: {e}")
            return {'status': 'error', 'message': f'分页执行插件失败: {str(e)}'}

    def _execute_plugin(self, plugin_id: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        from backend.volatility_wrapper import VolatilityWrapper

        wrapper = VolatilityWrapper(self.current_image['path'], self.current_image.get('os_type'), self._get_python_cmd(), symbols_dir=self._get_symbols_base_dir(self.current_image.get('os_type')), cache_path=self._cache_path)
        self._register_analysis_wrapper(wrapper)

        symbol_file_path = None
        os_type = self.current_image.get('os_type', '').lower()

        if 'mac' in os_type:
            symbol_dir_name = 'mac'
        elif 'linux' in os_type:
            symbol_dir_name = 'linux'
        elif 'windows' in os_type:
            symbol_dir_name = 'windows'
        else:
            symbol_dir_name = None

        if symbol_dir_name:
            symbol_dir = self._get_os_symbols_dir(symbol_dir_name)

            if 'mac' in os_type and symbol_dir.exists():
                self._fix_macos_symbol_files(symbol_dir)

            matched_symbol = None
            if 'windows' in os_type:
                status_result = self.get_symbol_status()
                windows_info = (
                    ((status_result.get('data') or {}).get('os_types') or {}).get('windows') or {}
                )
                pdb_info = windows_info.get('pdb_info') or {}
                candidate = Path(pdb_info['symbol_path']) if pdb_info.get('symbol_path') else None
                if pdb_info.get('symbol_exists') and candidate and self._is_volatility_isf_file(candidate):
                    matched_symbol = candidate
            else:
                banner = self.current_image.get('banner', '')
                kernel_version = self._extract_kernel_version(banner, symbol_dir_name) if banner else None
                if kernel_version:
                    matched_symbol = self._find_matching_kernel_symbol(symbol_dir_name, kernel_version)

            if matched_symbol:
                symbol_file_path = str(matched_symbol)
                logger.info(f"[{os_type.upper()}] 使用当前镜像匹配符号表: {matched_symbol.name}")
            else:
                logger.info(f"[{os_type.upper()}] 当前镜像无匹配符号表，将尝试 Volatility 自动下载")

        try:
            result = wrapper.run_plugin(plugin_id, params or {}, symbol_file_path=symbol_file_path)
            return result
        finally:
            self._unregister_analysis_wrapper(wrapper)

    def _fix_macos_symbol_files(self, symbol_dir: Path) -> None:
        try:
            import re

            file_patterns = [
                'macOS_KDK_*.json.xz',           
                'Kernel_Debug_Kit_*.json.xz',    
                'kernel_debug_kit_*.json.xz',    
                'KernelDebugKit_*.json.xz',      
                'macOS10*.json.xz',              
            ]

            processed_files = set()

            for pattern in file_patterns:
                for symbol_file in symbol_dir.glob(pattern):
                    if symbol_file.is_symlink():
                        continue

                    real_path = symbol_file.resolve()
                    if str(real_path) in processed_files:
                        continue
                    processed_files.add(str(real_path))

                    logger.info(f"处理 macOS 符号表文件: {symbol_file.name}")


                    version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', symbol_file.name)
                    if not version_match:
                        logger.debug(f"无法从文件名提取版本: {symbol_file.name}")
                        continue

                    macos_version = version_match.group(1)
                    logger.info(f"提取的 macOS 版本: {macos_version}")

                    build_match = re.search(r'build[-_]([A-Z]?\d+[A-Z]?\d*)', symbol_file.name, re.IGNORECASE)
                    if build_match:
                        build_number = build_match.group(1)
                        logger.info(f"提取的构建号: {build_number}")
                    else:
                        build_match = re.search(r'(\d+[a-z]+\d+)', symbol_file.name, re.IGNORECASE)
                        build_number = build_match.group(1) if build_match else None
                        logger.info(f"提取的构建号 (备用格式): {build_number}")

                    link_names = []

                    link_names.append(f"mac-{macos_version}.json.xz")
                    link_names.append(f"macOS-{macos_version}.json.xz")

                    if build_number:
                        link_names.append(f"mac-{macos_version}-{build_number}.json.xz")
                        link_names.append(f"macOS_KDK_{macos_version}_build-{build_number}.json.xz")

                    for link_name in link_names:
                        link_path = symbol_dir / link_name
                        if not link_path.exists():
                            try:
                                link_path.symlink_to(symbol_file)
                                logger.info(f"创建符号链接: {link_name} -> {symbol_file.name}")
                            except FileExistsError:
                                pass  
                            except Exception as e:
                                logger.debug(f"创建链接失败 {link_name}: {e}")

        except Exception as e:
            logger.warning(f"修复macOS符号表文件名失败: {e}")

    def get_analysis_status(self, task_id: str) -> Dict[str, Any]:
        if task_id in self.analysis_tasks:
            return {
                'status': 'success',
                'data': self.analysis_tasks[task_id]
            }
        return {
            'status': 'error',
            'message': '任务不存在'
        }


    def check_strings_tool(self) -> Dict[str, Any]:
        try:
            import platform
            import shutil

            system = platform.system()
            has_strings = False
            strings_path = None

            if system == 'Windows':
                possible_paths = [
                    self._user_data_dir / 'strings.exe',
                    Path(os.path.dirname(sys.executable)) / 'strings.exe',
                    'strings.exe'
                ]
                for path in possible_paths:
                    if isinstance(path, str):
                        if shutil.which(path):
                            has_strings = True
                            strings_path = shutil.which(path)
                            break
                    else:
                        if path.exists():
                            has_strings = True
                            strings_path = str(path)
                            break
            else:
                has_strings = shutil.which('strings') is not None
                if has_strings:
                    strings_path = shutil.which('strings')

            return {
                'status': 'success',
                'has_strings': has_strings,
                'platform': system,
                'strings_path': strings_path if has_strings else None
            }
        except Exception as e:
            logger.error(f"检测 strings 工具失败: {e}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def download_strings_tool(self) -> Dict[str, Any]:
        import platform
        import zipfile

        try:
            if platform.system() != 'Windows':
                return {
                    'status': 'error',
                    'message': '此功能仅支持 Windows 系统'
                }

            self._show_loading('正在下载 strings 工具', '正在从微软官方下载...\n\n文件较小，请稍候。')

            exe_path = self._user_data_dir / 'strings.exe'

            if exe_path.exists():
                self._hide_loading()
                return {
                    'status': 'success',
                    'message': 'strings 工具已存在',
                    'already_exists': True
                }

            zip_path = self._user_data_dir / 'Strings.zip'
            url = 'https://download.sysinternals.com/files/Strings.zip'

            logger.info(f"开始下载 strings 工具: {url}")

            try:
                import urllib.request

                proxy_url = self._build_proxy_url()
                if proxy_url:
                    if proxy_url.startswith('socks'):
                        try:
                            import socks
                            import socket as socket_module
                            import ssl

                            _original_create_context = ssl._create_default_https_context

                            def _create_unverified_context():
                                ctx = ssl.create_default_context()
                                ctx.check_hostname = False
                                ctx.verify_mode = ssl.CERT_NONE
                                return ctx

                            ssl._create_default_https_context = _create_unverified_context

                            sock_type = socks.PROXY_TYPE_SOCKS5 if 'socks5' in proxy_url else socks.PROXY_TYPE_SOCKS4
                            proxy_host = self._proxy_config.get('host')
                            proxy_port = self._proxy_config.get('port')
                            proxy_user = self._proxy_config.get('username')
                            proxy_pass = self._proxy_config.get('password')

                            socks.set_default_proxy(sock_type, proxy_host, proxy_port, proxy_user, proxy_pass)
                            socket_module.socket = socks.socksocket

                            urllib.request.urlretrieve(url, zip_path)

                            ssl._create_default_https_context = _original_create_context
                            try:
                                import socket as socket_module2
                                socket_module2.socket = socket_module2._socket.socket
                            except:
                                pass
                        except ImportError:
                            logger.warning("未安装 PySocks 库，尝试直接下载")
                            urllib.request.urlretrieve(url, zip_path)
                    else:
                        proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                        opener = urllib.request.build_opener(proxy_handler)
                        urllib.request.urlretrieve(url, zip_path)
                else:
                    urllib.request.urlretrieve(url, zip_path)

                logger.info(f"下载完成: {zip_path}")

            except Exception as download_error:
                self._hide_loading()
                logger.error(f"下载失败: {download_error}")
                return {
                    'status': 'error',
                    'message': f'下载失败: {str(download_error)}'
                }

            logger.info(f"开始解压: {zip_path}")
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(self._user_data_dir)
                logger.info("解压完成")
            except Exception as extract_error:
                self._hide_loading()
                if zip_path.exists():
                    zip_path.unlink()
                logger.error(f"解压失败: {extract_error}")
                return {
                    'status': 'error',
                    'message': f'解压失败: {str(extract_error)}'
                }

            try:
                zip_path.unlink()
                logger.info(f"已清理临时文件: {zip_path}")
            except:
                pass

            if exe_path.exists():
                self._hide_loading()
                logger.info(f"strings 工具安装成功: {exe_path}")
                return {
                    'status': 'success',
                    'message': 'strings 工具下载成功',
                    'already_exists': False
                }
            else:
                self._hide_loading()
                return {
                    'status': 'error',
                    'message': '下载完成但未找到 strings.exe'
                }

        except Exception as e:
            self._hide_loading()
            logger.error(f"下载 strings 工具失败: {e}", exc_info=True)
            return {
                'status': 'error',
                'message': f'下载失败: {str(e)}'
            }

    def search_flag(self, patterns: List[str] = None, force: bool = False) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if patterns:
                cache_key = 'custom:' + ':'.join(patterns)
                is_custom = True
            else:
                cache_key = 'default'
                is_custom = False

            if cache_key in self._flag_search_cache:
                cache_entry = self._flag_search_cache[cache_key]
                if cache_entry.get('searching', False):
                    return {
                        'status': 'searching',
                        'message': '正在搜索中，请稍候...'
                    }

                if not force and 'results' in cache_entry:
                    logger.info(f"使用缓存的Flag搜索结果: {cache_key}, {len(cache_entry['results'])} 条")
                    return {
                        'status': 'success',
                        'data': {
                            'flags': cache_entry['results'],
                            'count': len(cache_entry['results']),
                            'cached': True,
                            'timestamp': cache_entry.get('timestamp', ''),
                            'pattern': cache_entry.get('pattern', ''),
                            'is_custom': is_custom
                        }
                    }

            self._flag_search_cache[cache_key] = {
                'searching': True,
                'results': [],
                'timestamp': None,
                'pattern': ':'.join(patterns) if patterns else ''
            }

            if not patterns:
                patterns = [
                    r'flag\{[^}]+\}',      
                    r'ctf\{[^}]+\}',       
                    r'key\{[^}]+\}',       
                    r'hgame\{[^}]+\}',     
                    r'actf\{[^}]+\}',      
                    r'qwb\{[^}]+\}',       
                    r'bdctf\{[^}]+\}',     
                    r'ciscn\{[^}]+\}',     
                    r'sctf\{[^}]+\}',      
                    r'xctf\{[^}]+\}',      
                    r'swpu\{[^}]+\}',      
                ]

            import shutil
            import platform
            has_strings = shutil.which('strings') is not None

            if platform.system() == 'Windows' and not has_strings:
                logger.warning("Windows系统未找到strings命令，搜索功能可能受限")

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'], self.current_image.get('os_type'), self._get_python_cmd(), symbols_dir=self._get_symbols_base_dir(self.current_image.get('os_type')), cache_path=self._cache_path)

            results = wrapper.search_strings(patterns)

            self._flag_search_cache[cache_key] = {
                'searching': False,
                'results': results,
                'timestamp': datetime.now().isoformat(),
                'pattern': ':'.join(patterns) if patterns else ''
            }

            self._save_flag_search_cache_to_file()

            logger.info(f"Flag搜索完成: {cache_key}, 找到 {len(results)} 条结果")

            return {
                'status': 'success',
                'data': {
                    'flags': results,
                    'count': len(results),
                    'cached': False,
                    'timestamp': self._flag_search_cache[cache_key]['timestamp'],
                    'pattern': self._flag_search_cache[cache_key]['pattern'],
                    'is_custom': is_custom,
                    'cache_key': cache_key
                }

            }
        except Exception as e:
            logger.error(f"搜索Flag失败: {str(e)}")
            if 'cache_key' in locals() and cache_key in self._flag_search_cache:
                self._flag_search_cache[cache_key]['searching'] = False
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_flag_search_history(self) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            logger.info(f"获取Flag搜索历史，当前镜像有 {len(self._flag_search_cache)} 条记录")

            history = []

            for cache_key, entry in self._flag_search_cache.items():
                if entry.get('searching', False):
                    continue  

                if cache_key == 'default':
                    history.append({
                        'cache_key': cache_key,
                        'pattern': '默认搜索 (flag{xxx}, FLAG{xxx}, ctf{xxx}, CTF{xxx})',
                        'display_name': '默认搜索',
                        'count': len(entry.get('results', [])),
                        'timestamp': entry.get('timestamp', ''),
                        'is_default': True
                    })
                elif cache_key.startswith('custom:'):
                    pattern = entry.get('pattern', cache_key[7:])
                    history.append({
                        'cache_key': cache_key,
                        'pattern': pattern,
                        'display_name': pattern if len(pattern) <= 50 else pattern[:50] + '...',
                        'count': len(entry.get('results', [])),
                        'timestamp': entry.get('timestamp', ''),
                        'is_default': False
                    })

            history.sort(key=lambda x: x['timestamp'], reverse=True)

            return {
                'status': 'success',
                'data': {'history': history}
            }

        except Exception as e:
            logger.error(f"获取搜索历史失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def delete_flag_search_result(self, cache_key: str) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if cache_key in self._flag_search_cache:
                del self._flag_search_cache[cache_key]
                self._save_flag_search_cache_to_file()
                logger.info(f"已删除搜索结果: {cache_key}")
                return {
                    'status': 'success',
                    'message': '已删除搜索结果'
                }

            return {
                'status': 'error',
                'message': '搜索结果不存在'
            }

        except Exception as e:
            logger.error(f"删除搜索结果失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_cached_flag_result(self, cache_key: str) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if cache_key not in self._flag_search_cache:
                return {
                    'status': 'error',
                    'message': f'缓存键不存在: {cache_key}'
                }

            entry = self._flag_search_cache[cache_key]
            if entry.get('searching', False):
                return {
                    'status': 'searching',
                    'message': '正在搜索中...'
                }

            return {
                'status': 'success',
                'data': {
                    'flags': entry.get('results', []),
                    'count': len(entry.get('results', [])),
                    'cached': True,
                    'timestamp': entry.get('timestamp', ''),
                    'pattern': entry.get('pattern', ''),
                    'cache_key': cache_key
                }
            }

        except Exception as e:
            logger.error(f"获取缓存结果失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_flag_search_status(self) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            image_hash = self.current_image.get('hash', '')
            if not image_hash:
                return {
                    'status': 'not_searched',
                    'message': '尚未进行过搜索'
                }

            if image_hash not in self._flag_search_cache:
                return {
                    'status': 'not_searched',
                    'message': '尚未进行过搜索'
                }

            cache_entry = self._flag_search_cache[image_hash]

            if cache_entry.get('searching', False):
                return {
                    'status': 'searching',
                    'message': '正在搜索中...'
                }

            return {
                'status': 'completed',
                'data': {
                    'count': len(cache_entry.get('results', [])),
                    'timestamp': cache_entry.get('timestamp', '')
                }
            }

        except Exception as e:
            logger.error(f"获取搜索状态失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def clear_flag_search_cache(self) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if self._flag_search_cache:
                self._flag_search_cache.clear()
                self._save_flag_search_cache_to_file()
                return {
                    'status': 'success',
                    'message': '缓存已清除'
                }

            return {
                'status': 'success',
                'message': '无需清除（无缓存）'
            }

        except Exception as e:
            logger.error(f"清除缓存失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def _load_flag_search_cache_from_file(self):
        try:
            cache_file = self._get_image_cache_dir() / 'flag_search_cache.json'
            if cache_file.exists():
                with open(cache_file, 'r', encoding='utf-8') as f:
                    self._flag_search_cache = json.load(f)
                logger.info(f"已加载当前镜像的Flag搜索缓存: {len(self._flag_search_cache)} 条记录")
            else:
                logger.info("当前镜像的Flag搜索缓存文件不存在")
                self._flag_search_cache = {}
        except Exception as e:
            logger.warning(f"加载Flag搜索缓存失败: {e}")
            self._flag_search_cache = {}

    def _save_flag_search_cache_to_file(self):
        try:
            cache_dir = self._get_image_cache_dir()
            cache_file = cache_dir / 'flag_search_cache.json'
            cache_dir.mkdir(parents=True, exist_ok=True)
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(self._flag_search_cache, f, ensure_ascii=False, indent=2)
            logger.info(f"Flag搜索缓存已保存到: {cache_file}")
            self._refresh_cache_index_for_file(cache_file)
        except Exception as e:
            logger.warning(f"保存Flag搜索缓存失败: {e}")

    def dump_process_memory(
        self,
        pid: int,
        output_dir: str = None,
        source_plugin: str = None,
        task_id: str = None,
    ) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = self._default_export_dir('processes')

            os.makedirs(output_dir, exist_ok=True)
            process_id = int(pid)
            operation_key = (
                'process',
                os.path.normcase(os.path.abspath(self.current_image['path'])),
                process_id,
                os.path.normcase(os.path.abspath(output_dir)),
                str(source_plugin or '').strip().lower(),
            )
            return self._run_extraction(
                lambda wrapper: wrapper.dump_process(
                    process_id, output_dir, source_plugin=source_plugin
                ),
                task_id,
                operation_key,
            )

        except Exception as e:
            logger.error(f"转储进程内存失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_file(
        self, offset: str, output_dir: str = None, task_id: str = None
    ) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = self._default_export_dir('files')

            os.makedirs(output_dir, exist_ok=True)

            return self._run_extraction(
                lambda wrapper: wrapper.extract_file(str(offset), output_dir),
                task_id,
            )

        except Exception as e:
            logger.error(f"提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_pagecache_file(
        self, file_path: str, output_dir: str = None, task_id: str = None
    ) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = self._default_export_dir('files')

            os.makedirs(output_dir, exist_ok=True)

            file_name = os.path.basename(file_path)
            save_path = os.path.join(output_dir, file_name)

            return self._run_extraction(
                lambda wrapper: wrapper.extract_pagecache_file(file_path, save_path),
                task_id,
            )

        except Exception as e:
            logger.error(f"提取页缓存文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_dll(
        self, pid: str, base: str, output_dir: str = None, task_id: str = None
    ) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = self._default_export_dir('dlls')

            os.makedirs(output_dir, exist_ok=True)

            return self._run_extraction(
                lambda wrapper: wrapper.extract_dll(int(pid), base, output_dir),
                task_id,
            )

        except Exception as e:
            logger.error(f"提取DLL失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_elf_file(
        self,
        pid: str,
        start: str,
        file_name: str,
        output_dir: str = None,
        task_id: str = None,
    ) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = self._default_export_dir('elf')

            os.makedirs(output_dir, exist_ok=True)

            return self._run_extraction(
                lambda wrapper: wrapper.extract_elf_file(
                    int(pid), start, os.path.basename(file_name), output_dir
                ),
                task_id,
            )

        except Exception as e:
            logger.error(f"提取 ELF 文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_lsof_file(
        self,
        file_path: str,
        plugin_id: str,
        output_dir: str = None,
        task_id: str = None,
    ) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = self._default_export_dir('files')

            os.makedirs(output_dir, exist_ok=True)

            return self._run_extraction(
                lambda wrapper: wrapper.extract_lsof_file(
                    file_path, plugin_id, output_dir
                ),
                task_id,
            )

        except Exception as e:
            logger.error(f"提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_lsof_files(
        self, plugin_id: str, output_dir: str = None, task_id: str = None
    ) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = self._default_export_dir('files')

            os.makedirs(output_dir, exist_ok=True)

            return self._run_extraction(
                lambda wrapper: wrapper.extract_lsof_files(plugin_id, output_dir),
                task_id,
            )

        except Exception as e:
            logger.error(f"批量提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_elf_files(
        self, pid: str = None, output_dir: str = None, task_id: str = None
    ) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = self._default_export_dir('elf')

            os.makedirs(output_dir, exist_ok=True)

            pid_int = int(pid) if pid else None
            return self._run_extraction(
                lambda wrapper: wrapper.extract_elf_files(pid_int, output_dir),
                task_id,
            )

        except Exception as e:
            logger.error(f"提取 ELF 文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def dump_file(
        self,
        offset: str,
        output_dir: str,
        file_name: str = None,
        task_id: str = None,
    ) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            os.makedirs(output_dir, exist_ok=True)

            def operation(wrapper):
                result = wrapper.extract_file(offset, output_dir)
                if result.get('status') != 'success' or not file_name:
                    return result

                safe_name = re.split(r'[\\/]', str(file_name))[-1].strip()
                if not safe_name or safe_name in ('.', '..'):
                    return {
                        'status': 'error',
                        'error': '目标文件名无效',
                    }

                old_path = Path(result.get('path') or (Path(output_dir) / result['file']))
                new_path = self._unique_destination_path(Path(output_dir) / safe_name)
                old_path.rename(new_path)
                result['file'] = new_path.name
                result['path'] = str(new_path)
                logger.info(f"文件已重命名为: {new_path.name}")
                return result

            return self._run_extraction(operation, task_id)

        except Exception as e:
            logger.error(f"提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def preview_file(
        self,
        offset: str,
        file_name: str = None,
        max_size: int = 1024 * 1024 * 10  
    ) -> Dict[str, Any]:
        import tempfile

        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            temp_dir = tempfile.gettempdir()
            image_hash = str(self.current_image.get('hash') or 'unknown')
            preview_dir = os.path.join(temp_dir, 'lens_preview', image_hash)
            os.makedirs(preview_dir, exist_ok=True)

            wrapper = self._create_extraction_wrapper()
            self._register_analysis_wrapper(wrapper)
            try:
                result = wrapper.extract_file(offset, preview_dir)
            finally:
                self._unregister_analysis_wrapper(wrapper)

            if result['status'] != 'success':
                return {
                    'status': 'error',
                    'message': result.get('error', '文件提取失败')
                }

            extracted_file = result.get('path') or os.path.join(preview_dir, result['file'])

            if not os.path.exists(extracted_file):
                return {
                    'status': 'error',
                    'message': '提取的文件不存在'
                }

            file_size = os.path.getsize(extracted_file)

            with open(extracted_file, 'rb') as f:
                content = f.read(max_size)

            preview_content = self._bytes_to_hexdump(content)

            _, ext = os.path.splitext(file_name or result['file'])

            return {
                'status': 'success',
                'data': {
                    'file_name': file_name or result['file'],
                    'file_size': file_size,
                    'content_type': 'hexdump',
                    'content': preview_content,
                    'extension': ext.lower(),
                    'truncated': file_size > max_size,
                    'max_size': max_size,
                    'temp_path': extracted_file
                }
            }

        except Exception as e:
            logger.error(f"预览文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def _bytes_to_hexdump(self, content: bytes, bytes_per_line: int = 16) -> str:
        lines = []
        for i in range(0, len(content), bytes_per_line):
            chunk = content[i:i + bytes_per_line]
            offset = f'{i:08X}'
            hex_parts = []
            for j in range(bytes_per_line):
                if j < len(chunk):
                    hex_parts.append(f'{chunk[j]:02X}')
                else:
                    hex_parts.append('  ')
                if j == 7:
                    hex_parts.append('')
            hex_part = ' '.join(hex_parts)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'{offset}  {hex_part}  |{ascii_part}|')
        return '\n'.join(lines)

    def _is_text_content(self, content: bytes) -> bool:
        if not content:
            return True

        sample = content[:512]

        if b'\x00' in sample:
            return False

        try:
            text = sample.decode('utf-8')
            printable_count = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
            return printable_count / len(text) > 0.85
        except:
            try:
                text = sample.decode('latin-1')
                printable_count = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
                return printable_count / len(text) > 0.85
            except:
                return False

    def _bytes_to_hex(self, content: bytes, bytes_per_line: int = 16) -> str:
        lines = []
        for i in range(0, len(content), bytes_per_line):
            chunk = content[i:i + bytes_per_line]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            offset = f'{i:08X}'
            lines.append(f'{offset}  {hex_part:<48}  |{ascii_part}|')
        return '\n'.join(lines)

    def copy_file(
        self,
        source_path: str,
        dest_dir: str,
        new_name: str = None
    ) -> Dict[str, Any]:
        import shutil

        try:
            if not os.path.exists(source_path):
                return {
                    'status': 'error',
                    'message': '源文件不存在'
                }

            os.makedirs(dest_dir, exist_ok=True)

            requested_name = new_name or os.path.basename(source_path)
            file_name = re.split(r'[\\/]', str(requested_name))[-1].strip()
            if not file_name or file_name in ('.', '..'):
                return {'status': 'error', 'message': '目标文件名无效'}
            dest_path = self._unique_destination_path(Path(dest_dir) / file_name)

            shutil.copy2(source_path, str(dest_path))

            return {
                'status': 'success',
                'data': {
                    'source': source_path,
                    'destination': str(dest_path),
                    'file_name': dest_path.name,
                    'file_size': dest_path.stat().st_size
                }
            }

        except Exception as e:
            logger.error(f"复制文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def dump_files(
        self,
        filter_pattern: str = None,
        ignore_case: bool = False,
        pid: str = None,
        output_dir: str = None,
        task_id: str = None,
    ) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = self._default_export_dir('linux_filesystem')

            os.makedirs(output_dir, exist_ok=True)

            pid_int = int(pid) if pid else None
            response = self._run_extraction(
                lambda wrapper: wrapper.dump_files(
                    filter_pattern, ignore_case, pid_int, output_dir
                ),
                task_id,
            )
            response['output_dir'] = str(Path(output_dir).resolve())
            return response

        except Exception as e:
            logger.error(f"提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def export_certificates(
        self, output_dir: str = None, task_id: str = None
    ) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = self._default_export_dir('certificates')

            os.makedirs(output_dir, exist_ok=True)

            response = self._run_extraction(
                lambda wrapper: wrapper.dump_certificates(output_dir),
                task_id,
            )
            if response.get('status') == 'success':
                result = response['data']
                return {
                    'status': 'success',
                    'data': {
                        'count': result['count'],
                        'total_size': result['total_size'],
                        'output_dir': result['output_dir'],
                        'files': result['files']
                    },
                    'message': f"成功导出 {result['count']} 个证书到 {output_dir}"
                }
            else:
                return response

        except Exception as e:
            logger.error(f"导出证书失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }


    def generate_report(self, format_type: str = 'markdown') -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像并执行分析'
                }

            from backend.report_generator import ReportGenerator
            generator = ReportGenerator(self.current_image)

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            if format_type == 'markdown':
                report_path = generator.generate_markdown(timestamp)
            elif format_type == 'html':
                report_path = generator.generate_html(timestamp)
            elif format_type == 'docx':
                report_path = generator.generate_docx(timestamp)
            else:
                return {
                    'status': 'error',
                    'message': f'不支持的报告格式: {format_type}'
                }

            return {
                'status': 'success',
                'data': {
                    'path': report_path,
                    'format': format_type
                }
            }

        except Exception as e:
            logger.error(f"生成报告失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def generate_report_with_data(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if not report_data or 'plugins' not in report_data:
                return {
                    'status': 'error',
                    'message': '无效的报告数据'
                }

            from backend.report_generator import ReportGenerator

            image_info = report_data.get('image_info') or self.current_image
            if not image_info:
                return {
                    'status': 'error',
                    'message': '缺少镜像信息'
                }

            generator = ReportGenerator(image_info)

            plugins_data = report_data.get('plugins', [])
            format_type = report_data.get('format', 'markdown')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            if format_type == 'markdown':
                report_path = generator.generate_markdown_from_data(plugins_data, timestamp)
            elif format_type == 'html':
                report_path = generator.generate_html_from_data(plugins_data, timestamp)
            elif format_type == 'docx':
                report_path = generator.generate_docx_from_data(plugins_data, timestamp)
            else:
                return {
                    'status': 'error',
                    'message': f'不支持的报告格式: {format_type}'
                }

            return {
                'status': 'success',
                'data': {
                    'path': report_path,
                    'format': format_type,
                    'plugins_count': len(plugins_data)
                }
            }

        except Exception as e:
            logger.error(f"生成报告失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def _internal_cache_files(self) -> set:
        return {
            'project_info.json',
            'cache_index.json',
            'ai_chat_history.json',
            'ai_analysis_plan.json',
            'ai_evidence_index.json',
            'ai_timeline.json',
            'ai_workflow_last.json',
        }

    def _cache_file_signature(self, cache_file: Path) -> Dict[str, Any]:
        stat = cache_file.stat()
        return {
            'size': stat.st_size,
            'mtime_ns': getattr(stat, 'st_mtime_ns', int(stat.st_mtime * 1_000_000_000)),
        }

    def _summarize_cache_file(self, cache_file: Path, include_results: bool = False) -> List[Dict[str, Any]]:
        if cache_file.name == 'flag_search_cache.json':
            with open(cache_file, 'r', encoding='utf-8') as f:
                flag_cache = json.load(f)
            plugins = []
            for search_key, search_data in (flag_cache or {}).items():
                results = search_data.get('results', [])
                pattern = search_data.get('pattern')
                if pattern is None:
                    plugin_id = 'flag_search_default'
                    display_name = 'Flag搜索（默认）'
                else:
                    plugin_id = f'flag_search_custom:{pattern}'
                    display_name = f'Flag搜索: {pattern}'
                plugin_info = {
                    'pluginId': plugin_id,
                    'displayName': display_name,
                    'count': search_data.get('count', len(results)),
                    'executionTime': 0,
                    'timestamp': search_data.get('timestamp', ''),
                    'cached': True,
                    'isFlagSearch': True,
                    'sourceFile': cache_file.name,
                }
                if include_results:
                    plugin_info['results'] = results
                plugins.append(plugin_info)
            return plugins

        with open(cache_file, 'r', encoding='utf-8') as f:
            cache_data = json.load(f)
        plugin_id = cache_file.stem
        results = cache_data.get('results', []) if isinstance(cache_data, dict) else []
        metadata = cache_data.get('metadata', {}) if isinstance(cache_data, dict) else {}
        plugin_info = {
            'pluginId': plugin_id,
            'displayName': self._get_plugin_display_name(plugin_id),
            'count': len(results),
            'executionTime': metadata.get('execution_time', 0),
            'timestamp': metadata.get('timestamp', cache_data.get('timestamp', '') if isinstance(cache_data, dict) else ''),
            'cached': True,
            'sourceFile': cache_file.name,
        }
        if include_results:
            plugin_info['results'] = results
        return [plugin_info]

    def _load_cache_index(self) -> Optional[Dict[str, Any]]:
        index_file = self._get_image_cache_dir() / 'cache_index.json'
        if not index_file.exists():
            return None
        try:
            with open(index_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if data.get('image_hash') != (self.current_image or {}).get('hash'):
                return None
            return data
        except Exception as e:
            logger.debug(f"读取缓存索引失败: {e}")
            return None

    def _save_cache_index(self, index_data: Dict[str, Any]) -> None:
        try:
            cache_dir = self._get_image_cache_dir()
            cache_dir.mkdir(parents=True, exist_ok=True)
            index_file = cache_dir / 'cache_index.json'
            with open(index_file, 'w', encoding='utf-8') as f:
                json.dump(index_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.debug(f"保存缓存索引失败: {e}")

    def _build_cache_index(self) -> Dict[str, Any]:
        cache_dir = self._get_image_cache_dir()
        internal_cache_files = self._internal_cache_files()
        files = {}
        plugins = []
        for cache_file in cache_dir.glob('*.json'):
            if cache_file.name in internal_cache_files:
                continue
            try:
                signature = self._cache_file_signature(cache_file)
                summaries = self._summarize_cache_file(cache_file, include_results=False)
                files[cache_file.name] = {
                    **signature,
                    'plugins': summaries,
                }
                plugins.extend(summaries)
            except Exception as e:
                logger.warning(f"构建缓存索引失败 {cache_file}: {e}")
                continue
        plugins.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        index_data = {
            'version': 1,
            'image_hash': (self.current_image or {}).get('hash'),
            'updated_at': datetime.now().isoformat(),
            'files': files,
            'plugins': plugins,
            'count': len(plugins),
        }
        self._save_cache_index(index_data)
        return index_data

    def _get_cache_index_plugins(self) -> List[Dict[str, Any]]:
        cache_dir = self._get_image_cache_dir()
        index_data = self._load_cache_index()
        if not index_data:
            index_data = self._build_cache_index()
        else:
            indexed_files = index_data.get('files') or {}
            current_files = {}
            for cache_file in cache_dir.glob('*.json'):
                if cache_file.name in self._internal_cache_files():
                    continue
                current_files[cache_file.name] = self._cache_file_signature(cache_file)
            valid = set(current_files) == set(indexed_files)
            if valid:
                for name, signature in current_files.items():
                    indexed = indexed_files.get(name) or {}
                    if indexed.get('size') != signature.get('size') or indexed.get('mtime_ns') != signature.get('mtime_ns'):
                        valid = False
                        break
            if not valid:
                index_data = self._build_cache_index()
        return index_data.get('plugins') or []

    def _refresh_cache_index_for_file(self, cache_file: Path, data: Optional[Dict[str, Any]] = None) -> None:
        if cache_file.name in self._internal_cache_files():
            return
        index_data = self._load_cache_index() or {
            'version': 1,
            'image_hash': (self.current_image or {}).get('hash'),
            'files': {},
            'plugins': [],
        }
        try:
            summaries = []
            if data is not None and cache_file.name != 'flag_search_cache.json':
                results = data.get('results', []) if isinstance(data, dict) else []
                metadata = data.get('metadata', {}) if isinstance(data, dict) else {}
                plugin_id = cache_file.stem
                summaries = [{
                    'pluginId': plugin_id,
                    'displayName': self._get_plugin_display_name(plugin_id),
                    'count': len(results),
                    'executionTime': metadata.get('execution_time', 0),
                    'timestamp': metadata.get('timestamp', data.get('timestamp', '') if isinstance(data, dict) else ''),
                    'cached': True,
                    'sourceFile': cache_file.name,
                }]
            else:
                summaries = self._summarize_cache_file(cache_file, include_results=False)
            index_data['files'][cache_file.name] = {
                **self._cache_file_signature(cache_file),
                'plugins': summaries,
            }
            plugins = []
            for file_info in (index_data.get('files') or {}).values():
                plugins.extend(file_info.get('plugins') or [])
            plugins.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            index_data['plugins'] = plugins
            index_data['count'] = len(plugins)
            index_data['updated_at'] = datetime.now().isoformat()
            self._save_cache_index(index_data)
        except Exception as e:
            logger.debug(f"刷新缓存索引失败 {cache_file}: {e}")

    def _safe_cache_source_file(self, source_file: Optional[str]) -> str:
        name = Path(str(source_file or '')).name
        if not name.endswith('.json'):
            return ''
        if name in self._internal_cache_files():
            return ''
        return name

    def _load_cached_plugin_rows(self, plugin_id: str, source_file: Optional[str] = None) -> Dict[str, Any]:
        plugin_id = str(plugin_id or '').strip()
        if not plugin_id:
            return {'status': 'error', 'message': '缺少 plugin_id'}

        cache_dir = self._get_image_cache_dir()
        if plugin_id.startswith('flag_search_'):
            cache_file = cache_dir / 'flag_search_cache.json'
            if not cache_file.exists():
                return {'status': 'error', 'message': 'Flag 搜索缓存不存在'}
            with open(cache_file, 'r', encoding='utf-8') as f:
                flag_cache = json.load(f)
            expected_key = 'default' if plugin_id == 'flag_search_default' else ''
            if plugin_id.startswith('flag_search_custom:'):
                expected_key = f"custom:{plugin_id.split(':', 1)[1]}"
            search_data = (flag_cache or {}).get(expected_key)
            if not search_data:
                return {'status': 'error', 'message': f'没有找到 {plugin_id} 的缓存'}
            return {
                'status': 'success',
                'plugin_id': plugin_id,
                'display_name': self._get_plugin_display_name(plugin_id),
                'source_file': cache_file.name,
                'timestamp': search_data.get('timestamp', ''),
                'rows': search_data.get('results') or [],
            }

        safe_source = self._safe_cache_source_file(source_file)
        cache_file = cache_dir / safe_source if safe_source else cache_dir / f"{self._get_cache_key(plugin_id, None)}.json"
        if not cache_file.exists():
            return {'status': 'error', 'message': f'没有找到 {plugin_id} 的缓存'}
        with open(cache_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        rows = data.get('results') if isinstance(data, dict) else []
        metadata = data.get('metadata', {}) if isinstance(data, dict) else {}
        return {
            'status': 'success',
            'plugin_id': plugin_id,
            'display_name': self._get_plugin_display_name(plugin_id),
            'source_file': cache_file.name,
            'timestamp': metadata.get('timestamp', data.get('timestamp', '') if isinstance(data, dict) else ''),
            'rows': rows or [],
        }

    def read_cached_plugin_page(self, plugin_id: str, offset: int = 0, limit: int = 100, keyword: str = '', source_file: str = '') -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {'status': 'error', 'message': '请先加载内存镜像'}

            offset = max(0, int(offset or 0))
            limit = max(1, min(int(limit or 100), 500))
            loaded = self._load_cached_plugin_rows(plugin_id, source_file)
            if loaded.get('status') != 'success':
                return {'status': 'error', 'message': loaded.get('message') or '缓存读取失败'}

            rows = loaded.get('rows') or []
            keyword_text = str(keyword or '').strip().lower()
            if keyword_text:
                rows = [
                    row for row in rows
                    if self._row_contains_keyword(row, keyword_text)
                ]
            page = rows[offset:offset + limit]
            return {
                'status': 'success',
                'data': {
                    'plugin_id': loaded.get('plugin_id'),
                    'display_name': loaded.get('display_name'),
                    'source_file': loaded.get('source_file'),
                    'timestamp': loaded.get('timestamp', ''),
                    'offset': offset,
                    'limit': limit,
                    'total': len(rows),
                    'rows': page,
                    'truncated': offset + limit < len(rows),
                }
            }
        except Exception as e:
            logger.error(f"分页读取插件缓存失败: {e}")
            return {'status': 'error', 'message': f'分页读取插件缓存失败: {str(e)}'}

    def read_cached_plugin_record(self, plugin_id: str, row_index: int, source_file: str = '') -> Dict[str, Any]:
        try:
            row_index = max(1, int(row_index or 1))
        except (TypeError, ValueError):
            row_index = 1
        result = self.read_cached_plugin_page(plugin_id, row_index - 1, 1, '', source_file)
        if result.get('status') != 'success':
            return result
        data = result.get('data') or {}
        rows = data.get('rows') or []
        if not rows:
            return {'status': 'error', 'message': f'没有找到第 {row_index} 条记录'}
        data['row_index'] = row_index
        data['row'] = rows[0]
        data.pop('rows', None)
        return {'status': 'success', 'data': data}

    def read_file_visualization_entries(self, plugin_id: str = 'filescan', source_file: str = '') -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {'status': 'error', 'message': '请先加载内存镜像'}

            plugin_id = str(plugin_id or 'filescan').strip()
            supported_plugins = {'filescan', 'eventlog', 'linux_pagecache_files', 'linux_passwd_hashes'}
            if plugin_id not in supported_plugins:
                return {'status': 'error', 'message': f'{plugin_id} 不支持文件可视化'}

            loaded = self._load_cached_plugin_rows(plugin_id, source_file)
            if loaded.get('status') != 'success':
                return {'status': 'error', 'message': loaded.get('message') or '缓存读取失败'}

            rows = loaded.get('rows') or []
            entries = []
            for index, row in enumerate(rows):
                if not isinstance(row, dict):
                    continue
                path = (
                    row.get('path') or
                    row.get('file_path') or
                    row.get('Name') or
                    row.get('name') or
                    row.get('file_name') or
                    ''
                )
                path = str(path or '').strip()
                if not path:
                    continue

                entry = {
                    'path': path,
                    'file_path': path,
                    'file_name': row.get('file_name') or path,
                    'offset': row.get('offset') or '',
                    'inode_addr': row.get('inode_addr') or '',
                    'size': row.get('size') or row.get('inode_size') or 0,
                    'inode_size': row.get('inode_size') or row.get('size') or 0,
                    'file_type': row.get('file_type') or '',
                    'row_index': index + 1,
                }
                entries.append(entry)

            return {
                'status': 'success',
                'data': {
                    'plugin_id': loaded.get('plugin_id') or plugin_id,
                    'display_name': loaded.get('display_name') or self._get_plugin_display_name(plugin_id),
                    'source_file': loaded.get('source_file') or '',
                    'timestamp': loaded.get('timestamp', ''),
                    'total': len(rows),
                    'entries': entries,
                    'entry_count': len(entries),
                }
            }
        except Exception as e:
            logger.error(f"读取文件可视化数据失败: {e}")
            return {'status': 'error', 'message': f'读取文件可视化数据失败: {str(e)}'}

    def get_cached_plugins(self, include_results: bool = True) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not include_results:
                plugins = self._get_cache_index_plugins()
                return {
                    'status': 'success',
                    'data': {
                        'plugins': plugins,
                        'count': len(plugins),
                        'indexed': True,
                    }
                }

            cache_dir = self._get_image_cache_dir()
            plugins = []
            internal_cache_files = self._internal_cache_files()
            for cache_file in cache_dir.glob('*.json'):
                if cache_file.name in internal_cache_files:
                    continue

                if cache_file.name == 'flag_search_cache.json':
                    try:
                        plugins.extend(self._summarize_cache_file(cache_file, include_results=True))
                    except Exception as e:
                        logger.warning(f"读取Flag搜索缓存失败 {cache_file}: {e}")
                    continue

                try:
                    plugins.extend(self._summarize_cache_file(cache_file, include_results=True))
                except Exception as e:
                    logger.warning(f"读取缓存文件失败 {cache_file}: {e}")
                    continue

            plugins.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

            return {
                'status': 'success',
                'data': {
                    'plugins': plugins,
                    'count': len(plugins)
                }
            }

        except Exception as e:
            logger.error(f"获取缓存插件列表失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def _get_plugin_display_name(self, plugin_id: str) -> str:
        if plugin_id.startswith('flag_search_'):
            if plugin_id == 'flag_search_default':
                return 'Flag搜索（默认）'
            elif plugin_id.startswith('flag_search_custom:'):
                pattern = plugin_id.split(':', 1)[1] if ':' in plugin_id else plugin_id
                return f'Flag搜索: {pattern}'

        plugin_name_map = {
            'linux.bash.Bash': 'Bash命令历史',
            'linux.check_afinfo.CheckAffinity': '进程亲和性检查',
            'linux.check_creds.CheckCreds': '凭据检查',
            'linux.check_idt.CheckIdt': 'IDT检查',
            'linux.check_modules.CheckModules': '内核模块检查',
            'linux.check_syscall.SyscallChecker': '系统调用检查',
            'linux.chk_creds.CheckCreds': '凭据检查',
            'linux.elfs.Elfs': 'ELF文件信息',
            'linux.heap.HEAP': '堆信息',
            'linux.keyboard_notifiers.KeyboardNotifiers': '键盘通知器',
            'linux.kmsg.Kmsg': '内核消息',
            'linux.librarylist.LibraryList': '加载的库列表',
            'linux.lsof.Lsof': '打开的文件',
            'linux.malfind.Malfind': '恶意代码查找',
            'linux-mount.Mount': '挂载点信息',
            'linuxmount.Mount': '挂载点信息',
            'linux.proc.Maps': '进程内存映射',
            'linuxpslist.PsList': '进程列表',
            'linux.pstree.PsTree': '进程树',
            'linux.sockstat.Sockstat': '网络连接统计',
            'linux.strings.Strings': '字符串扫描',
            'linux.banner.Banner': '内核Banner',
            'linux.linux banners.Banners': 'Linux Banner',

            'linux.ip.IpFilters': 'IP过滤器',
            'linux.ip.NetFilters': '网络过滤器',
            'linux.ip.Addr': 'IP地址',
            'linux.ip.Filters': 'IP过滤器',
            'linux.ip.Interface': '网络接口',
            'linux.ip.Link': '网络链接',
            'linux.ip.Route': '路由表',
            'linux.ip.Sockets': '网络套接字',
            'linux.netfilter.Netfilter': 'Netfilter网络过滤',
            'linux.netstat.Netstat': '网络状态',
            'linux.arpscan.ArpScan': 'ARP扫描',
            'linux.tty_check.tty_check': 'TTY检查',

            'linux.pslist.PsList': '进程列表',
            'linux.psscan.PsScan': '进程扫描',
            'linux.pstree.PsTree': '进程树',
            'linux.proc.Maps': '内存映射',
            'linux.taskstats.TaskStats': '任务统计',
            'linux.environ.Environ': '环境变量',
            'linux.linuxmodels.LinuxModels': 'Linux模型',

            'linux.lsof.Lsof': '打开的文件',
            'linux.filescan.FileScan': '文件扫描',
            'linux.mft.MFT': '主文件表',
            'linux.link_count.LinkCount': '链接计数',
            'linux.pagecache.Pagecache': '页缓存',
            'linux.pagecache.PageCache': '页缓存',

            'linux.banner.Banner': '内核Banner',
            'linux.kernel_modules.KernelModules': '内核模块',
            'linux.loadables_kernels.KernelLoadables': '可加载内核模块',
            'linux.malfind.Malfind': '恶意代码查找',
            'linux.bigpools.BigPools': '大内存池',
            'linux.pidhashtable.PidHashTable': 'PID哈希表',
            'linux.kallsyms.Kallsyms': '内核符号表',

            'windows.bigpools.BigPools': '大内存池',
            'windows.cmdline.CmdLine': '命令行参数',
            'windows.devicetree.DeviceTree': '设备树',
            'windows.dlllist.DllList': 'DLL列表',
            'windows.driverirp.DriverIrp': '驱动IRP',
            'windows.driverscan.DriverScan': '驱动扫描',
            'windows.filescan.FileScan': '文件扫描',
            'windows.getsids.GetSIDs': '安全ID',
            'windows.handles.Handles': '句柄列表',
            'windows.hashdump.HashDump': '密码哈希',
            'pypykatz_plugin.PypykatzPlugin': '明文密码',
            'windows.info.Info': '系统信息',
            'windows.malware.malfind.Malfind': '恶意代码查找',
            'windows.mbrscan.MBRScan': 'MBR扫描',
            'windows.memmap.Memmap': '内存映射',
            'windows.modscan.ModScan': '内核模块扫描',
            'windows.modules.Modules': '内核模块',
            'windows.mutantscan.MutantScan': '互斥体扫描',
            'windows.poolscanner.PoolScanner': '池扫描',
            'windows.privileges.Privileges': '进程权限',
            'windows.pslist.PsList': '进程列表',
            'windows.psscan.PsScan': '进程扫描',
            'windows.pstree.PsTree': '进程树',
            'windows.services.Services': '服务列表',
            'windows.svcscan.SvcScan': '服务扫描',
            'windows.vadtree.VadTree': 'VAD树',
            'windows.vadyarascan.VadYaraScan': 'VAD Yara扫描',
            'windows.verinfo.VerInfo': '版本信息',
            'windows.volshell.Volshell': 'Volshell控制台',

            'mac.bash.Bash': 'Bash命令历史',
            'mac.check_sysctl.Check_sysctl': 'Sysctl检查',
            'mac.check_syscall.Check_syscall': '系统调用检查',
            'mac.check_trap_table.Check_trap_table': '陷阱表检查',
            'mac.dmesg.Dmesg': '内核消息',
            'mac.ifconfig.Ifconfig': '网络配置',
            'mac.kauth_listeners.Kauth_listeners': 'Kauth监听器',
            'mac.kauth_scopes.Kauth_scopes': 'Kauth范围',
            'mac.kevents.Kevents': '内核事件',
            'mac.list_files.List_Files': '文件列表',
            'mac.lsof.Lsof': '打开的文件',
            'mac.lsmod.Lsmod': '内核扩展',
            'mac.malfind.Malfind': '恶意代码查找',
            'mac.mount.Mount': '挂载点信息',
            'mac.netstat.Netstat': '网络状态',
            'mac.proc_maps.Maps': '进程内存映射',
            'mac.psaux.Psaux': '进程参数',
            'mac.pslist.PsList': '进程列表',
            'mac.pstree.PsTree': '进程树',
            'mac.socket_filters.Socket_filters': '套接字过滤器',
            'mac.timers.Timers': '定时器',
            'mac.trustedbsd.Trustedbsd': 'TrustedBSD',
            'mac.vfsevents.VFSevents': '文件系统事件',

            'pslist': '进程列表',
            'pstree': '进程树',
            'psscan': '进程扫描',
            'dlllist': 'DLL列表',
            'handles': '句柄列表',
            'netscan': '网络连接',
            'cmdline': '命令行参数',
            'filescan': '文件扫描',
            'hivelist': '注册表配置单元',
            'malfind': '恶意代码查找',
            'getsids': '安全标识符',
            'envars': '环境变量',
            'svcscan': '服务扫描',
            'hashdump': '密码哈希',
            'lsadump': 'LSA 密钥',
            'cachedump': '域缓存凭据',
            'cmdscan': '命令历史扫描',
            'consoles': '控制台历史',
            'psxview': '隐藏进程检测',
            'malware_psxview': '恶意进程交叉视图',
            'ldrmodules': '异常模块检测',
            'hollowprocesses': '进程镜像劫持检测',
            'svcdiff': '异常服务检测',
            'unhooked_system_calls': '未挂钩系统调用检测',
            'processghosting': '幽灵进程检测',
            'pebmasquerade': 'PEB 伪装检测',
            'callbacks': '内核回调',
            'skeleton_key_check': '骨架密钥检测',
            'mutantscan': '互斥体扫描',
            'suspicious_threads': '可疑线程检测',
            'imageinfo': '系统信息',
            'privileges': '进程权限',
            'sessions': '会话列表',
            'threads': '线程列表',
            'vadinfo': 'VAD 信息',
            'userassist': 'UserAssist 用户活动',
            'scheduled_tasks': '计划任务',
            'amcache': 'Amcache 程序痕迹',
            'modscan': '内核模块扫描',
            'ssdt': 'SSDT 系统调用表',
            'driverscan': '驱动扫描',
            'drivermodule': '驱动模块检测',
            'certificates': '证书列表',

            'linux_pslist': '进程列表',
            'linux_pstree': '进程树',
            'linux_psscan': '进程扫描',
            'linux_psaux': '进程命令行',
            'linux_sockstat': '进程网络连接',
            'linux_ip_addr': '网络地址',
            'linux_ip_link': '网络接口',
            'linux_lsof': '打开文件列表',
            'linux_elfs': 'ELF 文件列表',
            'linux_mountinfo': '挂载信息',
            'linux_pagecache_files': '页缓存文件',
            'linux_bash': 'Bash 历史',
            'linux_envars': '环境变量',
            'linux_lsmod': '内核模块',
            'linux_kmsg': '内核消息',
            'linux_maps': '进程内存映射',
            'linux_malware_malfind': '恶意代码查找',
            'linux_malware_check_afinfo': '协议族异常检查',
            'linux_malware_check_creds': '凭据异常检查',
            'linux_malware_check_idt': 'IDT 异常检查',
            'linux_malware_check_modules': '内核模块完整性检查',
            'linux_malware_check_syscall': '系统调用表检查',
            'linux_malware_hidden_modules': '隐藏内核模块检测',
            'linux_malware_keyboard_notifiers': '键盘通知器检查',
            'linux_malware_netfilter': 'Netfilter 挂钩检查',
            'linux_malware_tty_check': 'TTY 挂钩检查',
            'linux_malware_modxview': '内核模块交叉视图',

            'mac_pslist': '进程列表',
            'mac_pstree': '进程树',
            'mac_psaux': '进程参数',
            'mac_netstat': '网络状态',
            'mac_ifconfig': '网络接口',
            'mac_socket_filters': '套接字过滤器',
            'mac_lsof': '打开文件列表',
            'mac_list_files': '文件列表',
            'mac_mount': '挂载信息',
            'mac_bash': 'Bash 历史',
            'mac_malfind': '恶意代码查找',
            'mac_lsmod': '内核扩展',
            'mac_check_syscall': '系统调用表检查',
            'mac_check_sysctl': 'Sysctl 检查',
            'mac_check_trap_table': '陷阱表检查',
            'mac_dmesg': '内核消息',
            'mac_kevents': '内核事件',
            'mac_timers': '内核定时器',
            'mac_kauth_listeners': 'Kauth 监听器',
            'mac_kauth_scopes': 'Kauth 授权范围',
            'mac_trustedbsd': 'TrustedBSD 策略',
            'mac_maps': '进程内存映射',
            'mac_vfsevents': '文件系统事件',

            'banner': 'Banner信息',
            'linux_pslist': '进程列表',
            'linux_psscan': '进程扫描',
            'linux_pstree': '进程树',
            'linux_bash': 'Bash历史',
            'linux_lsof': '打开文件',
            'linux_envars': '环境变量',
            'linux_environ': '环境变量',
            'linux_mount': '挂载信息',
            'linux_sockstat': '网络连接',
            'linux_ip_addr': 'IP地址',
            'linux_ip_link': '网络链接',
            'linux_ip_route': '路由表',
            'linux_ip_interface': '网络接口',
            'linux_ip_filters': 'IP过滤器',
            'linux_netstat': '网络状态',
            'linux_maps': '内存映射',
            'linux_malfind': '恶意代码查找',
            'linux_pstree': '进程树',
            'linux_pslist': '进程列表',
            'linux_sockstat': '网络连接',
            'linux_kmsg': '内核消息',
            'linux_elfs': 'ELF文件',
            'linux_librarylist': '加载的库',
            'linux_keyboard_notifiers': '键盘通知器',
            'linux_check_modules': '内核模块检查',
            'linux_check_syscall': '系统调用检查',
            'linux_check_creds': '凭据检查',
            'linux_check_afinfo': '进程亲和性',
            'linux_taskstats': '任务统计',
            'linux_pidhashtable': 'PID哈希表',
            'linux_bigpools': '大内存池',
            'linux_kallsyms': '内核符号表',
            'mac_pslist': '进程列表',
            'mac_pstree': '进程树',
            'mac_psaux': '进程参数',
            'mac_netstat': '网络状态',
            'mac_ifconfig': '网络配置',
            'mac_socket_filters': '套接字过滤器',
            'mac_lsof': '打开的文件',
            'mac_list_files': '文件列表',
            'mac_mount': '挂载点信息',
            'mac_bash': 'Bash命令历史',
            'mac_malfind': '恶意代码查找',
            'mac_lsmod': '内核扩展',
            'mac_check_syscall': '系统调用检查',
            'mac_check_sysctl': 'Sysctl检查',
            'mac_check_trap_table': '陷阱表检查',
            'mac_dmesg': '内核消息',
            'mac_kevents': '内核事件',
            'mac_timers': '定时器',
            'mac_kauth_listeners': 'Kauth监听器',
            'mac_kauth_scopes': 'Kauth范围',
            'mac_trustedbsd': 'TrustedBSD',
            'mac_maps': '进程内存映射',
            'mac_vfsevents': '文件系统事件',
        }

        if plugin_id in plugin_name_map:
            return plugin_name_map[plugin_id]

        plugins_dict = self.get_available_plugins()
        for os_type, categories in plugins_dict.items():
            if not isinstance(categories, dict):
                continue
            for category, plugin_list in categories.items():
                if not isinstance(plugin_list, list):
                    continue
                for plugin in plugin_list:
                    if isinstance(plugin, dict) and plugin.get('id') == plugin_id:
                        return plugin.get('name', plugin_id)

        for key, name in plugin_name_map.items():
            if key.endswith(plugin_id) or plugin_id.endswith(key.split('.')[-1]):
                return name

        if '_' in plugin_id:
            parts = plugin_id.replace('linux_', '').replace('windows_', '').replace('mac_', '').split('_')
            formatted = ' '.join([p.capitalize() for p in parts])
            return formatted

        return plugin_id


    def _get_symbol_file_name(self) -> str:
        if not self.current_image:
            return None

        os_type = self.current_image.get('os_type', '').lower()

        try:
            if os_type == 'windows':
                from volatility3.framework.symbols.windows import pdbutil
                from volatility3.framework import contexts
                from volatility3.framework.layers import physical

                context = contexts.Context()
                file_path = self.current_image['path']

                import urllib.request
                file_url = 'file://' + urllib.request.pathname2url(file_path)
                context.config['FileLayer.location'] = file_url

                layer = physical.FileLayer(context, 'FileLayer', name="FileLayer")
                context.add_layer(layer)

                layer_name = layer.name
                page_size = 0x1000

                pdb_names = [b'ntkrnlmp.pdb', b'ntoskrnl.pdb', b'krnl.pdb', b'ntkrpamp.pdb']

                for result in pdbutil.PDBUtility.pdbname_scan(
                    context, layer_name, page_size, pdb_names
                ):
                    guid = result.get('GUID', '')
                    age = result.get('age', 0)
                    pdb_name = result.get('pdb_name', '')

                    if guid and pdb_name:
                        symbol_path = self._find_matching_windows_symbol(pdb_name, guid, age)
                        if symbol_path and symbol_path.exists():
                            return f"{pdb_name} ({guid}-{age})"
                        else:
                            return None

                return None

            elif 'linux' in os_type or 'mac' in os_type:
                banner = self.current_image.get('banner', '')
                if not banner:
                    return None

                kernel_version = self._extract_kernel_version(banner, os_type)
                if not kernel_version:
                    return None

                if 'mac' in os_type:
                    symbol_dir_name = 'mac'
                else:
                    symbol_dir_name = os_type

                symbol_dir = self._get_os_symbols_dir(symbol_dir_name)
                if not symbol_dir.exists():
                    return None

                for symbol_file in symbol_dir.glob('*.json.xz'):
                    if kernel_version in symbol_file.stem:
                        return symbol_file.name

                for symbol_file in symbol_dir.glob('*.json'):
                    if kernel_version in symbol_file.stem:
                        return symbol_file.name

                return None

        except ImportError:
            logger.info("打包后无法直接导入 volatility3，改用当前镜像 PDB 索引获取符号表文件名")
            symbol_status = {'windows': {}}
            if self._load_pdb_info_from_file(symbol_status):
                pdb_info = symbol_status['windows'].get('pdb_info') or {}
                if pdb_info.get('symbol_exists'):
                    return f"{pdb_info.get('name')} ({pdb_info.get('guid')}-{pdb_info.get('age')})"
            return None
        except Exception as e:
            logger.warning(f"获取符号表文件名失败: {e}")
            return None

    @classmethod
    def _cache_fingerprint_offsets(cls, file_size: int) -> List[int]:
        file_size = max(0, int(file_size))
        sample_bytes = cls._CACHE_FINGERPRINT_CHUNKS * cls._CACHE_FINGERPRINT_CHUNK_SIZE
        if file_size <= sample_bytes:
            return [0]

        last_offset = file_size - cls._CACHE_FINGERPRINT_CHUNK_SIZE
        divisor = cls._CACHE_FINGERPRINT_CHUNKS - 1
        return [
            (last_offset * index) // divisor
            for index in range(cls._CACHE_FINGERPRINT_CHUNKS)
        ]

    def _calculate_cache_fingerprint(self, file_path: str) -> str:
        started_at = time.perf_counter()
        digest = hashlib.sha256()
        digest.update(self._CACHE_FINGERPRINT_VERSION)

        with open(file_path, 'rb') as stream:
            before = os.fstat(stream.fileno())
            file_size = int(before.st_size)
            offsets = self._cache_fingerprint_offsets(file_size)
            digest.update(file_size.to_bytes(16, 'big', signed=False))

            bytes_sampled = 0
            if file_size <= self._CACHE_FINGERPRINT_CHUNKS * self._CACHE_FINGERPRINT_CHUNK_SIZE:
                remaining = file_size
                buffer = bytearray(min(self._CACHE_FINGERPRINT_CHUNK_SIZE, max(1, file_size)))
                view = memoryview(buffer)
                while remaining:
                    count = stream.readinto(view[:min(len(buffer), remaining)])
                    if not count:
                        raise OSError('读取镜像内容时意外到达文件末尾')
                    digest.update(bytes_sampled.to_bytes(16, 'big', signed=False))
                    digest.update(count.to_bytes(8, 'big', signed=False))
                    digest.update(view[:count])
                    bytes_sampled += count
                    remaining -= count
            else:
                buffer = bytearray(self._CACHE_FINGERPRINT_CHUNK_SIZE)
                view = memoryview(buffer)
                for offset in offsets:
                    stream.seek(offset)
                    count = stream.readinto(buffer)
                    if count != self._CACHE_FINGERPRINT_CHUNK_SIZE:
                        raise OSError('读取镜像抽样内容时数据不完整')
                    digest.update(offset.to_bytes(16, 'big', signed=False))
                    digest.update(count.to_bytes(8, 'big', signed=False))
                    digest.update(view[:count])
                    bytes_sampled += count

            after = os.fstat(stream.fileno())

        before_mtime = getattr(before, 'st_mtime_ns', int(before.st_mtime * 1_000_000_000))
        after_mtime = getattr(after, 'st_mtime_ns', int(after.st_mtime * 1_000_000_000))
        if before.st_size != after.st_size or before_mtime != after_mtime:
            raise RuntimeError('镜像文件在加载过程中发生了变化，请重新加载')

        elapsed = time.perf_counter() - started_at
        logger.info(
            "镜像缓存指纹已生成: size=%d, sampled=%d, chunks=%d, elapsed=%.3fs",
            file_size, bytes_sampled, len(offsets), elapsed,
        )
        return digest.hexdigest()

    def _calculate_file_hash(self, file_path: str) -> str:
        return self._calculate_cache_fingerprint(file_path)

    def _get_cache_key(self, plugin_id: str, params: Optional[Dict] = None) -> str:
        if params:
            sorted_params = sorted(params.items())
            params_str = '&'.join(f"{k}={v}" for k, v in sorted_params)
            return f"{plugin_id}?{params_str}"
        return plugin_id

    def _get_image_cache_dir(self) -> Path:
        if not self.current_image:
            return self._cache_dir
        image_cache_dir = self._cache_dir / self.current_image['hash']
        image_cache_dir.mkdir(parents=True, exist_ok=True)
        return image_cache_dir

    def _load_from_cache(self, cache_key: str) -> Optional[Dict]:
        cache_dir = self._get_image_cache_dir()
        cache_file = cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return None

    def _save_to_cache(self, cache_key: str, data: Dict):
        cache_dir = self._get_image_cache_dir()
        cache_file = cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"缓存保存失败: {str(e)}")

    def _load_from_cache_file(self, cache_key: str) -> Optional[Dict]:
        cache_dir = self._get_image_cache_dir()
        cache_file = cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"缓存读取失败: {str(e)}")
        return None

    def _save_to_cache_file(self, cache_key: str, data: Dict):
        cache_dir = self._get_image_cache_dir()
        cache_file = cache_dir / f"{cache_key}.json"
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info(f"结果已缓存到: {cache_file}")
            self._refresh_cache_index_for_file(cache_file, data)
        except Exception as e:
            logger.warning(f"缓存保存失败: {str(e)}")

    def _format_size(self, size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"

    def _get_services_from_registry(self, max_detail_services: int = 50, cancel_task_id: Optional[str] = None) -> Optional[Dict]:
        try:
            from backend.volatility_wrapper import VolatilityWrapper

            wrapper = VolatilityWrapper(self.current_image['path'], self.current_image.get('os_type'), self._get_python_cmd(), symbols_dir=self._get_symbols_base_dir(self.current_image.get('os_type')), cache_path=self._cache_path)
            self._register_analysis_wrapper(wrapper)

            try:
                hivelist_result = wrapper.run_plugin('hivelist')
                system_offset = None
                for hive in hivelist_result.get('results', []):
                    if 'SYSTEM' in hive.get('path', ''):
                        system_offset = hive['offset']
                        break

                if not system_offset:
                    logger.error("未找到 SYSTEM 注册表")
                    return None

                logger.info(f"找到 SYSTEM 注册表偏移: {system_offset}")

                services_result = wrapper._run_volatility_raw(
                    'windows.registry.printkey.PrintKey',
                    ['--offset', system_offset, '--key', 'ControlSet001\\services']
                )
            finally:
                self._unregister_analysis_wrapper(wrapper)

            if not services_result:
                logger.error("无法读取服务列表")
                return None

            services = []
            for line in services_result.strip().split('\n'):
                if not line.strip() or line.startswith('Volatility') or line.startswith('Last Write') or line.startswith('-') or 'Hive Offset' in line:
                    continue

                parts = line.split('\t')
                if len(parts) >= 5 and parts[2] == 'Key':
                    service_name = parts[4]
                    services.append(service_name)

            logger.info(f"找到 {len(services)} 个服务")

            service_details = []
            start_type_map = {
                '0': 'Boot',
                '1': 'System',
                '2': 'Auto',
                '3': 'Manual',
                '4': 'Disabled'
            }

            detail_limit = max(0, min(int(max_detail_services or 0), len(services)))
            if detail_limit:
                logger.info(f"读取前 {detail_limit} 个服务详细信息，其余仅保留名称")
            else:
                logger.info("跳过服务逐项详细读取，仅返回服务清单")

            self._register_analysis_wrapper(wrapper)
            for i, service in enumerate(services[:detail_limit]):
                if self._is_ai_task_cancelled(cancel_task_id):
                    logger.info("服务注册表 fallback 已取消")
                    self._unregister_analysis_wrapper(wrapper)
                    return None
                try:
                    detail_result = wrapper._run_volatility_raw(
                        'windows.registry.printkey.PrintKey',
                        ['--offset', system_offset, '--key', f'ControlSet001\\services\\{service}'],
                        quiet=True
                    )

                    service_info = {
                        'order': i + 1,
                        'name': service,
                        'pid': 0,
                        'start': 'Unknown',
                        'state': 'Unknown',
                        'type': 'Unknown',
                        'display': service,
                        'binary': 'Unknown'
                    }

                    for line in detail_result.strip().split('\n'):
                        if not line.strip() or line.startswith('Volatility') or line.startswith('Last Write') or line.startswith('-') or 'Hive Offset' in line:
                            continue

                        parts = line.split('\t')
                        if len(parts) >= 6 and parts[2] != 'Key':
                            key_name = parts[4]
                            data = parts[5]

                            if key_name == 'Start':
                                service_info['start'] = start_type_map.get(data, data)
                            elif key_name == 'DisplayName':
                                service_info['display'] = data
                            elif key_name == 'ImagePath':
                                service_info['binary'] = data
                            elif key_name == 'Type':
                                service_info['type'] = data
                            elif key_name == 'ObjectName':
                                try:
                                    service_info['pid'] = int(data)
                                except:
                                    pass

                    service_details.append(service_info)

                except Exception as e:
                    logger.warning(f"读取服务 {service} 失败: {str(e)}")
                    continue
            self._unregister_analysis_wrapper(wrapper)

            for i, service in enumerate(services[detail_limit:], start=detail_limit + 1):
                service_details.append({
                    'order': i,
                    'name': service,
                    'pid': 0,
                    'start': 'Unknown',
                    'state': 'Unknown',
                    'type': 'Unknown',
                    'display': service,
                    'binary': 'Unknown'
                })

            return {
                'plugin': 'svcscan',
                'timestamp': datetime.now().isoformat(),
                'image': self.current_image['name'],
                'results': service_details
            }

        except Exception as e:
            if 'wrapper' in locals():
                self._unregister_analysis_wrapper(wrapper)
            logger.error(f"从注册表获取服务失败: {str(e)}")
            return None

    def clear_cache(self) -> Dict[str, Any]:
        try:
            import shutil
            cache_dir = self._get_image_cache_dir()

            if self.current_image:
                if cache_dir.exists() and cache_dir != self._cache_dir:
                    shutil.rmtree(cache_dir)
                    logger.info(f"当前镜像缓存已清除: {cache_dir}")
                    message = f'当前镜像缓存已清除'

                    if self._flag_search_cache:
                        self._flag_search_cache.clear()
                        self._save_flag_search_cache_to_file()
                        message += '，Flag搜索缓存已清除'
                else:
                    message = '当前镜像没有缓存'
            else:
                if self._cache_dir.exists():
                    project_dirs = [d for d in self._cache_dir.iterdir() if d.is_dir()]
                    count = len(project_dirs)

                    if count > 0:
                        for project_dir in project_dirs:
                            shutil.rmtree(project_dir)
                            logger.info(f"清除项目缓存: {project_dir.name}")
                        message = f'所有缓存已清除（共清除 {count} 个项目）'

                        for cache_file in self._cache_dir.glob('flag_search_*.json'):
                            try:
                                cache_file.unlink()
                                logger.info(f"清除Flag搜索缓存: {cache_file.name}")
                            except Exception as e:
                                logger.warning(f"清除Flag搜索缓存失败: {e}")
                    else:
                        message = '没有缓存需要清除'
                else:
                    message = '没有缓存需要清除'

            return {
                'status': 'success',
                'message': message
            }
        except Exception as e:
            logger.error(f"清除缓存失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_project_list(self) -> Dict[str, Any]:
        try:
            projects = []
            if not self._cache_dir.exists():
                return {'status': 'success', 'data': []}

            for project_dir in self._cache_dir.iterdir():
                if project_dir.is_dir():
                    info_file = project_dir / 'project_info.json'
                    if info_file.exists():
                        try:
                            with open(info_file, 'r', encoding='utf-8') as f:
                                info = json.load(f)
                        except:
                            info = {}
                    else:
                        info = {}

                    internal_cache_files = self._internal_cache_files() | {'flag_search_cache.json'}
                    analysis_count = len([
                        path for path in project_dir.glob('*.json')
                        if path.name not in internal_cache_files
                    ])

                    last_modified = datetime.fromtimestamp(project_dir.stat().st_mtime)

                    projects.append({
                        'hash': project_dir.name,
                        'name': info.get('name', '未知'),
                        'path': info.get('path', ''),
                        'size': info.get('size', ''),
                        'last_modified': last_modified.strftime('%Y-%m-%d %H:%M:%S'),
                        'analysis_count': analysis_count,
                        'is_current': self.current_image and self.current_image.get('hash', '') == project_dir.name
                    })

            projects.sort(key=lambda x: x['last_modified'], reverse=True)

            return {
                'status': 'success',
                'data': projects
            }
        except Exception as e:
            logger.error(f"获取项目列表失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def load_project(self, project_hash: str) -> Dict[str, Any]:
        try:
            project_dir = self._cache_dir / project_hash
            if not project_dir.exists():
                return {
                    'status': 'error',
                    'message': '项目不存在'
                }

            info_file = project_dir / 'project_info.json'
            if not info_file.exists():
                return {
                    'status': 'error',
                    'message': '项目信息丢失'
                }

            with open(info_file, 'r', encoding='utf-8') as f:
                info = json.load(f)

            if not Path(info['path']).exists():
                return {
                    'status': 'error',
                    'message': '镜像文件不存在，可能已被移动或删除'
                }

            load_result = self.load_memory_image(info['path'], info.get('os_type'))
            if load_result['status'] == 'success':
                return {
                    'status': 'success',
                    'message': f'已加载项目: {info.get("name", "未知")}',
                    'data': load_result.get('data', {})
                }
            else:
                return load_result

        except Exception as e:
            logger.error(f"加载项目失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def delete_project(self, project_hash: str) -> Dict[str, Any]:
        try:
            project_dir = self._cache_dir / project_hash
            if not project_dir.exists():
                return {
                    'status': 'error',
                    'message': '项目不存在'
                }

            import shutil
            shutil.rmtree(project_dir)

            return {
                'status': 'success',
                'message': '项目已删除'
            }
        except Exception as e:
            logger.error(f"删除项目失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def export_results(self, data: List[Dict], format_type: str = 'csv') -> Dict[str, Any]:
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            export_dir = self._user_data_dir / 'exports'
            export_dir.mkdir(exist_ok=True)

            if format_type == 'csv':
                import csv
                file_path = export_dir / f"results_{timestamp}.csv"
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    if data:
                        fieldnames = []
                        for row in data:
                            for key in row.keys():
                                if key not in fieldnames:
                                    fieldnames.append(key)
                        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                        writer.writeheader()
                        writer.writerows(data)
            elif format_type == 'json':
                file_path = export_dir / f"results_{timestamp}.json"
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            else:
                return {
                    'status': 'error',
                    'message': f'不支持的导出格式: {format_type}'
                }

            return {
                'status': 'success',
                'data': {
                    'path': str(file_path),
                    'count': len(data)
                }
            }

        except Exception as e:
            logger.error(f"导出失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def export_cached_plugin_results(self, plugin_id: str, format_type: str = 'csv', source_file: str = '') -> Dict[str, Any]:
        try:
            loaded = self._load_cached_plugin_rows(plugin_id, source_file)
            if loaded.get('status') != 'success':
                return {'status': 'error', 'message': loaded.get('message') or '缓存读取失败'}
            rows = loaded.get('rows') or []
            result = self.export_results(rows, format_type)
            if result.get('status') == 'success':
                result.setdefault('data', {})['plugin_id'] = plugin_id
                result['data']['source_file'] = loaded.get('source_file') or ''
            return result
        except Exception as e:
            logger.error(f"导出缓存插件结果失败: {e}")
            return {'status': 'error', 'message': f'导出缓存插件结果失败: {str(e)}'}

    def get_symbol_download_source(self) -> Dict[str, Any]:
        try:
            settings = self._load_config().get('settings', {})
            source = str(settings.get('symbol_download_source') or SOURCE_MICROSOFT).strip()
            if source not in (SOURCE_MICROSOFT, SOURCE_MIRROR_CN, SOURCE_CUSTOM):
                source = SOURCE_MICROSOFT

            return {
                'status': 'success',
                'source': source,
                'custom_url': str(settings.get('custom_symbol_server') or '')
            }
        except Exception as e:
            logger.error(f"读取符号表下载源失败: {e}")
            return {
                'status': 'error',
                'message': f'读取符号表下载源失败: {str(e)}'
            }

    def download_windows_symbols(self, source: str = None, custom_url: str = None) -> Dict[str, Any]:
        import os
        import subprocess
        import sys
        import platform

        try:
            symbol_server = resolve_symbol_server(source, custom_url)
        except ValueError as e:
            return {
                'status': 'error',
                'message': f'符号表下载源无效: {str(e)}'
            }

        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            os_type = self.current_image.get('os_type', '').lower()
            if os_type != 'windows':
                return {
                    'status': 'error',
                    'message': f'当前镜像不是Windows系统 (检测到: {os_type})'
                }

            logger.info("开始下载Windows符号表...")

            symbol_host = describe_symbol_server(symbol_server)
            logger.info(f"使用自定义脚本下载符号表，下载源: {symbol_server}")
            self._show_loading(
                '正在下载Windows符号表...',
                f'正在从 {symbol_host} 下载...\n\n这可能需要几分钟，请耐心等待。'
            )

            import tempfile

            script_content = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows 符号表下载脚本
"""
import sys
import os
from pathlib import Path

try:
    from volatility3.framework.symbols.windows import pdbutil
    from volatility3.framework import contexts
    from volatility3.framework.layers import physical
    import urllib.request
    import urllib.parse
    import tempfile
    import lzma
    import json
    import uuid
except ImportError as e:
    print(f"Error: Missing dependency {e}")
    print("Please install: pip install volatility3==2.27.0")
    sys.exit(1)

def download_symbols(image_path, symbols_dir):
    """下载 Windows 符号表"""
    if not os.path.exists(image_path):
        print(f"Error: Image file not found: {image_path}")
        return False

    symbols_dir = Path(symbols_dir)
    symbols_dir.mkdir(parents=True, exist_ok=True)

    print(f"Scanning image: {image_path}")

    try:
        # 构建context并加载镜像
        context = contexts.Context()

        # 使用 Path.as_uri() 代替 pathname2url()，更好地处理特殊字符
        # pathname2url() 无法正确处理路径中的 @ 等特殊字符
        try:
            file_url = Path(image_path).absolute().as_uri()
        except Exception as e:
            # 如果 as_uri() 失败（路径包含非 ASCII 字符），使用备用方法
            print(f"Warning: Path encoding issue, using fallback method: {e}")
            # 手动构建 file:// URL，对特殊字符进行编码
            import urllib.parse
            encoded_path = urllib.parse.quote(str(Path(image_path).absolute()), safe='/:')
            file_url = f'file:///{encoded_path.lstrip("/")}'

        context.config['FileLayer.location'] = file_url

        # 加载物理层
        layer = physical.FileLayer(context, 'FileLayer', name="FileLayer")
        context.add_layer(layer)

        layer_name = layer.name
        page_size = 0x1000

        # 扫描常见的Windows内核PDB名称
        pdb_names = [b'ntkrnlmp.pdb', b'ntoskrnl.pdb', b'krnl.pdb', b'ntkrpamp.pdb']

        print("Scanning PDB signatures...")

        # 进度回调 - 显示扫描进度
        def scan_progress(progress, description=""):
            if progress % 10 == 0:  # 每10%显示一次
                print(f"  Scanning: {progress}%")

        # 使用pdbname_scan扫描PDB签名
        # 增加maximum_invalid_count以提高大镜像扫描的成功率
        pdb_results = list(pdbutil.PDBUtility.pdbname_scan(
            context, layer_name, page_size, pdb_names,
            progress_callback=scan_progress,
            maximum_invalid_count=10000  # 增加到10000，默认值100太低
        ))

        if not pdb_results:
            print("Error: PDB information not found in memory image")
            return False

        # 使用第一个找到的内核PDB
        result = pdb_results[0]
        guid = result.get('GUID', '')
        age = result.get('age', 0)
        pdb_name = result.get('pdb_name', 'ntkrnlmp.pdb')

        # 使用英文标记，方便正则匹配
        print(f"PDB_INFO: {pdb_name}")
        print(f"  GUID: {guid}")
        print(f"  Age: {age}")

        # 检查符号表是否已存在
        symbol_path = symbols_dir / 'windows' / pdb_name / f"{guid}-{age}.json.xz"
        if symbol_path.exists():
            print(f"Symbol file already exists: {symbol_path}")
            return True

        # 创建临时目录（优先使用安全路径，避免非 ASCII 字符问题）
        temp_dir = Path(tempfile.gettempdir())

        # 检查临时目录路径是否包含非 ASCII 字符（会导致 as_uri() 问题）
        try:
            temp_dir_str = str(temp_dir)
            temp_dir_str.encode('ascii')
        except UnicodeEncodeError:
            # 临时目录包含非 ASCII 字符，使用当前目录作为备用
            temp_dir = Path.cwd()
            print(f"Warning: Temp directory contains non-ASCII characters, using current directory: {temp_dir}")

        temp_pdb_path = temp_dir / f"temp_pdb_{os.getpid()}_{uuid.uuid4().hex[:8]}.pdb"

        try:
            # 下载 PDB 文件（支持代理和进度显示）
            symbol_server = os.environ.get('LENS_SYMBOL_SERVER') or 'https://msdl.microsoft.com/download/symbols'
            symbol_server = symbol_server.rstrip('/')
            pdb_url = f"{symbol_server}/{pdb_name}/{guid}{age:01X}/{pdb_name}"
            print(f"Downloading PDB file...")
            print(f"  URL: {pdb_url}")

            # 使用 urllib 下载（最快）
            import urllib.request as req2
            import ssl

            # 创建 SSL 上下文，兼容旧版 Python（3.9 默认 TLS 可能过低）
            # Windows + Python 3.13 上 set_default_verify_paths() 可能找不到 CA bundle，
            # 优先用 certifi；若仍失败则禁用验证（微软符号服务器可信，风险低）
            try:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ca_loaded = False
                try:
                    import certifi
                    ssl_ctx.load_verify_locations(cafile=certifi.where())
                    ca_loaded = True
                except (ImportError, RuntimeError, OSError):
                    pass
                if not ca_loaded:
                    ssl_ctx.set_default_verify_paths()
            except AttributeError:
                ssl_ctx = ssl.create_default_context()

            # 检测系统代理
            proxies = None
            try:
                http_proxy = os.environ.get('http_proxy') or os.environ.get('HTTP_PROXY')
                https_proxy = os.environ.get('https_proxy') or os.environ.get('HTTPS_PROXY')
                if http_proxy or https_proxy:
                    proxy_handler = req2.ProxyHandler({
                        'http': http_proxy or '',
                        'https': https_proxy or ''
                    })
                    https_handler = req2.HTTPSHandler(context=ssl_ctx)
                    opener = req2.build_opener(proxy_handler, https_handler)
                    req2.install_opener(opener)
                    print(f"Proxy detected")
                else:
                    https_handler = req2.HTTPSHandler(context=ssl_ctx)
                    opener = req2.build_opener(https_handler)
                    req2.install_opener(opener)
            except:
                pass

            # 进度回调函数（避免重复打印）
            last_shown = [0]  # 用列表跟踪上次显示的百分比
            def show_progress(block_num, block_size, total_size):
                downloaded = block_num * block_size
                if total_size > 0:
                    percent = min(int(downloaded * 100 / total_size), 100)
                    # 每下载 25% 显示一次进度，避免重复
                    if percent % 25 == 0 and percent > 0 and percent != last_shown[0]:
                        filled = percent // 5
                        bar = '=' * filled + ' ' * (20 - filled)
                        print(f"  Download: [{bar}] {percent}%")
                        last_shown[0] = percent

            try:
                req2.urlretrieve(pdb_url, str(temp_pdb_path), reporthook=show_progress)
            except Exception as dl_err:
                # SSL 验证失败时降级重试（公司代理替换证书 / Python 找不到 CA bundle）
                err_msg = str(dl_err)
                if 'CERTIFICATE' in err_msg or 'SSL' in err_msg or 'certificate' in err_msg:
                    print(f"SSL verify failed, retrying without verification: {err_msg}")
                    unverified_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    unverified_ctx.check_hostname = False
                    unverified_ctx.verify_mode = ssl.CERT_NONE
                    unverified_handler = req2.HTTPSHandler(context=unverified_ctx)
                    # 复用代理设置（如有）
                    http_proxy = os.environ.get('http_proxy') or os.environ.get('HTTP_PROXY')
                    https_proxy = os.environ.get('https_proxy') or os.environ.get('HTTPS_PROXY')
                    if http_proxy or https_proxy:
                        ph = req2.ProxyHandler({'http': http_proxy or '', 'https': https_proxy or ''})
                        opener = req2.build_opener(ph, unverified_handler)
                    else:
                        opener = req2.build_opener(unverified_handler)
                    req2.install_opener(opener)
                    req2.urlretrieve(pdb_url, str(temp_pdb_path), reporthook=show_progress)
                else:
                    raise

            pdb_size = temp_pdb_path.stat().st_size

            # 转换 PDB 为 ISF 格式（使用绝对路径，避免 URI 编码问题）
            # 将路径转换为 file:// URI（Volatility 3 要求）
            try:
                temp_pdb_url = temp_pdb_path.absolute().as_uri()
            except Exception as e:
                # 如果 URI 转换失败，使用备用方法
                logger.error(f"URI 转换失败: {e}，尝试直接路径")
                temp_pdb_url = str(temp_pdb_path.absolute())

            # 创建context并加载PDB文件
            pdb_context = contexts.Context()
            pdb_context.config['pdbreader.FileLayer.location'] = temp_pdb_url

            pdb_layer = physical.FileLayer(pdb_context, 'pdbreader.FileLayer', 'FileLayer')
            pdb_context.add_layer(pdb_layer)

            # 使用PdbReader转换
            msf_layer_name, new_context = pdbutil.pdbconv.PdbReader.load_pdb_layer(pdb_context, temp_pdb_url)
            reader = pdbutil.pdbconv.PdbReader(new_context, temp_pdb_url, pdb_name)
            json_output = reader.get_json()

            # 将字典转换为 JSON 字符串
            json_str = json.dumps(json_output, indent=2, sort_keys=True)
            print(f"Symbol conversion successful, JSON size: {len(json_str)} bytes")

            # 确保目录存在
            os.makedirs(os.path.dirname(symbol_path), exist_ok=True)

            # 保存为JSON.xz文件
            with lzma.open(symbol_path, 'w') as f:
                f.write(bytes(json_str, 'utf-8'))

            print(f"Symbol file saved: {symbol_path}")
            print(f"Symbol file size: {symbol_path.stat().st_size} bytes")
            return True

        finally:
            # 清理临时文件
            try:
                if temp_pdb_path.exists():
                    temp_pdb_path.unlink()
            except:
                pass

    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    # 优先从环境变量获取路径（避免 Windows 命令行编码问题）
    image_path = os.environ.get('LENS_IMAGE_PATH')
    symbols_dir = os.environ.get('LENS_SYMBOLS_DIR')

    # 如果环境变量不存在，回退到命令行参数
    if not image_path or not symbols_dir:
        if len(sys.argv) < 3:
            print("Usage: script.py <image_file> <symbols_directory>")
            print("       Or set env vars: LENS_IMAGE_PATH and LENS_SYMBOLS_DIR")
            sys.exit(1)
        image_path = sys.argv[1]
        symbols_dir = sys.argv[2]

    success = download_symbols(image_path, symbols_dir)
    sys.exit(0 if success else 1)
'''

            scripts_dir = self._user_data_dir / 'scripts'
            scripts_dir.mkdir(parents=True, exist_ok=True)
            script_path = scripts_dir / 'download_symbols.py'

            try:
                script_path.write_text(script_content, encoding='utf-8')

                python_cmd = self._get_python_cmd()

                cmd = [python_cmd, str(script_path)]

                import os as os_module
                env = os_module.environ.copy()

                env['LENS_IMAGE_PATH'] = str(self.current_image['path'])
                env['LENS_SYMBOLS_DIR'] = str(self._get_symbols_base_dir('windows'))
                env['LENS_SYMBOL_SERVER'] = symbol_server

                proxy_url = self._build_proxy_url()
                if proxy_url:
                    env['http_proxy'] = proxy_url
                    env['https_proxy'] = proxy_url
                    logger.info(f"下载脚本使用代理: {proxy_url.split('@')[0] if '@' in proxy_url else proxy_url}")

                logger.info(f"执行下载命令: {' '.join(cmd)}")

                subprocess_kwargs = self._get_subprocess_kwargs(
                    env=env,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',  
                    errors='replace',  
                    timeout=300  
                )
                result = subprocess.run(cmd, **subprocess_kwargs)

                if result.returncode == 0:
                    self._hide_loading()
                    output = result.stdout + result.stderr
                    logger.info(f"符号表下载成功:\n{output}")

                    pdb_info = None
                    try:
                        import re
                        pdb_match = re.search(r'PDB_INFO:\s*(\S+)', output)
                        guid_match = re.search(r'GUID:\s*([0-9A-Fa-f]+)', output)
                        age_match = re.search(r'Age:\s*(\d+)', output)

                        if pdb_match and guid_match and age_match:
                            pdb_name = pdb_match.group(1)
                            guid = guid_match.group(1)
                            age = int(age_match.group(1))

                            pdb_info_path = self._get_os_symbols_dir('windows') / 'pdb_info.json'
                            pdb_info_path.parent.mkdir(parents=True, exist_ok=True)

                            import json

                            existing_data = {}
                            if pdb_info_path.exists():
                                try:
                                    existing_data = json.loads(pdb_info_path.read_text())
                                except:
                                    pass

                            if 'pdbs' not in existing_data:
                                existing_data['pdbs'] = {}

                            existing_data['pdbs'][self.current_image['path']] = {
                                'pdb_name': pdb_name,
                                'guid': guid,
                                'age': age
                            }

                            pdb_info_path.write_text(json.dumps(existing_data, indent=2), encoding='utf-8')
                            logger.info(f"已保存 PDB 信息到: {pdb_info_path}")
                    except Exception as e:
                        logger.warning(f"解析或保存 PDB 信息失败: {e}")

                    return {
                        'status': 'success',
                        'message': 'Windows符号表下载成功！',
                        'pdb_info': pdb_info
                    }
                else:
                    self._hide_loading()
                    error_output = result.stderr or result.stdout
                    logger.error(f"符号表下载失败:\n{error_output}")

                    if 'No module named' in error_output or '缺少依赖' in error_output:
                        return {
                            'status': 'error',
                            'message': f'缺少 Volatility 3 依赖\n\n'
                                      f'请安装: pip install volatility3==2.27.0'
                        }

                    return {
                        'status': 'error',
                        'message': f'符号表下载失败:\n\n{error_output[:500]}'
                    }

            except subprocess.TimeoutExpired:
                self._hide_loading()
                return {
                    'status': 'error',
                    'message': '下载超时（超过5分钟）\n\n请检查网络连接或手动下载'
                }
            except Exception as e:
                self._hide_loading()
                logger.error(f"执行下载脚本失败: {e}", exc_info=True)
                return {
                    'status': 'error',
                    'message': f'执行下载脚本失败: {str(e)}'
                }
            finally:
                pass

        except Exception as e:
            self._hide_loading()
            logger.error(f"下载Windows符号表失败: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'message': f'下载Windows符号表失败: {str(e)}'
            }

    def download_windows_symbols_via_vol(self) -> Dict[str, Any]:
        import os
        import subprocess
        import time

        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            os_type = self.current_image.get('os_type', '').lower()
            if os_type != 'windows':
                return {
                    'status': 'error',
                    'message': f'当前镜像不是Windows系统 (检测到: {os_type})'
                }

            vol_path = self._get_vol_path()
            if not vol_path:
                return {
                    'status': 'error',
                    'message': '未找到 vol 命令\n\n请先安装 Volatility 3:\npip install volatility3==2.27.0'
                }

            logger.info("使用 vol 命令下载符号表...")
            self._show_loading('正在下载Windows符号表...', '正在使用 vol 命令从微软官方下载...\n\n首次下载可能需要几分钟，请耐心等待。')

            symbol_dir = self._get_os_symbols_dir('windows')
            symbol_dir.mkdir(parents=True, exist_ok=True)

            nested_dir = symbol_dir / 'windows'
            if nested_dir.exists():
                logger.info(f"发现嵌套目录 {nested_dir}，正在清理...")
                import shutil
                try:
                    for pdb_dir in nested_dir.glob('*.pdb'):
                        target_pdb_dir = symbol_dir / pdb_dir.name
                        if not target_pdb_dir.exists():
                            shutil.move(str(pdb_dir), str(target_pdb_dir))
                            logger.info(f"已移动 {pdb_dir.name} 到正确位置")
                    shutil.rmtree(nested_dir, ignore_errors=True)
                    logger.info("已清理嵌套目录")
                except Exception as e:
                    logger.warning(f"清理嵌套目录失败: {e}")

            initial_files = set()
            for pdb_dir in symbol_dir.glob('*.pdb'):
                if pdb_dir.is_dir():
                    for f in pdb_dir.glob('*.json.xz'):
                        initial_files.add(f)
            logger.info(f"下载前符号表文件数: {len(initial_files)}")

            vol_cmd = [vol_path, '-f', self.current_image['path'],
                      '-s', str(self._get_symbols_base_dir('windows')),
                      'windows.info.Info']
            logger.info(f"执行 vol 命令: {' '.join(vol_cmd)}")

            env = os.environ.copy()
            proxy_url = self._build_proxy_url()
            if proxy_url:
                env['http_proxy'] = proxy_url
                env['https_proxy'] = proxy_url
                logger.info(f"vol 命令使用代理")

            max_retries = 3
            retry_count = 0
            result = None

            subprocess_kwargs = self._get_subprocess_kwargs(
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )

            while retry_count < max_retries:
                retry_count += 1
                logger.info(f"等待 vol 命令执行完成... (尝试 {retry_count}/{max_retries})")

                try:
                    result = subprocess.run(vol_cmd, timeout=300, **subprocess_kwargs)

                    if result.returncode == 0 and 'Variable' in result.stdout:
                        logger.info(f"vol 命令执行成功")
                        break

                    if 'RemoteDisconnected' in result.stderr or 'connection' in result.stderr.lower():
                        logger.warning(f"网络连接中断，准备重试...")
                        if retry_count < max_retries:
                            import time
                            time.sleep(2)  
                            continue

                except subprocess.TimeoutExpired:
                    logger.warning(f"vol 命令超时，准备重试...")
                    if retry_count < max_retries:
                        continue

            if result:
                logger.info(f"vol 命令执行完成，返回码: {result.returncode}")
                if result.stdout:
                    logger.info(f"vol stdout: {result.stdout[:2000]}")
                if result.stderr:
                    logger.warning(f"vol stderr: {result.stderr[:2000]}")

            self._hide_loading()

            try:
                from backend.volatility_wrapper import VolatilityWrapper
                migrated = VolatilityWrapper.migrate_volatility_symbols(self._symbols_dir)
                if migrated > 0:
                    logger.info(f"从 Volatility 缓存目录迁移了 {migrated} 个符号表文件")
            except Exception as e:
                logger.warning(f"迁移 Volatility 缓存符号表失败: {e}")

            output = ''
            if result:
                output = (result.stdout or '') + '\n' + (result.stderr or '')

            vol_symbol_info = self._copy_windows_symbol_from_vol_output(output, symbol_dir)
            if vol_symbol_info and self.current_image:
                self._save_pdb_info(
                    self.current_image['path'],
                    vol_symbol_info['pdb_name'],
                    vol_symbol_info['guid'],
                    int(vol_symbol_info['age'])
                )

            symbol_files = []
            for pdb_dir in symbol_dir.glob('*.pdb'):
                if pdb_dir.is_dir():
                    symbol_files.extend(pdb_dir.glob('*.json.xz'))
            symbol_files = set(symbol_files)
            new_files = symbol_files - initial_files

            if vol_symbol_info:
                return {
                    'status': 'success',
                    'message': f"Windows符号表下载成功！已匹配 {vol_symbol_info['pdb_name']} {vol_symbol_info['guid']}-{vol_symbol_info['age']}"
                }
            elif new_files:
                self._save_pdb_info_from_symbols(symbol_files, symbol_dir)
                return {
                    'status': 'success',
                    'message': f'Windows符号表下载成功！（已下载 {len(new_files)} 个符号表文件）'
                }
            elif symbol_files:
                self._save_pdb_info_from_symbols(symbol_files, symbol_dir)
                return {
                    'status': 'success',
                    'message': f'Windows符号表已就绪！（共 {len(symbol_files)} 个符号表文件）'
                }
            else:
                return {
                    'status': 'error',
                    'message': '符号表下载失败，请检查网络连接或尝试使用代理'
                }

        except Exception as e:
            self._hide_loading()
            logger.error(f"vol 命令下载符号表失败: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'message': f'下载失败: {str(e)}'
            }

    def _parse_windows_symbol_path(self, symbol_path: Path) -> Optional[Dict[str, Any]]:
        match = re.match(r'([A-Fa-f0-9]+)-(\d+)\.json(?:\.xz)?$', symbol_path.name)
        if not match or not symbol_path.parent.name.lower().endswith('.pdb'):
            return None
        return {
            'pdb_name': symbol_path.parent.name,
            'guid': match.group(1),
            'age': int(match.group(2)),
            'path': symbol_path
        }

    def _copy_windows_symbol_from_vol_output(self, output: str, symbol_dir: Path) -> Optional[Dict[str, Any]]:
        symbol_match = re.search(r'(?im)^\s*Symbols\s+(.+?)\s*$', output or '')
        if not symbol_match:
            return None

        symbol_ref = symbol_match.group(1).strip()
        if not symbol_ref or symbol_ref.lower() in ('n/a', 'none'):
            return None

        try:
            if symbol_ref.startswith('file://'):
                parsed = urlparse(symbol_ref)
                source_path = Path(unquote(parsed.path))
            else:
                source_path = Path(symbol_ref)

            parsed_info = self._parse_windows_symbol_path(source_path)
            if not parsed_info:
                logger.warning(f"vol 输出的 Symbols 路径不是可识别的 Windows PDB 符号: {symbol_ref}")
                return None

            target_path = (
                symbol_dir
                / parsed_info['pdb_name']
                / f"{parsed_info['guid']}-{parsed_info['age']}.json.xz"
            )
            target_path.parent.mkdir(parents=True, exist_ok=True)

            if source_path.exists() and source_path.resolve() != target_path.resolve():
                shutil.copy2(source_path, target_path)
                logger.info(f"已从 vol 命中路径复制匹配符号表: {source_path} -> {target_path}")
            elif target_path.exists():
                logger.info(f"vol 命中的匹配符号表已在工具目录中: {target_path}")
            else:
                logger.warning(f"vol 输出了 Symbols 路径，但本地文件不存在: {source_path}")
                return None

            parsed_info['path'] = target_path
            return parsed_info
        except Exception as e:
            logger.warning(f"解析或复制 vol Symbols 路径失败: {e}")
            return None

    def _save_pdb_info_from_symbols(self, symbol_files, symbol_dir, required_info: Optional[Dict[str, Any]] = None):
        try:
            import json

            pdb_info_path = symbol_dir / 'pdb_info.json'

            existing_data = {}
            if pdb_info_path.exists():
                try:
                    existing_data = json.loads(pdb_info_path.read_text())
                except:
                    pass

            if 'pdbs' not in existing_data:
                existing_data['pdbs'] = {}

            required_pdb = str(required_info.get('pdb_name', '')).lower() if required_info else ''
            required_guid = str(required_info.get('guid', '')).lower() if required_info else ''
            required_age = str(required_info.get('age', '')) if required_info else ''

            for symbol_file in sorted(symbol_files, key=lambda p: str(p)):
                try:
                    rel_path = symbol_file.relative_to(symbol_dir)
                    parts = rel_path.parts  

                    if len(parts) >= 2:
                        pdb_name = parts[0]
                        filename = parts[1]
                        match = re.match(r'([A-Fa-f0-9]+)-(\d+)\.json\.xz', filename)
                        if match:
                            guid = match.group(1)
                            age = int(match.group(2))

                            if required_info:
                                if (
                                    pdb_name.lower() != required_pdb
                                    or guid.lower() != required_guid
                                    or str(age) != required_age
                                ):
                                    continue

                            image_path = self.current_image.get('path') if self.current_image else ''
                            if image_path:
                                existing_data['pdbs'][image_path] = {
                                    'pdb_name': pdb_name,
                                    'guid': guid,
                                    'age': age
                                }

                            logger.info(f"已保存 PDB 信息: {pdb_name} - {guid}-{age}")
                            break
                except Exception as e:
                    logger.warning(f"解析符号表文件 {symbol_file} 失败: {e}")

            pdb_info_path.write_text(json.dumps(existing_data, indent=2), encoding='utf-8')
            logger.info(f"PDB 信息已保存到: {pdb_info_path}")

        except Exception as e:
            logger.warning(f"保存 PDB 信息失败: {e}")

    def _copy_symbols_from_volatility3_cache(self) -> int:
        import platform
        import shutil

        possible_paths = []

        try:
            import site
            for site_dir in site.getsitepackages():
                possible_paths.append(Path(site_dir) / 'volatility3' / 'symbols' / 'windows')
        except:
            pass

        try:
            import site
            usersite = site.getusersitepackages()
            if usersite:
                possible_paths.append(Path(usersite) / 'volatility3' / 'symbols' / 'windows')
        except:
            pass

        system = platform.system()

        if system == 'Linux':
            possible_paths.extend([
                Path('/usr/local/lib/python3.13/dist-packages/volatility3/symbols/windows'),
                Path('/usr/local/lib/python3.12/dist-packages/volatility3/symbols/windows'),
                Path('/usr/local/lib/python3.11/dist-packages/volatility3/symbols/windows'),
                Path('/usr/lib/python3/dist-packages/volatility3/symbols/windows'),
            ])
        elif system == 'Darwin':  
            possible_paths.extend([
                Path('/Library/Python/3.9/site-packages/volatility3/symbols/windows'),
                Path('/Library/Python/3.10/site-packages/volatility3/symbols/windows'),
                Path('/Library/Python/3.11/site-packages/volatility3/symbols/windows'),
                Path('/Library/Python/3.12/site-packages/volatility3/symbols/windows'),
                Path('/Library/Python/3.13/site-packages/volatility3/symbols/windows'),
                Path.home() / 'Library' / 'Python' / '3.9' / 'lib' / 'python' / 'site-packages' / 'volatility3' / 'symbols' / 'windows',
                Path.home() / 'Library' / 'Python' / '3.10' / 'lib' / 'python' / 'site-packages' / 'volatility3' / 'symbols' / 'windows',
                Path.home() / 'Library' / 'Python' / '3.11' / 'lib' / 'python' / 'site-packages' / 'volatility3' / 'symbols' / 'windows',
            ])
        elif system == 'Windows':
            possible_paths.extend([
                Path('C:/Python39/Lib/site-packages/volatility3/symbols/windows'),
                Path('C:/Python310/Lib/site-packages/volatility3/symbols/windows'),
                Path('C:/Python311/Lib/site-packages/volatility3/symbols/windows'),
                Path('C:/Python312/Lib/site-packages/volatility3/symbols/windows'),
                Path(os.path.expanduser('~/AppData/Local/Programs/Python/Python39/Lib/site-packages/volatility3/symbols/windows')),
                Path(os.path.expanduser('~/AppData/Local/Programs/Python/Python310/Lib/site-packages/volatility3/symbols/windows')),
                Path(os.path.expanduser('~/AppData/Roaming/Python/Python39/site-packages/volatility3/symbols/windows')),
            ])

        try:
            subprocess_kwargs = self._get_subprocess_kwargs(capture_output=True, text=True, timeout=10)
            python_cmd = self._get_python_cmd()
            result = subprocess.run([python_cmd, '-m', 'pip', 'show', 'volatility3'], **subprocess_kwargs)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('Location:'):
                        location = Path(line.split(':', 1)[1].strip())
                        possible_paths.append(location / 'volatility3' / 'symbols' / 'windows')
                        break
        except:
            pass

        logger.info(f"检查可能的符号表缓存路径，共 {len(possible_paths)} 个")

        copied_count = 0
        target_dir = self._get_os_symbols_dir('windows')
        target_dir.mkdir(parents=True, exist_ok=True)

        for source_path in possible_paths:
            if source_path and source_path.exists():
                logger.info(f"找到 volatility3 符号表缓存: {source_path}")

                for symbol_file in source_path.rglob('*.json.xz'):
                    try:
                        rel_path = symbol_file.relative_to(source_path)
                        target_file = target_dir / rel_path
                        target_file.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(symbol_file, target_file)
                        copied_count += 1
                        logger.info(f"复制符号表: {symbol_file.name}")
                    except Exception as e:
                        logger.warning(f"复制符号表失败 {symbol_file}: {e}")

                if copied_count > 0:
                    symbol_files = list(target_dir.rglob('*.json.xz'))
                    self._save_pdb_info_from_symbols(symbol_files, target_dir)
                    break

        return copied_count


    def check_volatility3(self) -> Dict[str, Any]:
        try:
            import subprocess
            import platform

            system = platform.system()
            logger.info(f"检测 Volatility 3，平台: {system}")
            settings = self._load_config().get('settings', {})

            python_cmd = self._get_python_cmd()
            can_import, import_error = self._verify_installed_dependency(
                python_cmd, 'volatility3'
            )
            if can_import:
                logger.info(f"目标 Python 可导入 Volatility 3: {python_cmd}")
            else:
                logger.info(
                    f"目标 Python 无法导入 Volatility 3: "
                    f"{python_cmd} -> {import_error}"
                )

            vol_path = None
            vol_works = False

            vol_path = self._get_vol_path()

            cache_key = f'_vol_verified_{vol_path}'
            if vol_path and hasattr(self, cache_key):
                vol_works = getattr(self, cache_key)
                logger.info(f"使用缓存的 vol 验证结果: {vol_path} -> {vol_works}")
            elif vol_path:
                try:
                    vol_path_str = str(vol_path).replace('\\', '/')
                    clean_env = os.environ.copy()
                    clean_env.pop('PYTHONPATH', None)
                    clean_env.pop('PYTHONHOME', None)
                    subprocess_kwargs = self._get_subprocess_kwargs(
                        capture_output=True,
                        text=True,
                        timeout=30,
                        env=clean_env,
                        cwd=str(Path.home())
                    )
                    result = subprocess.run(
                        [vol_path_str, '--help'],
                        **subprocess_kwargs
                    )
                    output = result.stdout + result.stderr
                    vol_works = result.returncode == 0 or 'Volatility 3' in output or 'volatility' in output.lower()
                    if vol_works:
                        logger.info(f"Vol 命令可用: {vol_path}")
                        setattr(self, cache_key, True)
                    else:
                        logger.warning(f"Vol 命令存在但不可用: {vol_path}")
                except Exception as e:
                    logger.warning(f"验证 vol 命令失败: {e}")
                    vol_works = False

            configured_vol_path = settings.get('custom_vol_path')
            explicit_vol_selected = False
            if configured_vol_path and vol_path:
                configured_normalized = os.path.normcase(os.path.abspath(
                    os.path.expanduser(str(configured_vol_path))
                ))
                selected_normalized = os.path.normcase(os.path.abspath(
                    os.path.expanduser(str(vol_path))
                ))
                explicit_vol_selected = configured_normalized == selected_normalized

            if explicit_vol_selected:
                installed = vol_works
            else:
                installed = can_import and bool(vol_path) and vol_works

            version = None
            if can_import:
                try:
                    clean_env = os.environ.copy()
                    clean_env.pop('PYTHONPATH', None)
                    clean_env.pop('PYTHONHOME', None)
                    subprocess_kwargs = self._get_subprocess_kwargs(
                        capture_output=True,
                        text=True,
                        timeout=10,
                        env=clean_env,
                        cwd=str(Path.home())
                    )
                    version_result = subprocess.run(
                        [
                            python_cmd,
                            '-c',
                            'import importlib.metadata as m; '
                            'print(m.version("volatility3"))'
                        ],
                        **subprocess_kwargs
                    )
                    if version_result.returncode == 0:
                        version = version_result.stdout.strip()
                except Exception as e:
                    logger.warning(f"无法读取目标 Volatility 3 版本: {e}")

            return {
                'status': 'success',
                'data': {
                    'installed': installed,
                    'platform': system,
                    'vol_command': bool(vol_path),
                    'can_import': can_import,
                    'vol_works': vol_works,
                    'vol_path': vol_path,
                    'explicit_vol_selected': explicit_vol_selected,
                    'python_path': python_cmd,
                    'version': version,
                    'install_command': self._get_install_command(system)
                }
            }
        except Exception as e:
            logger.error(f"检测 Volatility 3 失败: {e}", exc_info=True)
            return {
                'status': 'error',
                'message': f'检测失败: {str(e)}'
            }

    def _apply_explicit_volatility_status(
        self, dependencies: Dict[str, Any]
    ) -> Dict[str, Any]:
        settings = self._load_config().get('settings', {})
        if not settings.get('custom_vol_path'):
            return dependencies

        status = self.check_volatility3()
        data = status.get('data', {}) if status.get('status') == 'success' else {}
        if not data.get('explicit_vol_selected'):
            return dependencies

        info = dependencies.setdefault('volatility3', {})
        info['installed'] = bool(data.get('installed'))
        info['runtime_path'] = data.get('vol_path')
        info['runtime_source'] = 'custom_vol'
        if data.get('version'):
            info['version'] = data['version']
        if info['installed']:
            info['error'] = None
        elif not info.get('error'):
            info['error'] = '自定义 vol 命令无法运行'
        return dependencies

    def _get_install_command(self, platform: str) -> str:
        mirror = ' -i https://pypi.tuna.tsinghua.edu.cn/simple'
        volatility_package = f'volatility3=={self.VOLATILITY3_VERSION}'

        if platform == 'Windows':
            return f'pip install{mirror} {volatility_package}'
        elif platform == 'Darwin':
            return f'pip3 install{mirror} {volatility_package}'
        else:  
            return f'pip3 install{mirror} {volatility_package} --break-system-packages'

    def check_all_dependencies(self) -> Dict[str, Any]:
        try:
            from backend.volatility_wrapper import VolatilityWrapper

            python_cmd = self._get_python_cmd()
            dependencies = VolatilityWrapper.check_all_dependencies(python_cmd)
            dependencies = self._apply_explicit_volatility_status(dependencies)

            install_commands = {
                'volatility3': f'pip install volatility3=={self.VOLATILITY3_VERSION}',
                'pycryptodome': 'pip install pycryptodome',
                'pypykatz': 'pip install pypykatz',
                'openai': 'pip install openai',
            }

            import platform
            system = platform.system()
            if system == 'Linux':
                install_commands = {k: v + ' --break-system-packages' for k, v in install_commands.items()}

            return {
                'success': True,
                'dependencies': dependencies,
                'install_commands': install_commands,
                'python_path': python_cmd
            }
        except Exception as e:
            logger.error(f"检测依赖失败: {e}")
            return {
                'success': False,
                'error': str(e),
                'dependencies': {},
                'install_commands': {}
            }

    def install_volatility3(self) -> Dict[str, Any]:
        try:
            import subprocess
            import sys
            import platform

            system = platform.system()
            logger.info(f"安装 Volatility 3，平台: {system}")

            import os
            is_frozen = getattr(sys, 'frozen', False)
            is_nuitka = '__compiled__' in globals() or hasattr(sys, '_nuitka_binary')
            executable_exists = os.path.exists(sys.executable) if sys.executable else False
            is_packaged = is_frozen or '.app' in sys.executable or '.exe' in sys.executable or is_nuitka or not executable_exists
            logger.info(f"检测到打包环境: {is_packaged}, is_frozen={is_frozen}, is_nuitka={is_nuitka}, executable_exists={executable_exists}, executable={sys.executable}")

            python_cmd = self._get_python_cmd()
            logger.info(f"使用 Python 命令: {python_cmd}")

            python_available = False
            try:
                logger.info(f"检测 Python 可用性: {python_cmd} --version")
                subprocess_kwargs = self._get_subprocess_kwargs(
                    capture_output=True,
                    timeout=10
                )
                result = subprocess.run([python_cmd, '--version'], **subprocess_kwargs)
                python_available = result.returncode == 0
                logger.info(f"Python 可用性检测: {'成功' if python_available else '失败'}, stdout={result.stdout.decode('utf-8', errors='ignore').strip()}")
            except Exception as e:
                logger.error(f"Python 可用性检测异常: {e}")

            if not python_available:
                logger.error(f"Python 不可用: {python_cmd}")
                return {
                    'status': 'error',
                    'message': self._get_manual_install_message(system)
                }

            self._show_loading('正在安装 Volatility 3，请稍候...')

            try:

                volatility_package = f'volatility3=={self.VOLATILITY3_VERSION}'
                cmd = [python_cmd, '-m', 'pip', 'install', '-i', 'https://pypi.tuna.tsinghua.edu.cn/simple', volatility_package, 'pycryptodome']

                logger.info(f"执行安装: {python_cmd} -m pip install {volatility_package} pycryptodome")
                logger.info(f"打包环境: {is_packaged}, 使用 Python: {python_cmd}")

                import os
                clean_env = os.environ.copy()
                clean_env.pop('PYTHONPATH', None)
                clean_env.pop('PYTHONHOME', None)
                clean_env['PYTHONIOENCODING'] = 'utf-8'

                cwd = str(Path.home())

                subprocess_kwargs = self._get_subprocess_kwargs(
                    capture_output=True,
                    text=True,
                    timeout=300,  
                    env=clean_env,
                    cwd=cwd
                )
                result = subprocess.run(cmd, **subprocess_kwargs)

                stderr = result.stderr or ''
                if result.returncode != 0 and 'externally-managed-environment' in stderr:
                    logger.info("检测到 externally-managed-environment，使用 --break-system-packages 重试")
                    cmd.append('--break-system-packages')
                    result = subprocess.run(cmd, **subprocess_kwargs)

                if result.returncode == 0:
                    self._hide_loading()
                    logger.info("Volatility 3 安装成功")

                    version = None
                    try:
                        subprocess_kwargs2 = self._get_subprocess_kwargs(
                            capture_output=True,
                            text=True,
                            timeout=5,
                            env=clean_env,
                            cwd=cwd
                        )
                        result2 = subprocess.run([python_cmd, '-c', 'import volatility3; print(volatility3.__version__)'], **subprocess_kwargs2)
                        if result2.returncode == 0:
                            version = result2.stdout.strip()
                            logger.info(f"Volatility3 版本: {version}")
                    except Exception as e:
                        logger.warning(f"无法获取 volatility3 版本: {e}")

                    version_info = f' (版本 {version})' if version else ''
                    if system in ['Darwin', 'Linux']:
                        message = f'Volatility 3 安装成功{version_info}！\n\n使用清华镜像加速下载。\n\n如果 vol 命令不可用，请将以下路径添加到 PATH:\n~/Library/Python/3.9/bin (macOS)\n~/.local/bin (Linux)'
                    else:
                        message = f'Volatility 3 安装成功{version_info}！\n\n使用清华镜像加速下载。\n\n现在可以使用内存分析功能了。'

                    return {
                        'status': 'success',
                        'message': message,
                        'version': version
                    }
                else:
                    self._hide_loading()
                    error_msg = result.stderr or result.stdout or '未知错误'
                    logger.error(f"Volatility 3 安装失败: {error_msg}")

                    return {
                        'status': 'error',
                        'message': f'自动安装失败：\n{error_msg}\n\n{self._get_manual_install_message(system)}'
                    }
            except subprocess.TimeoutExpired:
                self._hide_loading()
                return {
                    'status': 'error',
                    'message': f'安装超时，请检查网络连接。\n\n{self._get_manual_install_message(system)}'
                }
            except FileNotFoundError:
                self._hide_loading()
                return {
                    'status': 'error',
                    'message': f'未找到 pip 命令。\n\n{self._get_manual_install_message(system)}'
                }
            except Exception as e:
                self._hide_loading()
                logger.error(f"安装 Volatility 3 异常: {e}", exc_info=True)
                return {
                    'status': 'error',
                    'message': f'安装异常：{str(e)}\n\n{self._get_manual_install_message(system)}'
                }
        except Exception as e:
            self._hide_loading()
            logger.error(f"安装 Volatility 3 失败: {e}")
            return {
                'status': 'error',
                'message': f'安装失败: {str(e)}'
            }

    def install_dependency(self, package_name: str) -> Dict[str, Any]:
        python_cmd = self._get_python_cmd()
        valid, error = self._validate_python_executable(python_cmd)
        if not valid:
            return {
                'status': 'error',
                'message': (
                    f'当前 Python 不可用：{python_cmd}\n\n'
                    f'{error}\n\n请重新选择 Python，或恢复默认设置。'
                ),
                'package': package_name
            }
        return self._install_dependency_for_python(package_name, python_cmd)

    def _install_dependency_for_python(
        self, package_name: str, python_cmd: str
    ) -> Dict[str, Any]:
        try:
            import subprocess
            import sys
            import platform
            import os

            system = platform.system()
            logger.info(f"安装依赖: {package_name}, 平台: {system}")

            self._show_loading(f'正在安装 {package_name}，请稍候...')

            target_python_version = self._get_python_version(python_cmd)
            if target_python_version:
                logger.info(
                    f"目标 Python 版本: "
                    f"{target_python_version[0]}.{target_python_version[1]}"
                )

            install_package = package_name
            if package_name == 'volatility3':
                install_package = f'volatility3=={self.VOLATILITY3_VERSION}'
            if package_name == 'pypykatz':
                check_version = target_python_version or sys.version_info[:2]
                if check_version < (3, 10):
                    install_package = 'pypykatz==0.5.0'
                    logger.info(f"Python {check_version[0]}.{check_version[1]} 检测到，使用 pypykatz 0.5.0")

                prepared, prepare_message = (
                    self._prepare_pypykatz_dependencies(python_cmd)
                )
                if not prepared:
                    self._hide_loading()
                    logger.error(
                        f"pypykatz 平台依赖准备失败: {prepare_message}"
                    )
                    return {
                        'status': 'error',
                        'message': (
                            'pypykatz 的平台依赖安装失败。\n\n'
                            f'目标 Python：{python_cmd}\n'
                            f'错误：{prepare_message}'
                        ),
                        'package': package_name
                    }

            logger.info(f"执行安装: {python_cmd} -m pip install {install_package}")

            success, message = self._run_pip_install(python_cmd, [install_package])

            if success:
                verified, verify_error = self._verify_installed_dependency(python_cmd, package_name)

                if not verified and package_name == 'pycryptodome':
                    logger.warning(
                        "pycryptodome 安装命令成功但 Crypto 仍不可导入，"
                        "开始修复目标 Python 的安装位置"
                    )
                    success, message, verified, verify_error = (
                        self._repair_pycryptodome_install(
                            python_cmd, install_package
                        )
                    )

                if not success or not verified:
                    self._hide_loading()
                    error_detail = verify_error or message or '安装后无法导入'
                    logger.error(f"{package_name} 安装后验证失败: {error_detail}")
                    return {
                        'status': 'error',
                        'message': (
                            f'{package_name} 安装后仍无法加载。\n\n'
                            f'目标 Python：{python_cmd}\n'
                            f'错误：{error_detail}'
                        ),
                        'package': package_name
                    }

                self._hide_loading()
                logger.info(f"{package_name} 安装并验证成功")

                if package_name == 'pycryptodome':
                    pypykatz_installed, _ = self._verify_installed_dependency(
                        python_cmd, 'pypykatz'
                    )
                    if pypykatz_installed:
                        logger.info("pypykatz 已安装")
                        self._fix_pypykatz_compatibility(python_cmd)
                    else:
                        logger.info("同时安装 pypykatz...")
                        pypykatz_result = self._install_package('pypykatz', python_cmd)
                        if pypykatz_result['status'] == 'success':
                            self._fix_pypykatz_compatibility(python_cmd)
                            return {
                                'status': 'success',
                                'message': f'{package_name} 和 pypykatz 安装成功！\n\n请重新执行插件即可使用。',
                                'package': f'{package_name}, pypykatz'
                            }
                        else:
                            return {
                                'status': 'success',
                                'message': f'{package_name} 安装成功！pypykatz 安装失败，明文密码提取功能不可用。',
                                'package': package_name
                            }

                if package_name == 'pypykatz':
                    self._fix_pypykatz_compatibility(python_cmd)

                return {
                    'status': 'success',
                    'message': f'{package_name} 安装成功！\n\n请重新执行插件即可使用。',
                    'package': package_name
                }
            else:
                self._hide_loading()
                logger.error(f"{package_name} 安装失败: {message}")
                return {
                    'status': 'error',
                    'message': f'安装失败：{message}\n\n请重试',
                    'package': package_name
                }

        except subprocess.TimeoutExpired:
            self._hide_loading()
            return {
                'status': 'error',
                'message': f'安装超时，请检查网络连接后重试。'
            }
        except Exception as e:
            self._hide_loading()
            logger.error(f"安装 {package_name} 异常: {e}")
            return {
                'status': 'error',
                'message': f'安装失败，请重试。'
            }

    def _verify_installed_dependency(
        self, python_cmd: str, package_name: str
    ) -> Tuple[bool, str]:
        import_statements = {
            'volatility3': 'import volatility3',
            'pycryptodome': 'from Crypto.Cipher import AES',
            'pypykatz': 'from pypykatz.pypykatz import pypykatz',
            'openai': 'from openai import OpenAI',
        }
        import_statement = import_statements.get(package_name, f'import {package_name}')

        clean_env = self._get_clean_python_env()

        subprocess_kwargs = self._get_subprocess_kwargs(
            capture_output=True,
            text=True,
            timeout=30,
            env=clean_env,
            cwd=str(Path.home())
        )

        try:
            result = subprocess.run(
                [python_cmd, '-c', import_statement],
                **subprocess_kwargs
            )
        except Exception as e:
            return False, str(e)

        if result.returncode == 0:
            return True, ''

        error = (result.stderr or result.stdout or '未知导入错误').strip()
        return False, error

    def _run_pip_install(self, python_cmd: str, packages: list) -> Tuple[bool, str]:
        import subprocess
        import platform

        system = platform.system()

        mirrors = [
            (['-i', 'https://pypi.tuna.tsinghua.edu.cn/simple'], '清华'),
            (['-i', 'https://mirrors.aliyun.com/pypi/simple/'], '阿里云'),
            ([], 'PyPI官方'),
        ]

        clean_env = self._get_clean_python_env()

        subprocess_kwargs = self._get_subprocess_kwargs(
            capture_output=True, text=True, timeout=300,
            env=clean_env, cwd=str(Path.home())
        )

        for mirror_args, mirror_name in mirrors:
            cmd = [python_cmd, '-m', 'pip', 'install'] + mirror_args + packages

            logger.info(f"尝试 {mirror_name} 镜像安装: {' '.join(cmd)}")

            result = subprocess.run(cmd, **subprocess_kwargs)

            if result.returncode == 0:
                return True, result.stdout or '安装成功'

            stderr = result.stderr or ''

            if 'externally-managed-environment' in stderr:
                logger.info("检测到 externally-managed-environment，使用 --break-system-packages 重试")
                cmd.append('--break-system-packages')
                result = subprocess.run(cmd, **subprocess_kwargs)
                if result.returncode == 0:
                    return True, result.stdout or '安装成功'
                stderr = result.stderr or stderr

            if '403' in stderr or 'ConnectionError' in stderr or 'Temporary failure' in stderr:
                logger.warning(f"{mirror_name} 镜像不可用 (403/连接失败)，切换...")
                continue

            if '404' in stderr:
                logger.warning(f"{mirror_name} 镜像无此包，切换...")
                continue

            return False, stderr or result.stdout or '安装失败'

        return False, stderr or result.stdout or '安装失败'

    def _prepare_pypykatz_dependencies(
        self, python_cmd: str
    ) -> Tuple[bool, str]:
        target_platform = self._get_python_platform(python_cmd)
        if not target_platform:
            logger.warning(
                "无法识别目标 Python 平台，按默认依赖解析安装 pypykatz"
            )
            return True, ''

        system, machine = target_platform
        normalized_machine = machine.lower().replace('-', '').replace('_', '')
        if system != 'win32' or normalized_machine not in ('arm64', 'aarch64'):
            return True, ''

        cryptography_package = 'cryptography==46.0.3'
        logger.info(
            "检测到 Windows ARM64 Python，预装带官方 ARM64 wheel 的 "
            f"{cryptography_package}"
        )
        success, message = self._run_pip_install(
            python_cmd, [cryptography_package]
        )
        if not success:
            return False, message

        return True, message

    def _repair_pycryptodome_install(
        self, python_cmd: str, install_package: str
    ) -> Tuple[bool, str, bool, str]:
        success, message = self._run_pip_install(
            python_cmd,
            ['--force-reinstall', '--no-cache-dir', install_package]
        )
        verify_error = ''
        if success:
            verified, verify_error = self._verify_installed_dependency(
                python_cmd, 'pycryptodome'
            )
            if verified:
                return True, message, True, ''

        for target_path in self._get_python_package_paths(python_cmd):
            logger.warning(
                "pycryptodome 常规重装后仍不可导入，"
                f"尝试定点安装到: {target_path}"
            )
            success, message = self._run_pip_install(
                python_cmd,
                [
                    '--upgrade',
                    '--force-reinstall',
                    '--no-cache-dir',
                    '--target',
                    target_path,
                    install_package,
                ]
            )
            if not success:
                continue
            verified, verify_error = self._verify_installed_dependency(
                python_cmd, 'pycryptodome'
            )
            if verified:
                return True, message, True, ''

        return success, message, False, verify_error

    def _install_package(
        self, package_name: str, python_cmd: str = None
    ) -> Dict[str, Any]:
        import subprocess
        import platform

        system = platform.system()
        python_cmd = python_cmd or self._get_python_cmd()

        python_version = self._get_python_version(python_cmd) or sys.version_info[:2]

        install_package = package_name
        if package_name == 'pypykatz' and python_version < (3, 10):
            install_package = 'pypykatz==0.5.0'
            logger.info(f"Python {python_version[0]}.{python_version[1]} 检测到，使用 pypykatz 0.5.0")

        if package_name == 'pypykatz':
            prepared, prepare_message = self._prepare_pypykatz_dependencies(
                python_cmd
            )
            if not prepared:
                logger.error(
                    f"pypykatz 平台依赖准备失败: {prepare_message}"
                )
                return {'status': 'error', 'message': prepare_message}

        logger.info(f"执行安装: {python_cmd} -m pip install {install_package}")
        success, message = self._run_pip_install(python_cmd, [install_package])

        if success:
            verified, verify_error = self._verify_installed_dependency(
                python_cmd, package_name
            )
            if not verified and package_name == 'pycryptodome':
                logger.warning(
                    "pycryptodome 安装命令成功但 Crypto 仍不可导入，"
                    "开始修复目标 Python 的安装位置"
                )
                success, message, verified, verify_error = (
                    self._repair_pycryptodome_install(
                        python_cmd, install_package
                    )
                )

            if not success or not verified:
                error_detail = verify_error or message or '安装后无法导入'
                logger.error(f"{package_name} 安装后验证失败: {error_detail}")
                return {'status': 'error', 'message': error_detail}

            logger.info(f"{package_name} 安装并验证成功")
            return {'status': 'success', 'message': f'{package_name} 安装成功'}
        else:
            logger.error(f"{package_name} 安装失败: {message}")
            return {'status': 'error', 'message': message}

    def _fix_pypykatz_compatibility(self, python_cmd: str = None):
        import subprocess
        try:
            import platform
            system = platform.system()

            is_frozen = getattr(sys, 'frozen', False)
            is_nuitka = '__compiled__' in globals() or hasattr(sys, '_nuitka_binary')
            is_packaged = is_frozen or '.app' in sys.executable or '.exe' in sys.executable or is_nuitka

            python_cmd = python_cmd or self._get_python_cmd()

            clean_env = self._get_clean_python_env()
            subprocess_kwargs = self._get_subprocess_kwargs(
                capture_output=True,
                text=True,
                timeout=10,
                env=clean_env,
                cwd=str(Path.home())
            )

            check_version = self._get_python_version(python_cmd) or sys.version_info[:2]
            if check_version >= (3, 10):
                logger.info(f"Python {check_version[0]}.{check_version[1]}，跳过 pypykatz 兼容性修复")
                return

            logger.info(f"Python {check_version[0]}.{check_version[1]}，检查 pypykatz 兼容性...")

            if is_packaged:
                try:
                    pypykatz_kwargs = subprocess_kwargs.copy()
                    pypykatz_kwargs['timeout'] = 30
                    result = subprocess.run(
                        [python_cmd, '-c', 'import pypykatz; print(pypykatz.__file__)'],
                        **pypykatz_kwargs
                    )
                    if result.returncode == 0:
                        pypykatz_file = result.stdout.strip()
                        pypykatz_path = Path(pypykatz_file).parent
                    else:
                        logger.warning(f"无法获取系统 pypykatz 路径: {result.stderr}")
                        return
                except Exception as e:
                    logger.warning(f"获取系统 pypykatz 路径失败: {e}")
                    return
            else:
                import pypykatz
                pypykatz_path = Path(pypykatz.__file__).parent

            vol3_reader_path = pypykatz_path / 'commons' / 'readers' / 'volatility3'

            if not vol3_reader_path.exists():
                logger.warning("pypykatz volatility3 reader 路径不存在")
                return

            init_file = vol3_reader_path / '__init__.py'
            if init_file.exists():
                content = init_file.read_text(encoding='utf-8')
                if 'from volatility.framework' in content:
                    content = content.replace('from volatility.framework', 'from volatility3.framework')
                    content = content.replace('from volatility.plugins', 'from volatility3.plugins')
                    init_file.write_text(content, encoding='utf-8')
                    logger.info("已修复 pypykatz __init__.py 兼容性")

            volreader_file = vol3_reader_path / 'volreader.py'
            if volreader_file.exists():
                content = volreader_file.read_text(encoding='utf-8')
                modified = False

                if "layer_name = self.vol_obj.config['primary']" in content:
                    new_find_lsass = '''
\tdef find_lsass(self):
\t\tfilter_func = pslist.PsList.create_name_filter(['lsass.exe'])

\t\t# 获取 kernel_module_name
\t\t# 兼容新版 volatility3
\t\ttry:
\t\t\tkernel = self.vol_obj.config['kernel']
\t\t\tkernel_module_name = kernel.config.get('kernel_module', 'kernel')
\t\t\t# 保存 symbol_table 供后续使用
\t\t\tself._symbol_table = kernel.symbol_table_name
\t\texcept (KeyError, AttributeError):
\t\t\tkernel_module_name = 'kernel'
\t\t\tself._symbol_table = self.vol_obj.config.get('nt_symbols', None)

\t\tfor proc in pslist.PsList.list_processes(
\t\t\t\t\tcontext = self.vol_obj.context,
\t\t\t\t\tkernel_module_name = kernel_module_name,
\t\t\t\t\tfilter_func = filter_func
\t\t\t\t):
\t\t\tself.lsass_process = proc
\t\t\tself.proc_layer_name = self.lsass_process.add_process_layer()
\t\t\tself.proc_layer = self.vol_obj.context.layers[self.proc_layer_name]
\t\t\treturn

\t\traise Exception('LSASS process not found!')

\tdef _get_symbol_table(self):
\t\t"""获取符号表名称"""
\t\tif hasattr(self, '_symbol_table') and self._symbol_table:
\t\t\treturn self._symbol_table
\t\ttry:
\t\t\tkernel = self.vol_obj.config['kernel']
\t\t\treturn kernel.symbol_table_name
\t\texcept (KeyError, AttributeError):
\t\t\treturn self.vol_obj.config.get('nt_symbols', None)
'''
                    import re
                    pattern = r'\tdef find_lsass\(self\):.*?(?=\n\tdef |\nclass |\Z)'
                    content = re.sub(pattern, new_find_lsass.rstrip() + '\n', content, flags=re.DOTALL)
                    modified = True

                if 'self.vol_obj.config["nt_symbols"]' in content:
                    content = content.replace(
                        'self.vol_obj.config["nt_symbols"]',
                        'self._get_symbol_table()'
                    )
                    modified = True

                if modified:
                    volreader_file.write_text(content, encoding='utf-8')
                    logger.info("已修复 pypykatz volreader.py 兼容性")

            logger.info("pypykatz 兼容性修复完成")

        except Exception as e:
            logger.warning(f"修复 pypykatz 兼容性时出错: {e}")

    def install_all_dependencies(self) -> Dict[str, Any]:
        try:
            python_cmd = self._get_python_cmd()
            valid, error = self._validate_python_executable(python_cmd)
            if not valid:
                return {
                    'status': 'error',
                    'message': (
                        f'当前 Python 不可用：{python_cmd}\n\n'
                        f'{error}\n\n请重新选择 Python，或恢复默认设置。'
                    ),
                    'installed': [],
                    'failed': []
                }

            from backend.volatility_wrapper import VolatilityWrapper
            dependencies = VolatilityWrapper.check_all_dependencies(python_cmd)
            dependencies = self._apply_explicit_volatility_status(dependencies)

            missing = []
            for name, info in dependencies.items():
                if not info['installed']:
                    missing.append(name)

            if not missing:
                return {
                    'status': 'success',
                    'message': '所有依赖已安装！',
                    'installed': [],
                    'failed': []
                }

            logger.info(f"需要安装的依赖: {missing}")

            installed = []
            failed = []

            for package in missing:
                result = self._install_dependency_for_python(package, python_cmd)
                if result.get('status') == 'success':
                    installed.append(package)
                else:
                    failed.append({'package': package, 'error': result.get('message', '未知错误')})

            if failed:
                return {
                    'status': 'partial',
                    'message': f'部分依赖安装成功。\n成功: {installed}\n失败: {[f["package"] for f in failed]}',
                    'installed': installed,
                    'failed': failed
                }

            return {
                'status': 'success',
                'message': f'所有依赖安装成功！\n已安装: {installed}',
                'installed': installed,
                'failed': []
            }

        except Exception as e:
            logger.error(f"安装依赖失败: {e}")
            return {
                'status': 'error',
                'message': f'安装失败: {str(e)}'
            }


    def _get_manual_install_message(self, platform: str) -> str:
        if platform == 'Windows':
            return """手动安装步骤：

1. 打开命令提示符（CMD）或 PowerShell
2. 运行命令（使用清华镜像加速）：
   pip install -i https://pypi.tuna.tsinghua.edu.cn/simple volatility3==2.27.0
   或使用官方源：
   pip install volatility3==2.27.0
3. 如果提示 pip 不存在，请先安装 Python：
   https://www.python.org/downloads/
4. 安装时勾选 "Add Python to PATH" """
        elif platform == 'Darwin':  
            return """手动安装步骤：

1. 打开终端（Terminal）
2. 运行命令（使用清华镜像加速）：
   pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple volatility3==2.27.0
   或使用官方源：
   pip3 install volatility3==2.27.0
3. 如果提示 pip3 不存在，请先安装 Python：
   brew install python3
   或访问 https://www.python.org/downloads/
4. 安装后可能需要添加到 PATH：
   export PATH=$PATH:~/Library/Python/3.9/bin """
        else:  
            return """手动安装步骤：

1. 打开终端
2. 运行命令（使用清华镜像加速）：
   pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple volatility3==2.27.0 --break-system-packages
   或使用官方源：
   pip3 install volatility3==2.27.0 --break-system-packages
3. 如果提示 pip3 不存在，请先安装：
   Ubuntu/Debian: sudo apt install python3-pip
   CentOS/RHEL: sudo yum install python3-pip
   Arch: sudo pacman -S python-pip
4. 添加到 PATH（如果需要）：
   export PATH=$PATH:~/.local/bin """

    def check_for_updates(self) -> Dict[str, Any]:
        import platform
        import urllib.request
        import urllib.error
        import re

        try:
            from backend import __version__ as current_version
        except ImportError:
            current_version = '1.1.0'

        gitee_owner = 'hilyary'
        gitee_repo = 'LensAnalysis-project'
        releases_url = f'https://gitee.com/{gitee_owner}/{gitee_repo}/releases'

        try:
            import ssl
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(releases_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')

            with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
                html = response.read().decode('utf-8')

            version_matches = re.findall(r"data-tag-name='([^']+)'", html)

            if not version_matches:
                return {
                    'status': 'error',
                    'message': '无法获取更新信息'
                }

            latest_version = version_matches[0].strip().lstrip('v')

            def parse_version(v):
                parts = v.split('.')
                return [int(p) for p in parts if p.isdigit()]

            current_parts = parse_version(current_version)
            latest_parts = parse_version(latest_version)

            while len(current_parts) < 3:
                current_parts.append(0)
            while len(latest_parts) < 3:
                latest_parts.append(0)

            has_update = latest_parts > current_parts

            system = platform.system()
            download_url = ''
            filename = ''

            if system == 'Windows':
                exe_matches = re.findall(r'href="([^"]*\.exe[^"]*)"', html)
                for url in exe_matches:
                    if 'gitee' in url or 'download' in url.lower():
                        if url.startswith('/'):
                            url = 'https://gitee.com' + url
                        download_url = url
                        filename = url.split('/')[-1]
                        break
            elif system == 'Darwin':
                dmg_matches = re.findall(r'href="([^"]*\.dmg[^"]*)"', html)
                for url in dmg_matches:
                    if 'gitee' in url or 'download' in url.lower():
                        if url.startswith('/'):
                            url = 'https://gitee.com' + url
                        download_url = url
                        filename = url.split('/')[-1]
                        break
            elif system == 'Linux':
                tar_matches = re.findall(r'href="([^"]*\.tar\.gz[^"]*)"', html)
                for url in tar_matches:
                    if 'gitee' in url or 'download' in url.lower():
                        if url.startswith('/'):
                            url = 'https://gitee.com' + url
                        download_url = url
                        filename = url.split('/')[-1]
                        break

            if not download_url:
                download_url = f'https://gitee.com/{gitee_owner}/{gitee_repo}/releases'

            release_body = ''
            first_tag_idx = html.find("data-tag-name='")
            if first_tag_idx > 0:
                tag_end = html.find('</div>', first_tag_idx + 200)
                search_area = html[first_tag_idx:first_tag_idx + 15000]
                body_match = re.search(r"<textarea\s+class='content'[^>]*>(.*?)</textarea>", search_area, re.DOTALL)
                if body_match:
                    import html as html_module
                    raw = body_match.group(1)
                    raw = raw.replace('&#x000A;', '\n').replace('&#xA;', '\n')
                    raw = html_module.unescape(raw)
                    raw = raw.strip()
                    lines = [l.rstrip() for l in raw.split('\n')]
                    release_body = '\n'.join(lines)

            result = {
                'status': 'success',
                'has_update': has_update,
                'current_version': current_version,
                'latest_version': latest_version,
                'release_title': f'v{latest_version}',
                'release_body': release_body,
                'download_url': download_url,
                'filename': filename,
                'published_at': ''
            }

            return result

        except urllib.error.URLError as e:
            logger.error(f"检查更新失败: {e}")
            return {
                'status': 'error',
                'message': f'检查更新失败: {str(e)}'
            }
        except Exception as e:
            logger.error(f"检查更新异常: {e}")
            return {
                'status': 'error',
                'message': f'检查更新异常: {str(e)}'
            }

    def download_update(self, download_url: str) -> Dict[str, Any]:
        import platform
        import urllib.request
        import shutil
        import glob

        system = platform.system()

        try:
            filename = download_url.split('/')[-1]

            if system == 'Darwin':
                download_dir = Path('/tmp')
                download_path = download_dir / filename
            elif system == 'Windows':
                exe_path = Path(sys.argv[0]).resolve() if hasattr(sys, 'argv') else Path.cwd()
                download_dir = exe_path.parent
                download_dir.mkdir(exist_ok=True)

                current_exe_name = exe_path.name
                for old_file in download_dir.glob('LensAnalysis*.exe'):
                    if old_file.name != current_exe_name:
                        try:
                            old_file.unlink()
                            logger.info(f"已清理旧更新文件: {old_file}")
                        except Exception as e:
                            logger.warning(f"清理旧文件失败: {old_file}, {e}")

                download_path = download_dir / filename
            else:
                download_dir = self._user_data_dir / 'updates'
                download_dir.mkdir(exist_ok=True)

                for old_file in download_dir.glob('*'):
                    try:
                        old_file.unlink()
                        logger.info(f"已清理旧更新文件: {old_file}")
                    except Exception as e:
                        logger.warning(f"清理旧文件失败: {old_file}, {e}")

                download_path = download_dir / filename

            logger.info(f"开始下载更新: {download_url}")

            import ssl
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(download_url)
            req.add_header('User-Agent', 'Mozilla/5.0')

            with urllib.request.urlopen(req, context=ssl_context, timeout=60) as response:
                total_size = int(response.headers.get('Content-Length', 0))
                downloaded = 0
                chunk_size = 8192

                with open(download_path, 'wb') as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)

            logger.info(f"更新文件下载完成: {download_path}")

            if system == 'Darwin':
                subprocess.Popen(['open', str(download_path)])
                return {
                    'status': 'success',
                    'message': '已下载并打开 DMG，请按照提示安装',
                    'download_path': str(download_path)
                }
            else:
                return {
                    'status': 'success',
                    'message': '下载完成',
                    'download_path': str(download_path),
                    'auto_update': True
                }

        except Exception as e:
            logger.error(f"下载更新失败: {e}")
            return {
                'status': 'error',
                'message': f'下载失败: {str(e)}'
            }

    def apply_update_windows(self, download_path: str) -> Dict[str, Any]:
        import platform
        import subprocess
        import os

        if platform.system() != 'Windows':
            return {'status': 'error', 'message': '仅支持 Windows'}

        try:
            current_exe = Path(sys.argv[0]).resolve()
            current_dir = current_exe.parent
            current_name = current_exe.name

            new_exe = Path(download_path).resolve()
            new_name = new_exe.name

            logger.info(f"当前exe: {current_exe}, 新版本: {new_exe}")

            script_content = f'''@echo off
chcp 65001 >nul
echo 正在更新...
echo 等待程序退出...
timeout /t 5 /nobreak >nul

echo 删除旧版本...
del /f /q "{current_exe}" 2>nul

echo 启动新版本...
start "" "{new_exe}"
exit
'''
            script_path = Path(os.environ.get('TEMP', current_dir)) / 'lens_update.bat'
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(script_content)

            logger.info(f"更新脚本: {script_path}")

            logger.info(f"启动更新脚本: cmd /c {script_path}")
            subprocess.Popen(
                f'cmd /c "{script_path}"',
                cwd=str(current_dir),
                shell=False,
                start_new_session=True
            )

            return {
                'status': 'success',
                'message': '正在更新...',
                'download_path': download_path,
                'will_exit': True
            }

        except Exception as e:
            logger.error(f"更新准备失败: {e}")
            return {
                'status': 'error',
                'message': f'更新失败: {str(e)}'
            }


    def wechat_analyze(self) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {'status': 'error', 'message': '请先加载内存镜像'}

            os_type = self.current_image.get('os_type', '').lower()
            if os_type != 'windows':
                return {'status': 'error', 'message': '微信分析仅支持 Windows 内存镜像'}

            from backend.wechat_analyzer import WeChatAnalyzer
            dep_check = WeChatAnalyzer.check_dependencies()
            if not dep_check['available']:
                return {
                    'status': 'error',
                    'message': dep_check['message'],
                    'error_type': 'pycryptodome_missing'
                }

            cached = self._load_from_cache_file('wechat_analysis')
            if cached:
                logger.info("微信分析: 从缓存加载")
                return {'status': 'success', 'data': cached, 'cached': True}

            cache_dir = str(self._get_image_cache_dir())

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'], self.current_image.get('os_type'), self._get_python_cmd(), symbols_dir=self._get_symbols_base_dir(self.current_image.get('os_type')), cache_path=self._cache_path)
            vol_path = wrapper._vol_path
            symbols_dir = str(wrapper._symbols_dir)

            analyzer = WeChatAnalyzer(
                self.current_image['path'],
                vol_path=vol_path,
                symbols_dir=symbols_dir,
                wrapper=wrapper
            )
            result = analyzer.analyze_keys(cache_dir, None, False)

            if result.get('status') == 'success':
                self._save_to_cache_file('wechat_analysis', result)
                return {'status': 'success', 'data': result, 'cached': False}
            else:
                return {'status': 'success', 'data': result, 'cached': False}

        except Exception as e:
            logger.error(f"微信分析失败: {e}")
            return {'status': 'error', 'message': f'微信分析失败: {str(e)}'}

    def wechat_compare_databases(self) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {'status': 'error', 'message': '请先加载内存镜像'}

            os_type = self.current_image.get('os_type', '').lower()
            if os_type != 'windows':
                return {'status': 'error', 'message': '微信分析仅支持 Windows 内存镜像'}

            from backend.wechat_analyzer import WeChatAnalyzer
            dep_check = WeChatAnalyzer.check_dependencies()
            if not dep_check['available']:
                return {
                    'status': 'error',
                    'message': dep_check['message'],
                    'error_type': 'pycryptodome_missing'
                }

            cached = self._load_from_cache_file('wechat_analysis')
            if not cached:
                return {'status': 'error', 'message': '请先执行微信分析并提取密钥'}

            if cached.get('analysis_stage') in ('compared', 'decrypted'):
                return {'status': 'success', 'data': cached, 'cached': True}

            cache_dir = str(self._get_image_cache_dir())

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'], self.current_image.get('os_type'), self._get_python_cmd(), symbols_dir=self._get_symbols_base_dir(self.current_image.get('os_type')), cache_path=self._cache_path)
            vol_path = wrapper._vol_path
            symbols_dir = str(wrapper._symbols_dir)

            analyzer = WeChatAnalyzer(
                self.current_image['path'],
                vol_path=vol_path,
                symbols_dir=symbols_dir,
                wrapper=wrapper
            )
            result = analyzer.compare_from_keys(cache_dir, cached, None)

            if result.get('status') == 'success':
                self._save_to_cache_file('wechat_analysis', result)
                return {'status': 'success', 'data': result, 'cached': False}

            return {'status': 'success', 'data': result, 'cached': False}
        except Exception as e:
            logger.error(f"微信数据库比对失败: {e}")
            return {'status': 'error', 'message': f'微信数据库比对失败: {str(e)}'}

    def wechat_decrypt_databases(self) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {'status': 'error', 'message': '请先加载内存镜像'}

            os_type = self.current_image.get('os_type', '').lower()
            if os_type != 'windows':
                return {'status': 'error', 'message': '微信分析仅支持 Windows 内存镜像'}

            from backend.wechat_analyzer import WeChatAnalyzer
            dep_check = WeChatAnalyzer.check_dependencies()
            if not dep_check['available']:
                return {
                    'status': 'error',
                    'message': dep_check['message'],
                    'error_type': 'pycryptodome_missing'
                }

            cached = self._load_from_cache_file('wechat_analysis')
            if not cached:
                return {'status': 'error', 'message': '请先执行微信分析并提取密钥'}

            if cached.get('analysis_stage') == 'decrypted':
                return {'status': 'success', 'data': cached, 'cached': True}

            cache_dir = str(self._get_image_cache_dir())

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'], self.current_image.get('os_type'), self._get_python_cmd(), symbols_dir=self._get_symbols_base_dir(self.current_image.get('os_type')), cache_path=self._cache_path)
            vol_path = wrapper._vol_path
            symbols_dir = str(wrapper._symbols_dir)

            analyzer = WeChatAnalyzer(
                self.current_image['path'],
                vol_path=vol_path,
                symbols_dir=symbols_dir,
                wrapper=wrapper
            )
            result = analyzer.decrypt_from_keys(cache_dir, cached, None)

            if result.get('status') == 'success':
                self._save_to_cache_file('wechat_analysis', result)
                return {'status': 'success', 'data': result, 'cached': False}

            return {'status': 'success', 'data': result, 'cached': False}
        except Exception as e:
            logger.error(f"微信数据库解密失败: {e}")
            return {'status': 'error', 'message': f'微信数据库解密失败: {str(e)}'}

    @staticmethod
    def _sanitize_wechat_sqlite_value(value: Any) -> Any:
        if isinstance(value, memoryview):
            value = value.tobytes()

        if isinstance(value, bytes):
            if not value:
                return ''
            try:
                text = value.decode('utf-8')
                if text.isprintable() or any(ch.isalnum() for ch in text):
                    return text
            except Exception:
                pass

            hex_value = value.hex()
            preview = hex_value[:128]
            suffix = '...' if len(hex_value) > 128 else ''
            return f'<BLOB {len(value)} bytes> 0x{preview}{suffix}'

        return value

    def _sanitize_wechat_sqlite_rows(self, rows: List[Any]) -> List[Dict[str, Any]]:
        normalized = []
        for row in rows:
            if hasattr(row, 'keys') and not isinstance(row, dict):
                row = dict(row)
            if isinstance(row, dict):
                normalized.append({
                    str(key): self._sanitize_wechat_sqlite_value(value)
                    for key, value in row.items()
                })
            else:
                normalized.append({'value': self._sanitize_wechat_sqlite_value(row)})
        return normalized

    @staticmethod
    def _format_wechat_sqlite_error(error: Exception) -> str:
        message = str(error)
        if 'database disk image is malformed' in message.lower():
            return '该数据库或数据表已部分损坏，通常是内存提取不完整导致，当前无法直接预览。'
        return message

    @staticmethod
    def _is_expected_wechat_sqlite_damage(error: Exception) -> bool:
        return 'database disk image is malformed' in str(error).lower()

    @staticmethod
    def _pick_wechat_message_time_column(columns: List[str]) -> Optional[str]:
        candidates = ['CreateTime', 'create_time', 'timestamp', 'Timestamp', 'sort_seq']
        for column in candidates:
            if column in columns:
                return column
        return None

    def _normalize_wechat_message_row(self, row: Dict[str, Any], columns: List[str]) -> Dict[str, Any]:
        content = ''
        for key in ['msgContent', 'message_content', 'content', 'summary']:
            if key in row and row[key]:
                content = self._sanitize_wechat_sqlite_value(row[key])
                break

        time_column = self._pick_wechat_message_time_column(columns)
        create_time = row.get(time_column) if time_column else None

        status = None
        for key in ['msgStatus', 'status']:
            if key in row:
                status = row.get(key)
                break

        sender = ''
        for key in ['real_sender_id', 'last_msg_sender', 'sender', 'from_user']:
            if key in row and row[key] not in (None, ''):
                sender = self._sanitize_wechat_sqlite_value(row[key])
                break

        normalized = {
            'content': self._sanitize_wechat_sqlite_value(content),
            'create_time': self._sanitize_wechat_sqlite_value(create_time),
            'status': self._sanitize_wechat_sqlite_value(status),
            'sender': sender,
            'raw': self._sanitize_wechat_sqlite_rows([row])[0],
        }
        return normalized

    def _query_wechat_messages_from_table(self, cursor: Any, table_name: str, limit: int) -> Dict[str, Any]:
        cursor.execute(f"PRAGMA table_info([{table_name}])")
        columns = [row[1] for row in cursor.fetchall()]
        time_column = self._pick_wechat_message_time_column(columns)
        order_by = f"[{time_column}] DESC" if time_column else 'rowid DESC'

        cursor.execute(f"SELECT * FROM [{table_name}] ORDER BY {order_by} LIMIT ?", (limit,))
        raw_rows = [dict(row) for row in cursor.fetchall()]
        normalized_rows = [self._normalize_wechat_message_row(row, columns) for row in raw_rows]

        return {
            'table_name': table_name,
            'columns': columns,
            'messages': normalized_rows,
            'row_count': len(normalized_rows),
        }

    def wechat_get_messages(self, db_path: str, table_name: str) -> Dict[str, Any]:
        try:
            import sqlite3

            if not db_path or not Path(db_path).exists():
                return {'status': 'error', 'message': '数据库文件不存在'}

            if not re.match(r'^[a-zA-Z_@][a-zA-Z0-9_@]*$', table_name):
                return {'status': 'error', 'message': '无效的表名'}

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(f"""
                SELECT * FROM [{table_name}]
                ORDER BY CreateTime DESC
                LIMIT 500
            """)

            columns = [desc[0] for desc in cursor.description]
            raw_messages = [dict(zip(columns, row)) for row in cursor.fetchall()]
            messages = self._sanitize_wechat_sqlite_rows(raw_messages)

            conn.close()

            return {'status': 'success', 'data': {'messages': messages, 'columns': columns}}

        except Exception as e:
            if self._is_expected_wechat_sqlite_damage(e):
                logger.debug(f"查询消息命中损坏表: {e}")
            else:
                logger.warning(f"查询消息失败: {e}")
            return {'status': 'error', 'message': f'查询消息失败: {self._format_wechat_sqlite_error(e)}'}

    def wechat_get_session_messages(self, db_path: str, username: str, limit: int = 500) -> Dict[str, Any]:
        try:
            import hashlib
            import sqlite3

            if not db_path or not Path(db_path).exists():
                return {'status': 'error', 'message': '数据库文件不存在'}

            username = (username or '').strip()
            if not username:
                return {'status': 'error', 'message': '会话用户名为空'}

            limit = max(1, min(int(limit or 500), 1000))

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%' ORDER BY name")
            available_tables = {row[0] for row in cursor.fetchall()}

            hashed_name = hashlib.md5(username.encode('utf-8')).hexdigest()
            candidate_tables = [
                f'Msg_{username}',
                f'Msg_{hashed_name}',
            ]

            try:
                cursor.execute("SELECT user_name FROM Name2Id WHERE user_name = ? LIMIT 1", (username,))
                if cursor.fetchone():
                    candidate_tables.append(f'Msg_{hashed_name}')
            except Exception:
                pass

            candidate_tables = [name for i, name in enumerate(candidate_tables) if name in available_tables and name not in candidate_tables[:i]]

            last_error = None
            for table_name in candidate_tables:
                try:
                    result = self._query_wechat_messages_from_table(cursor, table_name, limit)
                    conn.close()
                    return {'status': 'success', 'data': result}
                except Exception as e:
                    last_error = e
                    if self._is_expected_wechat_sqlite_damage(e):
                        logger.debug(f"读取微信会话消息命中损坏表 {table_name}: {e}")
                    else:
                        logger.warning(f"读取微信会话消息失败 {table_name}: {e}")

            conn.close()
            if last_error:
                return {'status': 'error', 'message': self._format_wechat_sqlite_error(last_error)}
            return {'status': 'error', 'message': '未找到该会话对应的消息表'}

        except Exception as e:
            if self._is_expected_wechat_sqlite_damage(e):
                logger.debug(f"查询微信会话消息命中损坏库: {e}")
            else:
                logger.warning(f"查询微信会话消息失败: {e}")
            return {'status': 'error', 'message': self._format_wechat_sqlite_error(e)}

    def wechat_get_table_messages(self, db_path: str, table_name: str, limit: int = 500) -> Dict[str, Any]:
        try:
            import sqlite3

            if not db_path or not Path(db_path).exists():
                return {'status': 'error', 'message': '数据库文件不存在'}

            if not re.match(r'^[a-zA-Z_@][a-zA-Z0-9_@]*$', table_name or ''):
                return {'status': 'error', 'message': '无效的表名'}

            limit = max(1, min(int(limit or 500), 1000))

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            result = self._query_wechat_messages_from_table(cursor, table_name, limit)
            conn.close()
            return {'status': 'success', 'data': result}

        except Exception as e:
            if self._is_expected_wechat_sqlite_damage(e):
                logger.debug(f"按表读取微信消息命中损坏表 {table_name}: {e}")
            else:
                logger.warning(f"按表读取微信消息失败 {table_name}: {e}")
            return {'status': 'error', 'message': self._format_wechat_sqlite_error(e)}

    def wechat_list_tables(self, db_path: str) -> Dict[str, Any]:
        try:
            import sqlite3
            if not db_path or not Path(db_path).exists():
                return {'status': 'error', 'message': '数据库文件不存在'}

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = [row[0] for row in cursor.fetchall()]
            table_details = []

            for table_name in tables:
                table_info = {
                    'name': table_name,
                    'status': 'ok',
                    'row_count': None,
                    'message': '',
                }
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM [{table_name}]")
                    count_row = cursor.fetchone()
                    table_info['row_count'] = count_row[0] if count_row else 0
                except Exception as e:
                    table_info['status'] = 'error'
                    table_info['message'] = self._format_wechat_sqlite_error(e)
                table_details.append(table_info)

            integrity = 'unknown'
            try:
                cursor.execute("PRAGMA integrity_check")
                integrity_row = cursor.fetchone()
                integrity = integrity_row[0] if integrity_row else 'unknown'
            except Exception as e:
                integrity = self._format_wechat_sqlite_error(e)

            conn.close()
            return {
                'status': 'success',
                'data': {
                    'tables': tables,
                    'table_details': table_details,
                    'integrity': integrity,
                }
            }
        except Exception as e:
            logger.error(f"列表表失败: {e}")
            return {'status': 'error', 'message': str(e)}

    def wechat_preview_table(self, db_path: str, table_name: str, limit: int = 200) -> Dict[str, Any]:
        try:
            import sqlite3

            if not db_path or not Path(db_path).exists():
                return {'status': 'error', 'message': '数据库文件不存在'}

            if not re.match(r'^[a-zA-Z_@][a-zA-Z0-9_@$]*$', table_name):
                return {'status': 'error', 'message': '无效的表名'}

            limit = max(1, min(int(limit or 200), 500))

            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(f"SELECT * FROM [{table_name}] LIMIT ?", (limit,))
            columns = [desc[0] for desc in cursor.description] if cursor.description else []
            raw_rows = [dict(row) for row in cursor.fetchall()]
            rows = self._sanitize_wechat_sqlite_rows(raw_rows)

            conn.close()

            return {
                'status': 'success',
                'data': {
                    'table_name': table_name,
                    'columns': columns,
                    'rows': rows,
                    'row_count': len(rows),
                    'limit': limit,
                }
            }
        except Exception as e:
            if self._is_expected_wechat_sqlite_damage(e):
                logger.debug(f"预览微信表命中损坏表: {e}")
            else:
                logger.warning(f"预览微信表失败: {e}")
            return {'status': 'error', 'message': self._format_wechat_sqlite_error(e)}

    def wechat_clear_cache(self) -> Dict[str, Any]:
        try:
            if not self.current_image:
                return {'status': 'error', 'message': '请先加载内存镜像'}

            cache_dir = self._get_image_cache_dir()

            cache_file = cache_dir / 'wechat_analysis.json'
            deleted = []
            if cache_file.exists():
                cache_file.unlink()
                deleted.append('wechat_analysis.json')

            import shutil
            work_dir = cache_dir / 'wechat_analysis'
            if work_dir.exists():
                shutil.rmtree(work_dir, ignore_errors=True)
                deleted.append('wechat_analysis/')

            logger.info(f"微信分析缓存已清除: {deleted}")
            return {'status': 'success', 'message': f'缓存已清除，请重新执行微信分析', 'deleted': deleted}
        except Exception as e:
            logger.error(f"清除缓存失败: {e}")
            return {'status': 'error', 'message': str(e)}

    def wechat_export_keys(self) -> Dict[str, Any]:
        try:
            cached = self._load_from_cache_file('wechat_analysis')
            if not cached:
                return {'status': 'error', 'message': '请先执行微信分析'}

            keys = cached.get('keys', [])
            if not keys:
                return {'status': 'error', 'message': '没有可导出的密钥'}

            cache_dir = self._get_image_cache_dir()
            export_path = cache_dir / 'wechat_keys.json'

            export_data = {
                'export_time': datetime.now().isoformat(),
                'image': self.current_image.get('name', '') if self.current_image else '',
                'wxid': cached.get('wxid', ''),
                'keys_count': len(keys),
                'keys': keys,
                'db_details': cached.get('db_details', []),
            }

            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)

            return {
                'status': 'success',
                'data': {
                    'export_path': str(export_path),
                    'keys_count': len(keys)
                }
            }

        except Exception as e:
            logger.error(f"导出密钥失败: {e}")
            return {'status': 'error', 'message': f'导出密钥失败: {str(e)}'}

    def exit(self):
        import os
        import signal
        import sys
        logger.info("退出应用程序")

        if self._window:
            try:
                self._window.destroy()
            except Exception as e:
                logger.error(f"关闭窗口失败: {e}")

        try:
            os._exit(0)
        except Exception as e:
            logger.error(f"os._exit 失败: {e}")
            try:
                sys.exit(0)
            except Exception as e2:
                logger.error(f"sys.exit 也失败: {e2}")
