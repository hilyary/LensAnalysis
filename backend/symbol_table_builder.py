import os
import sys
import re
import platform
import logging
import tempfile
import shutil
import subprocess
import lzma
import gzip
import tarfile
import json
from pathlib import Path
from typing import Optional, Dict, Any, Callable, Tuple
from urllib.request import urlopen, Request, build_opener, ProxyHandler, HTTPSHandler
from urllib.error import URLError, HTTPError
from html.parser import HTMLParser
import ssl

logger = logging.getLogger(__name__)


def _get_subprocess_kwargs(**kwargs) -> Dict[str, Any]:
    if platform.system() == 'Windows':
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    return kwargs


class ProgressReporter:

    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.current_stage = ''
        self.stage_weights = {
            'detect': 5,
            'download': 50,
            'extract': 15,
            'convert': 25,
            'compress': 5
        }
        self.completed_weight = 0
        self.last_logged_progress = {}  

    def report(self, stage: str, progress: int, message: str):
        self.current_stage = stage

        stage_weight = self.stage_weights.get(stage, 10)
        total_progress = self.completed_weight + (progress * stage_weight / 100)

        if self.callback:
            try:
                self.callback(stage, int(total_progress), message)
            except Exception as e:
                logger.warning(f"进度回调失败: {e}")

        last_progress = self.last_logged_progress.get(stage, -1)
        if progress != last_progress:
            if progress == 0 or progress == 100:
                logger.info(f"[{stage}] {progress}% - {message}")
            else:
                logger.debug(f"[{stage}] {progress}% - {message}")
            self.last_logged_progress[stage] = progress

    def complete_stage(self, stage: str):
        self.completed_weight += self.stage_weights.get(stage, 10)


class LinkParser(HTMLParser):

    def __init__(self):
        super().__init__()
        self.links = []
        self.current_href = None

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for name, value in attrs:
                if name == 'href':
                    self.current_href = value
                    self.links.append(value)

    def handle_data(self, data):
        pass


class LinuxVersionInfo:

    def __init__(self, banner: str):
        self.banner = banner
        self.kernel_version = ''  
        self.package_version = ''  
        self.distro = ''  
        self.distro_codename = ''  
        self.arch = 'amd64'
        self.major_version = ''  
        self.abi = ''  
        self.flavor = ''  

        self._parse()

    def _parse(self):
        match = re.search(r'Linux version\s+(\S+)', self.banner)
        if match:
            self.kernel_version = match.group(1)

            version_match = re.match(r'^(\d+\.\d+\.\d+)-(\d+)-(\w+)', self.kernel_version)
            if version_match:
                self.major_version = version_match.group(1)
                self.abi = version_match.group(2)
                self.flavor = version_match.group(3)

        banner_lower = self.banner.lower()

        if 'darwin' in banner_lower or 'macos' in banner_lower:
            self.distro = 'macOS'
            match = re.search(r'Darwin Kernel Version\s+(\d+\.\d+\.\d+)', self.banner)
            if match:
                self.kernel_version = match.group(1)
                self.major_version = match.group(1)
                self.package_version = match.group(1)
                self.arch = 'arm64' if 'arm64' in self.banner.lower() else 'amd64'
            return

        if 'ubuntu' in banner_lower:
            self.distro = 'Ubuntu'
            if '~22.04' in self.banner:
                self.distro_codename = 'jammy'
            elif '~20.04' in self.banner:
                self.distro_codename = 'focal'
            elif '~18.04' in self.banner:
                self.distro_codename = 'bionic'
            elif '~16.04' in self.banner:
                self.distro_codename = 'xenial'
            elif '~24.04' in self.banner:
                self.distro_codename = 'noble'


            pkg_match = re.search(
                r'\(Ubuntu\s+(\d+\.\d+\.\d+-\d+\.\d+~[\d.]+-\w+)\s+\d+\.\d+\.\d+\)',
                self.banner
            )
            if pkg_match:
                full_version_with_flavor = pkg_match.group(1)
                parts = full_version_with_flavor.rsplit('-', 1)
                self.package_version = parts[0]
                logger.debug(f"从 banner 末尾提取包版本: {self.package_version}")
            else:
                if self.flavor:
                    pkg_match = re.search(
                        rf'\(Ubuntu\s+(\d+\.\d+\.\d+-\d+\.\d+(?:\.\d+)?)(?:~[\d.]+)?-{re.escape(self.flavor)}',
                        self.banner
                    )
                    if pkg_match:
                        full_version = pkg_match.group(1)
                        self.package_version = full_version
                        logger.debug(f"通过 flavor 匹配包版本: {self.package_version}")

        elif 'debian' in banner_lower:
            self.distro = 'Debian'
            if 'bookworm' in banner_lower or '/12' in self.banner:
                self.distro_codename = 'bookworm'
            elif 'bullseye' in banner_lower or '/11' in self.banner:
                self.distro_codename = 'bullseye'
            elif 'buster' in banner_lower or '/10' in self.banner:
                self.distro_codename = 'buster'

        elif 'centos' in banner_lower or 'el7' in banner_lower or 'el8' in banner_lower or 'el9' in banner_lower:
            self.distro = 'CentOS'
            if 'el9' in banner_lower or '.el9' in self.kernel_version:
                self.distro_codename = '9'
            elif 'el8' in banner_lower or '.el8' in self.kernel_version:
                self.distro_codename = '8'
            elif 'el7' in banner_lower or '.el7' in self.kernel_version:
                self.distro_codename = '7'

        elif 'rocky' in banner_lower:
            self.distro = 'Rocky'
            if 'el9' in banner_lower:
                self.distro_codename = '9'
            elif 'el8' in banner_lower:
                self.distro_codename = '8'

        elif 'alma' in banner_lower:
            self.distro = 'AlmaLinux'
            if 'el9' in banner_lower:
                self.distro_codename = '9'
            elif 'el8' in banner_lower:
                self.distro_codename = '8'

    def __str__(self):
        return (f"LinuxVersionInfo(kernel={self.kernel_version}, "
                f"package={self.package_version}, distro={self.distro}, "
                f"codename={self.distro_codename})")


class SymbolTableBuilder:

    UBUNTU_CODENAMES = {
        'noble': '24.04',
        'jammy': '22.04',
        'focal': '20.04',
        'bionic': '18.04',
        'xenial': '16.04',
    }

    def __init__(self, symbols_dir: Path, progress_callback: Optional[Callable] = None, proxy_config: Optional[Dict] = None, data_dir: Optional[Path] = None):
        self.symbols_dir = Path(symbols_dir)
        self.symbols_dir.mkdir(parents=True, exist_ok=True)

        if data_dir:
            self.data_dir = Path(data_dir)
        else:
            self.data_dir = self.symbols_dir.parent

        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.progress = ProgressReporter(progress_callback)
        self.proxy_config = proxy_config or {}

        self.temp_dir = None

        self.dwarf2json_path = self._get_dwarf2json_path()

    def _get_dwarf2json_path(self) -> Optional[Path]:
        env_path = os.environ.get('DWARF2JSON_PATH')
        if env_path and Path(env_path).exists():
            return Path(env_path)

        system = platform.system()
        machine = platform.machine()

        binary_names = []

        if system == 'Windows':
            binary_names = ['dwarf2json.exe', 'dwarf2json-windows-amd64.exe']
        elif system == 'Darwin':
            if machine == 'arm64':
                binary_names = ['dwarf2json', 'dwarf2json-MacOS-arm64', 'dwarf2json-darwin-arm64', 'dwarf2json-darwin-amd64']
            else:
                binary_names = ['dwarf2json', 'dwarf2json-MacOS-amd64', 'dwarf2json-darwin-amd64']
        else:  
            binary_names = ['dwarf2json', 'dwarf2json-linux-amd64']

        base_paths = [
            self.data_dir / 'tools',
            self.symbols_dir / 'tools',
            Path(__file__).parent.parent / 'tools' / 'dwarf2json',
            Path(__file__).parent / 'tools' / 'dwarf2json',
            Path(__file__).parent,
            Path('/usr/local/bin'),
            Path('/usr/bin'),
        ]

        for base_path in base_paths:
            for binary_name in binary_names:
                path = base_path / binary_name
                if path.exists():
                    logger.info(f"找到 dwarf2json: {path}")
                    return path

        searched = [base / name for base in base_paths for name in binary_names]
        logger.warning(f"未找到 dwarf2json 工具，已搜索: {searched}")
        return None

    def build(self, banner: str) -> Dict[str, Any]:
        temp_base = self.data_dir / 'temp'
        temp_base.mkdir(parents=True, exist_ok=True)

        import time
        timestamp = int(time.time())
        self.temp_dir = temp_base / f'symbol_build_{timestamp}'
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        self._clean_old_temp_dirs(temp_base)

        try:
            self.progress.report('detect', 0, '正在解析内核版本...')
            version_info = LinuxVersionInfo(banner)
            logger.info(f"版本信息: {version_info}")

            if not version_info.kernel_version:
                return {
                    'status': 'error',
                    'message': '无法从 banner 解析内核版本'
                }

            if not version_info.distro:
                return {
                    'status': 'error',
                    'message': f'无法识别发行版类型，支持的发行版: Ubuntu, Debian, CentOS/RHEL\nBanner: {banner[:200]}'
                }

            self.progress.report('detect', 100, f'检测到 {version_info.distro} {version_info.kernel_version}')
            self.progress.complete_stage('detect')

            existing = self._check_existing_symbol(version_info)
            if existing:
                return {
                    'status': 'success',
                    'message': f'符号表已存在: {existing}',
                    'symbol_path': str(existing),
                    'version_info': version_info.__dict__
                }

            self.progress.report('download', 0, f'正在下载 {version_info.distro} 调试符号包...')
            ddeb_path = self._download_dbgsym(version_info)

            if not ddeb_path:
                if version_info.distro == 'macOS':
                    return {
                        'status': 'error',
                        'message': f'macOS 符号表需要手动获取。\n'
                                   f'请查看日志了解手动获取方法。',
                        'version_info': version_info.__dict__
                    }
                return {
                    'status': 'error',
                    'message': f'下载失败: 找不到 {version_info.kernel_version} 的调试符号包。\n'
                               f'可能的原因:\n'
                               f'1. 内核版本过新或过旧\n'
                               f'2. 该发行版不提供调试符号包\n'
                               f'建议: 手动下载 dbgsym 包并使用"安装符号表"功能',
                    'version_info': version_info.__dict__
                }

            self.progress.complete_stage('download')

            self.progress.report('extract', 0, '正在解压调试符号包...')

            if version_info.distro == 'macOS':
                vmlinux_path = ddeb_path
            else:
                vmlinux_path = self._extract_vmlinux(ddeb_path)

            if not vmlinux_path:
                return {
                    'status': 'error',
                    'message': '解压失败: 无法从调试符号包中提取 vmlinux 文件',
                    'version_info': version_info.__dict__
                }

            if version_info.distro != 'macOS':
                try:
                    if ddeb_path.exists():
                        ddeb_path.unlink()
                        logger.debug(f"已删除 ddeb 文件: {ddeb_path}")
                except Exception as e:
                    logger.warning(f"删除 ddeb 文件失败: {e}")

            self.progress.complete_stage('extract')

            self.progress.report('convert', 0, '正在生成符号表...')
            json_path = self._generate_isf(vmlinux_path, version_info)

            if not json_path:
                return {
                    'status': 'error',
                    'message': '转换失败: dwarf2json 执行失败。请确保已安装 dwarf2json 工具。',
                    'version_info': version_info.__dict__
                }

            try:
                extracted_dir = Path(self.temp_dir) / 'extracted'
                if extracted_dir.exists():
                    shutil.rmtree(extracted_dir, ignore_errors=True)
                    logger.debug(f"已删除解压目录: {extracted_dir}")
            except Exception as e:
                logger.warning(f"删除解压目录失败: {e}")

            self.progress.complete_stage('convert')

            self.progress.report('compress', 0, '正在压缩符号表...')
            xz_path = self._compress_and_save(json_path, version_info)

            try:
                if json_path.exists():
                    json_path.unlink()
                    logger.debug(f"已删除 JSON 文件: {json_path}")
            except Exception as e:
                logger.warning(f"删除 JSON 文件失败: {e}")

            self.progress.complete_stage('compress')
            self.progress.report('compress', 100, '符号表制作完成!')

            return {
                'status': 'success',
                'message': f'符号表制作成功: {version_info.kernel_version}',
                'symbol_path': str(xz_path),
                'version_info': version_info.__dict__
            }

        except Exception as e:
            logger.error(f"构建符号表失败: {e}", exc_info=True)
            return {
                'status': 'error',
                'message': f'构建失败: {str(e)}'
            }
        finally:
            if self.temp_dir and os.path.exists(self.temp_dir):
                try:
                    shutil.rmtree(self.temp_dir, ignore_errors=True)
                    logger.debug(f"已清理临时目录: {self.temp_dir}")
                except Exception as e:
                    logger.warning(f"清理临时目录失败: {e}")

    def _check_existing_symbol(self, version_info: LinuxVersionInfo) -> Optional[Path]:
        if version_info.distro == 'macOS':
            symbol_dir = self.symbols_dir / 'macos'
        else:
            symbol_dir = self.symbols_dir / 'linux'

        if not symbol_dir.exists():
            return None

        for file in symbol_dir.glob('*.json.xz'):
            if version_info.kernel_version in file.name:
                logger.info(f"找到已存在的符号表: {file}")
                return file

        return None

    def _clean_old_temp_dirs(self, temp_base: Path):
        import time
        from datetime import datetime, timedelta

        try:
            current_time = time.time()
            one_day_ago = current_time - 86400  

            for temp_dir in temp_base.glob('symbol_build_*'):
                try:
                    if temp_dir.is_dir():
                        mtime = temp_dir.stat().st_mtime
                        if mtime < one_day_ago:
                            shutil.rmtree(temp_dir, ignore_errors=True)
                            logger.debug(f"清理旧临时目录: {temp_dir}")
                except Exception as e:
                    logger.warning(f"清理临时目录失败 {temp_dir}: {e}")
        except Exception as e:
            logger.warning(f"扫描临时目录失败: {e}")

    def _download_dbgsym(self, version_info: LinuxVersionInfo) -> Optional[Path]:
        if version_info.distro == 'Ubuntu':
            return self._download_ubuntu_dbgsym(version_info)
        elif version_info.distro == 'Debian':
            return self._download_debian_dbgsym(version_info)
        elif version_info.distro in ['CentOS', 'Rocky', 'AlmaLinux']:
            return self._download_centos_dbgsym(version_info)
        elif version_info.distro == 'macOS':
            return self._download_macos_dbgsym(version_info)
        else:
            logger.error(f"不支持的发行版: {version_info.distro}")
            return None

    def _search_local_dbgsym(self, kernel_ver: str, pkg_ver: str) -> Optional[Path]:
        patterns = [
            f"**/linux-image-unsigned-{kernel_ver}-dbgsym_*.ddeb",
            f"**/linux-image-{kernel_ver}-dbgsym_*.ddeb",
            f"**/*{kernel_ver}*dbgsym*.ddeb",
        ]

        search_paths = [
            Path.home() / "Downloads",
            Path.home() / "Documents",
            Path.home(),
            self.data_dir,
            self.symbols_dir,
        ]

        for search_path in search_paths:
            if not search_path.exists():
                continue
            for pattern in patterns:
                matches = list(search_path.glob(pattern))
                if matches:
                    found = matches[0]
                    if found.exists() and found.stat().st_size > 1000000:
                        logger.info(f"找到本地 ddeb 文件: {found}")
                        return found

        return None

    def _download_ubuntu_dbgsym(self, version_info: LinuxVersionInfo) -> Optional[Path]:
        kernel_ver = version_info.kernel_version
        pkg_ver = version_info.package_version

        if not pkg_ver:
            pkg_ver = self._guess_ubuntu_package_version(version_info)
            if not pkg_ver:
                logger.error("无法确定包版本")
                return None

        package_candidates = [
            (f"linux-image-unsigned-{kernel_ver}-dbgsym_{pkg_ver}_amd64.ddeb", "ddeb"),
            (f"linux-image-{kernel_ver}-dbgsym_{pkg_ver}_amd64.ddeb", "ddeb"),
            (f"linux-image-unsigned-{kernel_ver}_{pkg_ver}_amd64.deb", "deb"),
            (f"linux-image-{kernel_ver}_{pkg_ver}_amd64.deb", "deb"),
        ]

        last_error = None
        for pkg_name, pkg_type in package_candidates:
            pkg_path = Path(self.temp_dir) / pkg_name

            urls = [
                f"https://mirrors.ustc.edu.cn/ubuntu/pool/main/l/linux/{pkg_name}",
                f"https://mirrors.ustc.edu.cn/ubuntu-debug/pool/main/l/linux/{pkg_name}",
                f"http://ddebs.ubuntu.com/pool/main/l/linux/{pkg_name}",
                f"https://launchpad.net/ubuntu/+archive/primary/+files/{pkg_name}",
            ]

            for url in urls:
                try:
                    logger.debug(f"尝试下载: {url}")
                    self._download_file(url, pkg_path, lambda p: self.progress.report('download', p, f'下载中... {p}%'))
                    if pkg_path.exists() and pkg_path.stat().st_size > 1000000:  
                        logger.debug(f"下载成功: {pkg_path.name} ({pkg_type})")
                        return pkg_path
                except Exception as e:
                    last_error = e
                    logger.debug(f"下载失败 {url}: {e}")
                    if pkg_path.exists():
                        pkg_path.unlink()
                    continue

        logger.debug("直接下载失败，尝试从镜像站搜索...")
        result = self._search_mirror_dbgsym(kernel_ver, pkg_ver)
        if result:
            return result

        logger.debug("镜像站搜索失败，尝试从 Launchpad 搜索...")
        result = self._search_launchpad_dbgsym(version_info)
        if result:
            return result

        logger.error("=" * 60)
        logger.error("符号表制作失败！")
        logger.error(f"内核版本: {kernel_ver}")
        logger.error(f"包版本: {pkg_ver}")
        logger.error("")
        logger.error("原因: 找不到 dbgsym/ddeb 调试符号包")
        logger.error("")
        logger.error("可能的解决方案:")
        logger.error("1. 尝试从 GitHub 下载预编译的符号表")
        logger.error("2. 手动从 Launchpad 下载 ddeb 包")
        logger.error(f"   https://launchpad.net/ubuntu/+source/linux/{pkg_ver}")
        logger.error("3. 检查是否有其他内核版本的内存镜像")
        logger.error("=" * 60)
        return None

    def _search_mirror_dbgsym(self, kernel_ver: str, pkg_ver: str) -> Optional[Path]:
        mirrors = [
            "https://mirrors.ustc.edu.cn/ubuntu/pool/main/l/linux/",
            "https://mirrors.ustc.edu.cn/ubuntu-debug/pool/main/l/linux/",
        ]

        search_patterns = [
            (f"linux-image-unsigned-{kernel_ver}-dbgsym", ".ddeb"),
            (f"linux-image-{kernel_ver}-dbgsym", ".ddeb"),
            (f"linux-image-unsigned-{kernel_ver}", ".deb"),
            (f"linux-image-{kernel_ver}", ".deb"),
        ]

        for mirror in mirrors:
            try:
                logger.debug(f"搜索镜像目录")
                html = self._fetch_url(mirror)

                for pattern_base, ext in search_patterns:
                    pattern = rf'href="({re.escape(pattern_base)}_[^"]+amd64\{ext})"'
                    matches = re.findall(pattern, html, re.IGNORECASE)

                    if matches:
                        file_name = matches[0]
                        file_url = mirror + file_name
                        file_path = Path(self.temp_dir) / file_name

                        logger.info(f"找到匹配的包: {file_name}")
                        try:
                            self._download_file(file_url, file_path, lambda p: self.progress.report('download', p, f'下载中... {p}%'))

                            if file_path.exists() and file_path.stat().st_size > 1000000:
                                logger.debug(f"下载成功")
                                return file_path
                        except Exception as e:
                            logger.warning(f"下载失败: {e}")
                            if file_path.exists():
                                file_path.unlink()
                            continue

            except Exception as e:
                logger.warning(f"镜像站搜索失败 {mirror}: {e}")
                continue

        return None

    def _guess_ubuntu_package_version(self, version_info: LinuxVersionInfo) -> Optional[str]:
        match = re.match(r'^(\d+\.\d+\.\d+)-(\d+)', version_info.kernel_version)
        if match:
            base = f"{match.group(1)}-{match.group(2)}"
            for suffix in ['.1', '.2', '.3', '.4', '.5', '.6', '.7', '.8', '.9',
                          '.10', '.11', '.12', '.13', '.14', '.15', '.16', '.17',
                          '.18', '.19', '.20', '.21', '.22', '.23', '.24', '.25',
                          '.26', '.27', '.28', '.29', '.30', '.31', '.32', '.33',
                          '.34', '.35', '.36', '.37', '.38', '.39', '.40',
                          '.41', '.42', '.43', '.44', '.45', '.46', '.47', '.48',
                          '.49', '.50', '.51', '.52', '.53', '.54', '.55', '.56',
                          '.57', '.58', '.59', '.60', '.61', '.62', '.63', '.64',
                          '.65', '.66', '.67', '.68', '.69', '.70', '.71', '.72',
                          '.73', '.74', '.75', '.76', '.77', '.78', '.79', '.80',
                          '.81', '.82', '.83', '.84', '.85', '.86', '.87', '.88',
                          '.89', '.90', '.91', '.92', '.93', '.94', '.95', '.96',
                          '.97', '.98', '.99', '.100', '.101', '.102', '.103',
                          '.104', '.105', '.106', '.107', '.108', '.109', '.110',
                          '.111', '.112', '.113', '.114', '.115', '.116', '.117',
                          '.118', '.119', '.120', '.121', '.122', '.123', '.124',
                          '.125', '.126', '.127', '.128', '.129', '.130', '.131',
                          '.132', '.133', '.134', '.135', '.136', '.137', '.138',
                          '.139', '.140', '.141', '.142', '.143', '.144', '.145',
                          '.146', '.147', '.148', '.149', '.150', '.151', '.152',
                          '.153', '.154', '.155', '.156', '.157', '.158', '.159',
                          '.160', '.161']:
                return base + suffix
        return None

    def _search_launchpad_dbgsym(self, version_info: LinuxVersionInfo) -> Optional[Path]:
        kernel_ver = version_info.kernel_version
        pkg_ver = version_info.package_version

        search_urls = []

        if pkg_ver:
            search_urls.append(f"https://launchpad.net/ubuntu/+source/linux/{pkg_ver}")
            search_urls.append(f"https://launchpad.net/ubuntu/+source/linux-signed/{pkg_ver}")

        for search_url in search_urls:
            try:
                logger.debug(f"尝试 Launchpad 搜索: {search_url}")
                html = self._fetch_url(search_url)
                logger.debug(f"Launchpad 页面已获取，长度: {len(html)}")

                result = self._try_download_ddeb_from_html(html, kernel_ver)
                if result:
                    return result

                package_patterns = [
                    rf'href="(/ubuntu/[^/]+/\+package/linux-image-unsigned-{re.escape(kernel_ver)}-dbgsym)"',
                    rf'href="(/ubuntu/[^/]+/\+package/linux-image-{re.escape(kernel_ver)}-dbgsym)"',
                ]

                for pattern in package_patterns:
                    matches = re.findall(pattern, html)
                    for pkg_path in matches:
                        try:
                            pkg_url = f"https://launchpad.net{pkg_path}"
                            logger.debug(f"获取包详情页")
                            pkg_html = self._fetch_url(pkg_url)
                            logger.debug(f"包详情页已获取")

                            result = self._try_download_ddeb_from_html(pkg_html, kernel_ver)
                            if result:
                                return result
                        except Exception as e:
                            logger.warning(f"获取包详情页失败: {e}")
                            continue

            except HTTPError as e:
                logger.warning(f"Launchpad 页面访问失败 ({search_url}): HTTP {e.code}")
                continue
            except Exception as e:
                logger.warning(f"Launchpad 搜索失败 ({search_url}): {e}")
                continue

        logger.error("Launchpad 搜索未找到可用的 ddeb 文件")
        return None

    def _try_download_ddeb_from_html(self, html: str, kernel_ver: str) -> Optional[Path]:
        patterns = [
            r'href="(https?://launchpadlibrarian\.net/\d+/[^"]*dbgsym[^"]*\.ddeb)"',
            rf'href="(https?://launchpadlibrarian\.net/\d+/[^"]*{re.escape(kernel_ver)}[^"]*\.ddeb)"',
            r'href="(https?://[^"\s]*launchpadlibrarian[^"\s]*\.ddeb)"',
            rf'href="(https?://launchpad\.net/ubuntu/\+archive/primary/\+files/[^"]*{re.escape(kernel_ver)}[^"]*dbgsym[^"]*\.ddeb)"',
            rf'href="(https?://[^"\s]*{re.escape(kernel_ver)}[^"\s]*dbgsym[^"\s]*\.ddeb)"',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for ddeb_url in matches:
                try:
                    if ddeb_url.startswith('http://'):
                        ddeb_url = 'https://' + ddeb_url[7:]

                    ddeb_name = ddeb_url.split('/')[-1]
                    ddeb_path = Path(self.temp_dir) / ddeb_name

                    logger.debug(f"找到 ddeb 链接")
                    self._download_file(ddeb_url, ddeb_path, lambda p: self.progress.report('download', p, f'下载中... {p}%'))

                    if ddeb_path.exists() and ddeb_path.stat().st_size > 1000000:
                        return ddeb_path
                except Exception as e:
                    logger.warning(f"下载 ddeb 失败: {e}")
                    continue

        all_ddeb_links = re.findall(r'href="(https?://[^"\s]*\.ddeb)"', html, re.IGNORECASE)
        for link in all_ddeb_links[:5]:
            try:
                logger.debug(f"尝试下载 ddeb: {link}")
                ddeb_name = link.split('/')[-1]
                ddeb_path = Path(self.temp_dir) / ddeb_name
                self._download_file(link, ddeb_path, lambda p: self.progress.report('download', p, f'下载中... {p}%'))
                if ddeb_path.exists() and ddeb_path.stat().st_size > 1000000:
                    return ddeb_path
            except Exception as e:
                logger.warning(f"下载失败: {e}")
                continue

        return None

    def _download_debian_dbgsym(self, version_info: LinuxVersionInfo) -> Optional[Path]:

        kernel_ver = version_info.kernel_version

        mirrors = [
            "https://mirrors.ustc.edu.cn/debian/pool/main/l/linux/",
            "https://mirrors.tuna.tsinghua.edu.cn/debian/pool/main/l/linux/",
            "https://mirrors.aliyun.com/debian/pool/main/l/linux/",
            "https://mirrors.hit.edu.cn/debian/pool/main/l/linux/",
        ]

        for mirror in mirrors:
            try:
                logger.debug(f"尝试 Debian 镜像")
                html = self._fetch_url(mirror)
                pattern = rf'href="(linux-image-{re.escape(kernel_ver)}[^"]*-dbg[^"]*\.deb)"'
                match = re.search(pattern, html)

                if match:
                    deb_name = match.group(1)
                    deb_url = mirror + deb_name
                    deb_path = Path(self.temp_dir) / deb_name

                    self._download_file(deb_url, deb_path, lambda p: self.progress.report('download', p, f'下载中... {p}%'))
                    return deb_path

            except Exception as e:
                logger.warning(f"Debian 镜像 {mirror} 访问失败: {e}")
                continue

        logger.error("所有 Debian 镜像源都失败了")
        return None

    def _download_centos_dbgsym(self, version_info: LinuxVersionInfo) -> Optional[Path]:
        kernel_ver = version_info.kernel_version
        distro_ver = version_info.distro_codename

        base_urls = [
            f"https://mirrors.ustc.edu.cn/centos-vault/{distro_ver}.2009/BaseOS/x86_64/Packages/",
            f"https://mirrors.tuna.tsinghua.edu.cn/centos-vault/{distro_ver}.2009/BaseOS/x86_64/Packages/",
            f"https://mirrors.aliyun.com/centos-vault/{distro_ver}.2009/BaseOS/x86_64/Packages/",
            f"http://vault.centos.org/{distro_ver}.2009/BaseOS/x86_64/Packages/",
        ]

        for base_url in base_urls:
            try:
                logger.debug(f"尝试 CentOS 镜像")
                html = self._fetch_url(base_url)
                pattern = rf'href="(kernel-debuginfo-{re.escape(kernel_ver)}[^"]*\.rpm)"'
                match = re.search(pattern, html)

                if match:
                    rpm_name = match.group(1)
                    rpm_url = base_url + rpm_name
                    rpm_path = Path(self.temp_dir) / rpm_name

                    self._download_file(rpm_url, rpm_path, lambda p: self.progress.report('download', p, f'下载中... {p}%'))
                    return rpm_path

            except Exception as e:
                logger.warning(f"CentOS 镜像 {base_url} 访问失败: {e}")
                continue

        logger.error("所有 CentOS 镜像源都失败了")
        return None

    def _download_macos_dbgsym(self, version_info: LinuxVersionInfo) -> Optional[Path]:
        kernel_ver = version_info.kernel_version

        logger.error("macOS 符号表需要手动获取")
        logger.error(f"内核版本: {kernel_ver}")
        logger.error("=" * 60)
        logger.error("macOS 调试符号包无法自动下载，请手动获取：")
        logger.error("")
        logger.error("方法1: 从 Apple 开发者网站下载")
        logger.error("  1. 访问 https://developer.apple.com/download/")
        logger.error("  2. 下载对应版本的 'Additional Tools for Xcode'")
        logger.error("  3. 挂载 DMG 后找到 debug 版本的 kernel")
        logger.error("")
        logger.error("方法2: 从同版本系统提取（需要关闭 SIP）")
        logger.error("  1. 关闭 SIP: csrutil disable")
        logger.error("  2. 复制 /System/Library/Kernels/kernel 到 U 盘")
        logger.error("  3. 使用 gzrecompress 解压: gzrecompress kernel")
        logger.error("")
        logger.error("获取到 kernel 文件后，请放到以下位置：")
        logger.error(f"  {self.data_dir}/tools/macos-kernel-{kernel_ver}")
        logger.error("=" * 60)

        possible_paths = [
            self.data_dir / 'tools' / f'macos-kernel-{kernel_ver}',
            self.data_dir / 'tools' / 'macos-kernel',
            Path.home() / 'Downloads' / f'kernel-{kernel_ver}',
            Path.home() / 'Downloads' / 'kernel',
        ]

        for kernel_path in possible_paths:
            if kernel_path.exists() and kernel_path.is_file():
                logger.info(f"找到 macOS kernel: {kernel_path}")
                return kernel_path

        return None

    def _extract_vmlinux(self, package_path: Path) -> Optional[Path]:
        system = platform.system()

        try:
            if package_path.suffix == '.ddeb' or package_path.suffix == '.deb':
                return self._extract_deb(package_path)
            elif package_path.suffix == '.rpm':
                return self._extract_rpm(package_path)
            else:
                logger.error(f"不支持的包格式: {package_path.suffix}")
                return None

        except Exception as e:
            logger.error(f"解压失败: {e}", exc_info=True)
            return None

    def _extract_deb(self, deb_path: Path) -> Optional[Path]:
        system = platform.system()
        extract_dir = Path(self.temp_dir) / 'extracted'
        extract_dir.mkdir(exist_ok=True)

        if system == 'Linux':
            try:
                subprocess.run(
                    ['dpkg-deb', '-x', str(deb_path), str(extract_dir)],
                    check=True,
                    capture_output=True,
                    **_get_subprocess_kwargs()
                )
            except subprocess.CalledProcessError as e:
                logger.error(f"dpkg-deb 解压失败: {e.stderr.decode()}")
                return None
            except FileNotFoundError:
                logger.warning("dpkg-deb 未找到，尝试使用 ar + tar")
                return self._extract_deb_with_ar(deb_path, extract_dir)
        else:
            return self._extract_deb_with_ar(deb_path, extract_dir)

        return self._find_vmlinux(extract_dir)

    def _extract_deb_with_ar(self, deb_path: Path, extract_dir: Path) -> Optional[Path]:

        try:
            system = platform.system()
            if system != 'Windows':
                try:
                    subprocess.run(
                        ['ar', '-x', str(deb_path)],
                        cwd=str(extract_dir),
                        check=True,
                        capture_output=True,
                        **_get_subprocess_kwargs()
                    )
                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                    logger.warning(f"ar 命令失败，尝试使用 Python 解析: {e}")
                    self._extract_ar_python(deb_path, extract_dir)
            else:
                logger.info("Windows 系统，使用 Python 解析 AR 格式")
                self._extract_ar_python(deb_path, extract_dir)

            data_tar = None
            for f in extract_dir.iterdir():
                if f.name.startswith('data.tar'):
                    data_tar = f
                    break

            if not data_tar:
                logger.error("未找到 data.tar 文件")
                return None

            if data_tar.suffix == '.xz':
                with tarfile.open(data_tar, 'r:xz') as tar:
                    tar.extractall(extract_dir)
            elif data_tar.suffix == '.gz':
                with tarfile.open(data_tar, 'r:gz') as tar:
                    tar.extractall(extract_dir)
            elif data_tar.suffix == '.zst':
                try:
                    import zstandard as zstd
                    with open(data_tar, 'rb') as f:
                        dctx = zstd.ZstdDecompressor()
                        with open(data_tar.with_suffix(''), 'wb') as dst:
                            dctx.copy_stream(f, dst)
                    with tarfile.open(data_tar.with_suffix(''), 'r') as tar:
                        tar.extractall(extract_dir)
                except ImportError:
                    subprocess.run(
                        ['zstd', '-d', str(data_tar), '-o', str(data_tar.with_suffix(''))],
                        check=True,
                        **_get_subprocess_kwargs()
                    )
                    with tarfile.open(data_tar.with_suffix(''), 'r') as tar:
                        tar.extractall(extract_dir)
            else:
                with tarfile.open(data_tar, 'r:*') as tar:
                    tar.extractall(extract_dir)

            return self._find_vmlinux(extract_dir)

        except subprocess.CalledProcessError as e:
            logger.error(f"解压失败: {e.stderr.decode() if e.stderr else str(e)}")
            return None
        except Exception as e:
            logger.error(f"解压失败: {e}", exc_info=True)
            return None

    def _extract_ar_python(self, ar_path: Path, extract_dir: Path):
        import struct

        with open(ar_path, 'rb') as f:
            magic = f.read(8)
            if magic != b'!<arch>\n':
                raise ValueError(f"不是有效的 AR 文件: {magic}")

            while True:
                header = f.read(60)
                if len(header) < 60:
                    break

                name = header[0:16].decode('ascii')
                size_str = header[48:58].decode('ascii')

                name = name.rstrip('/').strip()

                try:
                    size = int(size_str.strip())
                except ValueError:
                    logger.warning(f"无法解析 AR 文件大小: '{size_str}', 跳过")
                    break

                if name.startswith('/') or name == '':
                    f.seek((size + 1) // 2 * 2, 1)
                    continue

                content = f.read(size)

                output_path = extract_dir / name
                with open(output_path, 'wb') as out:
                    out.write(content)

                if size % 2 == 1:
                    f.read(1)

    def _extract_rpm(self, rpm_path: Path) -> Optional[Path]:
        extract_dir = Path(self.temp_dir) / 'extracted'
        extract_dir.mkdir(exist_ok=True)

        try:
            result = subprocess.run(
                f'rpm2cpio "{rpm_path}" | cpio -idmv',
                cwd=str(extract_dir),
                shell=True,
                capture_output=True,
                **_get_subprocess_kwargs()
            )

            if result.returncode != 0:
                logger.error(f"RPM 解压失败: {result.stderr.decode()}")
                return None

            return self._find_vmlinux(extract_dir)

        except Exception as e:
            logger.error(f"RPM 解压失败: {e}")
            return None

    def _find_vmlinux(self, extract_dir: Path) -> Optional[Path]:
        possible_paths = [
            extract_dir / 'usr' / 'lib' / 'debug' / 'boot',
            extract_dir / 'lib' / 'debug' / 'boot',
            extract_dir / 'boot',
        ]

        for path in possible_paths:
            if path.exists():
                for f in path.iterdir():
                    if f.name.startswith('vmlinux-'):
                        logger.info(f"找到 vmlinux: {f}")
                        self.progress.report('extract', 100, f'解压完成，找到 vmlinux')
                        return f

        for f in extract_dir.rglob('vmlinux*'):
            if f.is_file() and 'vmlinux' in f.name:
                logger.info(f"递归搜索找到 vmlinux: {f}")
                self.progress.report('extract', 100, f'解压完成，找到 vmlinux')
                return f

        logger.error(f"未找到 vmlinux 文件，目录内容: {list(extract_dir.rglob('*'))[:20]}")
        return None

    def _generate_isf(self, vmlinux_path: Path, version_info: LinuxVersionInfo) -> Optional[Path]:
        if not self.dwarf2json_path:
            logger.error("dwarf2json 工具未找到")
            return None

        output_path = Path(self.temp_dir) / f"symbol_{version_info.kernel_version}.json"

        if version_info.distro == 'macOS':
            cmd = 'mac'
        else:
            cmd = 'linux'

        try:
            result = subprocess.run(
                [str(self.dwarf2json_path), cmd, '--elf', str(vmlinux_path)],
                capture_output=True,
                check=True,
                **_get_subprocess_kwargs()
            )

            with open(output_path, 'wb') as f:
                f.write(result.stdout)

            logger.info(f"ISF 符号表已生成: {output_path}")
            self.progress.report('convert', 100, '符号表转换完成')
            return output_path

        except subprocess.CalledProcessError as e:
            logger.error(f"dwarf2json 执行失败: {e.stderr.decode()}")
            return None
        except Exception as e:
            logger.error(f"ISF 生成失败: {e}", exc_info=True)
            return None

    def _compress_and_save(self, json_path: Path, version_info: LinuxVersionInfo) -> Path:
        if version_info.distro == 'macOS':
            symbol_dir = self.symbols_dir / 'macos'
        else:
            symbol_dir = self.symbols_dir / 'linux'
        symbol_dir.mkdir(parents=True, exist_ok=True)

        distro = version_info.distro  
        kernel_version = version_info.kernel_version  
        arch = version_info.arch  

        output_name = f"{distro}_{kernel_version}_{arch}.json.xz"
        output_path = symbol_dir / output_name

        with open(json_path, 'rb') as f_in:
            with lzma.open(output_path, 'wb', preset=9) as f_out:
                shutil.copyfileobj(f_in, f_out)

        logger.info(f"符号表已保存: {output_path}")
        self.progress.report('compress', 100, '压缩完成')

        return output_path

    def _is_china_mirror(self, url: str) -> bool:
        china_domains = [
            'mirrors.ustc.edu.cn',  
            'mirrors.tuna.tsinghua.edu.cn',  
            'mirrors.aliyun.com',  
            'mirrors.hit.edu.cn',  
            'mirrors.bfsu.edu.cn',  
            'mirror.bjtu.edu.cn',  
            'mirrors.bupt.edu.cn',  
            'mirrors.nju.edu.cn',  
            'mirrors.hit.edu.cn',  
            'mirrors.sjtug.sjtu.edu.cn',  
            'mirrors.zju.edu.cn',  
            'mirrors.hust.edu.cn',  
            'mirrors.sysu.edu.cn',  
            'mirrors.neusoft.edu.cn',  
            'mirrors.pku.edu.cn',  
            'gitee.com',  
        ]
        for domain in china_domains:
            if domain in url:
                return True
        return False

    def _create_opener(self, url: str = None):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        https_handler = HTTPSHandler(context=ctx)

        proxy_dict = {}

        if url and self._is_china_mirror(url):
            logger.debug(f"国内镜像，不使用代理")
        elif self.proxy_config:
            proxy_type = self.proxy_config.get('type', 'http')
            host = self.proxy_config.get('host')
            port = self.proxy_config.get('port')
            username = self.proxy_config.get('username')
            password = self.proxy_config.get('password')

            if host and port:
                if username and password:
                    proxy_url = f"{proxy_type}://{username}:{password}@{host}:{port}"
                else:
                    proxy_url = f"{proxy_type}://{host}:{port}"

                logger.debug(f"使用代理: {proxy_type}")

                if proxy_type in ['http', 'https']:
                    proxy_dict['http'] = proxy_url
                    proxy_dict['https'] = proxy_url
                elif proxy_type == 'socks5':
                    try:
                        import socks
                        proxy_dict['http'] = f"socks5h://{host}:{port}"
                        proxy_dict['https'] = f"socks5h://{host}:{port}"
                        if username and password:
                            proxy_dict['http'] = f"socks5h://{username}:{password}@{host}:{port}"
                            proxy_dict['https'] = f"socks5h://{username}:{password}@{host}:{port}"
                    except ImportError:
                        logger.warning("SOCKS5 代理需要安装 PySocks 库: pip install PySocks")
                        logger.debug("将尝试不使用代理连接...")

        if proxy_dict:
            proxy_handler = ProxyHandler(proxy_dict)
            return build_opener(proxy_handler, https_handler)
        else:
            return build_opener(https_handler)

    def _fetch_url(self, url: str) -> str:
        request = Request(url)
        request.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        request.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
        request.add_header('Accept-Language', 'zh-CN,zh;q=0.9,en;q=0.8')
        request.add_header('Accept-Encoding', 'gzip, deflate, br')
        request.add_header('Referer', url)
        request.add_header('Connection', 'keep-alive')

        opener = self._create_opener(url)

        with opener.open(request, timeout=30) as response:
            data = response.read()
            if response.headers.get('Content-Encoding') == 'gzip':
                data = gzip.decompress(data)
            return data.decode('utf-8', errors='ignore')

    def _download_file(self, url: str, output_path: Path, progress_callback: Optional[Callable] = None):
        request = Request(url)
        request.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        request.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
        request.add_header('Accept-Language', 'zh-CN,zh;q=0.9,en;q=0.8')
        request.add_header('Accept-Encoding', 'gzip, deflate, br')
        request.add_header('Referer', url)
        request.add_header('Connection', 'keep-alive')

        opener = self._create_opener(url)

        with opener.open(request, timeout=120) as response:
            if hasattr(response, 'status') and response.status >= 400:
                raise HTTPError(url, response.status, response.msg, response.headers, None)

            total_size = int(response.headers.get('Content-Length', 0))
            downloaded = 0
            chunk_size = 8192
            last_reported_progress = -1  

            with open(output_path, 'wb') as f:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break

                    f.write(chunk)
                    downloaded += len(chunk)

                    if total_size > 0 and progress_callback:
                        current_progress = int(downloaded * 100 / total_size)
                        if current_progress != last_reported_progress:
                            progress_callback(current_progress)
                            last_reported_progress = current_progress

        if downloaded == 0:
            if output_path.exists():
                output_path.unlink()
            raise Exception(f"下载的文件为空 (0 bytes): {url}")

        logger.debug(f"下载完成: {output_path.name} ({downloaded} bytes)")


def build_linux_symbol_table(banner: str, symbols_dir: Path,
                            progress_callback: Optional[Callable] = None,
                            proxy_config: Optional[Dict] = None) -> Dict[str, Any]:
    builder = SymbolTableBuilder(symbols_dir, progress_callback, proxy_config)
    return builder.build(banner)
