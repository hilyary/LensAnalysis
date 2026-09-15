import os
import sys
import re
import json
import struct
import hashlib
import base64
import html
import logging
import shutil
import subprocess
import platform
import copy
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable

logger = logging.getLogger(__name__)


class WeChatAnalyzer:

    def __init__(self, image_path: str, vol_path: str = None, symbols_dir: str = None, wrapper=None):
        self.image_path = image_path
        self._vol_path = vol_path or self._find_vol_command()
        self._symbols_dir = symbols_dir
        self._wrapper = wrapper


    @staticmethod
    def _find_vol_command() -> Optional[str]:
        try:
            import platform as _platform
            system = _platform.system()
            if system == 'Windows':
                config_dir = Path('C:\\LensAnalysis')
            elif system == 'Darwin':
                config_dir = Path.home() / 'Library' / 'Application Support' / 'LensAnalysis'
            else:
                config_dir = Path.home() / '.local' / 'share' / 'LensAnalysis'

            config_path = config_dir / 'config.json'
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                custom = config.get('settings', {}).get('custom_vol_path')
                if custom and Path(custom).exists() and os.access(custom, os.X_OK):
                    return custom
        except Exception:
            pass

        is_windows = platform.system() == 'Windows'

        if not is_windows:
            vol = shutil.which('vol')
            if vol:
                return vol

            home = Path.home()
            for p in [
                home / '.local' / 'bin' / 'vol',
                home / 'Library' / 'Python' / '3.12' / 'bin' / 'vol',
                home / 'Library' / 'Python' / '3.11' / 'bin' / 'vol',
                home / 'Library' / 'Python' / '3.10' / 'bin' / 'vol',
            ]:
                if p.exists() and os.access(p, os.X_OK):
                    return str(p)

        return None

    def _get_subprocess_kwargs(self, **kwargs) -> Dict[str, Any]:
        if platform.system() == 'Windows':
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        env = kwargs.get('env', os.environ.copy())
        env['SYSDINTERNALS_EULA'] = '1'
        env['PYTHONWARNINGS'] = 'ignore'
        kwargs['env'] = env
        return kwargs

    def _run_vol(self, plugin: str, extra_args: List[str] = None, output_dir: str = None) -> str:
        env = os.environ.copy()
        if self._symbols_dir and Path(self._symbols_dir).exists():
            env['VOLATILITY_SYMBOLS'] = str(self._symbols_dir)
        env['PYTHONIOENCODING'] = 'utf-8'

        vol_path = self._vol_path
        if vol_path:
            cmd = [vol_path, '-f', self.image_path]
        else:
            python = shutil.which('python3') or shutil.which('python') or sys.executable
            cmd = [python, '-m', 'volatility3', '-f', self.image_path]

        if self._symbols_dir and Path(self._symbols_dir).exists():
            cmd.extend(['-s', str(self._symbols_dir)])

        if output_dir:
            cmd.extend(['-o', str(output_dir)])

        cmd.append(plugin)
        if extra_args:
            cmd.extend(extra_args)

        logger.info(f"执行命令: {' '.join(cmd)}")

        subprocess_kwargs = self._get_subprocess_kwargs(
            env=env,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=600,
            check=False
        )

        result = subprocess.run(cmd, **subprocess_kwargs)

        if result.returncode != 0:
            stderr = result.stderr or ''
            logger.error(f"vol 命令失败: {stderr[:500]}")
            raise RuntimeError(f"Volatility 执行失败: {stderr[:200]}")

        return result.stdout

    def _run_vol_parsed(self, plugin: str, extra_args: List[str] = None) -> List[Dict]:
        output = self._run_vol(plugin, extra_args)
        return self._parse_table_output(output)

    @staticmethod
    def _parse_table_output(output: str) -> List[Dict]:
        lines = output.strip().split('\n')
        results = []
        header = None

        for line in lines:
            line = line.strip()
            if not line or line.startswith('Progress'):
                continue
            if all(c in '-= ' for c in line):
                continue

            parts = line.split('\t') if '\t' in line else re.split(r'\s{2,}', line)
            parts = [p.strip() for p in parts if p.strip()]

            if header is None:
                header = parts
                continue

            if header and len(parts) >= 2:
                row = {}
                for i, h in enumerate(header):
                    row[h] = parts[i] if i < len(parts) else ''
                results.append(row)

        return results


    @staticmethod
    def check_dependencies() -> Dict:
        try:
            from Crypto.Cipher import AES
            return {'available': True}
        except ImportError:
            return {
                'available': False,
                'message': '需要安装 pycryptodome：pip install pycryptodome'
            }


    def _run_plugin_cached(self, plugin_id: str, cache_dir: str = None) -> List[Dict]:
        all_results = []

        if cache_dir:
            cache_file = Path(cache_dir) / f'{plugin_id}.json'
            if cache_file.exists():
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cached = json.load(f)
                    all_results = cached.get('results', [])
                    if all_results:
                        logger.info(f"微信分析: 从 {plugin_id} 缓存加载 {len(all_results)} 条")
                        return all_results
                except Exception as e:
                    logger.warning(f"读取 {plugin_id} 缓存失败: {e}")

        if self._wrapper:
            from datetime import datetime
            result = self._wrapper.run_plugin(plugin_id)
            all_results = result.get('results', [])
        else:
            try:
                vol_plugin = {
                    'pslist': 'windows.pslist.PsList',
                    'filescan': 'windows.filescan.FileScan',
                }.get(plugin_id, plugin_id)
                all_results = self._run_vol_parsed(vol_plugin)
            except Exception as e:
                logger.error(f"{plugin_id} 执行失败: {e}")
                return []

        if cache_dir and all_results:
            try:
                from datetime import datetime
                cache_file = Path(cache_dir) / f'{plugin_id}.json'
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_data = {
                    'plugin': plugin_id,
                    'timestamp': datetime.now().isoformat(),
                    'image': Path(self.image_path).name,
                    'results': all_results,
                }
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(cache_data, f, ensure_ascii=False, indent=2)
                logger.info(f"微信分析: 已保存 {plugin_id} 缓存 ({len(all_results)} 条)")
            except Exception as e:
                logger.warning(f"保存 {plugin_id} 缓存失败: {e}")

        return all_results

    def find_wechat_process(self, cache_dir: str = None) -> List[Dict]:
        all_procs = self._run_plugin_cached('pslist', cache_dir)

        wechat_procs = []
        for proc in all_procs:
            name = proc.get('name', '')
            if name.lower() in ('weixin.exe', 'wechat.exe'):
                wechat_procs.append({
                    'pid': proc.get('pid', 0),
                    'name': name,
                    'create_time': proc.get('create_time', ''),
                    'offset': proc.get('offset', ''),
                })
        return wechat_procs

    def dump_process_memory(self, pid: int, output_dir: str,
                            progress_cb: Callable = None) -> Optional[str]:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if progress_cb:
            progress_cb(5, '正在 dump 进程内存...')

        existing_files = set()
        if output_dir.exists():
            existing_files = set(output_dir.iterdir())

        try:
            self._run_vol(
                'windows.memmap.Memmap',
                ['--pid', str(pid), '--dump'],
                output_dir=str(output_dir)
            )
        except Exception as e:
            logger.error(f"memmap dump 失败: {e}")
            return None

        output_files = []
        for f in output_dir.iterdir():
            if f.is_file() and f.name.startswith(f'pid.{pid}.') and f.name.endswith('.dmp'):
                if f not in existing_files:
                    output_files.append(f)

        if output_files:
            if len(output_files) == 1:
                logger.info(f"dump 文件: {output_files[0]}")
                return str(output_files[0])

            merged_path = output_dir / f'pid.{pid}.merged.dmp'
            with open(merged_path, 'wb') as out_f:
                for f in sorted(output_files):
                    with open(f, 'rb') as in_f:
                        out_f.write(in_f.read())
            logger.info(f"合并 {len(output_files)} 个 dump 文件到: {merged_path}")
            return str(merged_path)

        logger.warning(f"未找到 pid.{pid}.*.dmp 文件")
        return None

    def scan_keys(self, dump_path: str, progress_cb: Callable = None) -> List[Dict]:
        if progress_cb:
            progress_cb(40, '正在扫描密钥...')

        pattern = re.compile(rb"x'([0-9a-fA-F]{64}|[0-9a-fA-F]{96})'")
        keys = []

        file_size = os.path.getsize(dump_path)
        chunk_size = 64 * 1024 * 1024  
        overlap = 256  

        with open(dump_path, 'rb') as f:
            offset = 0
            prev_tail = b''
            while offset < file_size:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                search_data = prev_tail + chunk
                base_offset = offset - len(prev_tail)

                for match in pattern.finditer(search_data):
                    hex_str = match.group(1).decode('ascii')
                    enc_key = hex_str[:64]  
                    salt = hex_str[64:] if len(hex_str) > 64 else ''
                    full_hex = hex_str
                    if not any(k['full_hex'] == full_hex for k in keys):
                        keys.append({
                            'enc_key': enc_key,
                            'salt': salt,
                            'full_hex': full_hex,
                            'offset': match.start() + base_offset,
                            'pragma_key': f"x'{full_hex}'",
                        })

                prev_tail = chunk[-overlap:] if len(chunk) > overlap else chunk
                offset += len(chunk)

                if progress_cb:
                    pct = 40 + int((offset / file_size) * 15)
                    progress_cb(pct, f'扫描密钥... {offset / file_size * 100:.0f}%')

        logger.info(f"扫描到 {len(keys)} 组候选密钥")
        return keys

    def find_wechat_dbs(self, cache_dir: str = None, progress_cb: Callable = None) -> List[Dict]:
        if progress_cb:
            progress_cb(55, '正在查找微信数据库文件...')

        all_files = self._run_plugin_cached('filescan', cache_dir)

        wechat_dbs = []
        seen_paths = set()
        for row in all_files:
            file_path = row.get('path', '') or row.get('file_name', '')
            file_name = os.path.basename(file_path.replace('\\', '/')) or row.get('file_name', '')
            offset = row.get('offset', '')

            if 'xwechat_files' in file_path.lower() and file_name.endswith('.db') and 'all_users' not in file_path.lower():
                normalized_path = file_path.replace('/', '\\').lower()
                if normalized_path in seen_paths:
                    logger.info(f"跳过重复微信数据库路径: {file_path} (offset={offset})")
                    continue

                seen_paths.add(normalized_path)
                wechat_dbs.append({
                    'offset': offset,
                    'file_name': file_name,
                    'file_path': file_path,
                })

        logger.info(f"找到 {len(wechat_dbs)} 个微信数据库文件")
        return wechat_dbs

    def extract_db(self, offset: str, output_dir: str) -> Optional[str]:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        existing_files = set()
        if output_dir.exists():
            existing_files = set(output_dir.iterdir())

        try:
            self._run_vol(
                'windows.dumpfiles.DumpFiles',
                ['--virtaddr', str(offset)],
                output_dir=str(output_dir)
            )
        except Exception as e:
            logger.error(f"DumpFiles 执行失败: {e}")
            return None

        found_files = []
        for f in output_dir.iterdir():
            if f.is_file() and f not in existing_files and f.stat().st_size > 0:
                found_files.append(f)
                
        if found_files:
            for f in found_files:
                if str(f.name).endswith('.dat'):
                    logger.info(f"提取文件: {f.name} ({f.stat().st_size} bytes)")
                    return str(f)
            logger.info(f"提取文件 (非 dat): {found_files[0].name} ({found_files[0].stat().st_size} bytes)")
            return str(found_files[0])

        return None

    def validate_and_match(self, dbs: List[Dict], keys: List[Dict]) -> List[Dict]:
        import hmac

        matched = []

        for db_info in dbs:
            db_path = db_info.get('local_path')
            if not db_path or not Path(db_path).exists():
                db_info['status'] = 'FILE_NOT_FOUND'
                matched.append(db_info)
                continue

            try:
                with open(db_path, 'rb') as f:
                    page1 = f.read(4096)
            except Exception as e:
                logger.error(f"读取数据库失败 {db_path}: {e}")
                db_info['status'] = 'READ_ERROR'
                matched.append(db_info)
                continue

            if len(page1) < 4096:
                db_info['status'] = 'FILE_TOO_SMALL'
                matched.append(db_info)
                continue

            salt = page1[:16]

            found = False
            for key_info in keys:
                full_hex = key_info['full_hex']
                key_bytes = bytes.fromhex(full_hex[:64])

                try:
                    mac_salt = bytes(b ^ 0x3A for b in salt)
                    mac_key = hashlib.pbkdf2_hmac(
                        'sha512', key_bytes, mac_salt,
                        iterations=2, dklen=32
                    )

                    page_num = struct.pack('<I', 1)
                    hmac_data = page1[16:4032] + page_num
                    expected_hmac = page1[4032:4096]  

                    computed_hmac = hmac.new(mac_key, hmac_data, hashlib.sha512).digest()

                    if computed_hmac == expected_hmac:
                        db_info['enc_key'] = key_info['enc_key']
                        db_info['salt'] = salt.hex()
                        db_info['pragma_key'] = f"x'{full_hex}'"
                        db_info['status'] = 'DECRYPTED'
                        found = True
                        logger.info(f"匹配成功: {db_info['file_name']} -> key {key_info['enc_key'][:16]}...")
                        break
                except Exception as e:
                    logger.debug(f"密钥验证异常: {e}")
                    continue

            if not found:
                db_info['status'] = 'NO_KEY'
                db_info['salt'] = salt.hex()

            matched.append(db_info)

        return matched

    def decrypt_db(self, enc_key_hex: str, db_path: str, out_path: str) -> bool:
        from Crypto.Cipher import AES

        key_bytes = bytes.fromhex(enc_key_hex)

        with open(db_path, 'rb') as f:
            data = f.read()

        if len(data) < 4096:
            logger.error(f"数据库文件太小: {len(data)} bytes")
            return False

        page_size = 4096
        total_pages = len(data) // page_size
        decrypted = bytearray()

        for page_num in range(total_pages):
            page_start = page_num * page_size
            page = data[page_start:page_start + page_size]
            if len(page) < page_size:
                break

            iv = page[4016:4032]

            if page_num == 0:
                cipher_text = page[16:4016]
                dec = AES.new(key_bytes, AES.MODE_CBC, iv).decrypt(cipher_text)
                decrypted.extend(b"SQLite format 3\x00")
                decrypted.extend(dec)
                decrypted.extend(b'\x00' * 80)
            else:
                cipher_text = page[0:4016]
                dec = AES.new(key_bytes, AES.MODE_CBC, iv).decrypt(cipher_text)
                decrypted.extend(dec)
                decrypted.extend(b'\x00' * 80)

        with open(out_path, 'wb') as f:
            f.write(bytes(decrypted))

        logger.info(f"解密完成: {out_path} ({len(decrypted)} bytes, {total_pages} pages)")
        return True

    @staticmethod
    def _merge_records_by_key(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]], key_field: str) -> List[Dict[str, Any]]:
        index = {}
        for item in existing:
            key = item.get(key_field)
            if key not in (None, ''):
                index[key] = item

        for item in incoming:
            key = item.get(key_field)
            if key in (None, ''):
                existing.append(dict(item))
                continue
            target = index.get(key)
            if target is None:
                record = dict(item)
                existing.append(record)
                index[key] = record
            else:
                for field, value in item.items():
                    if value not in (None, '', []):
                        target[field] = value
        return existing

    @staticmethod
    def _apply_avatar_entries(result: Dict[str, Any], avatars: List[Dict[str, Any]]) -> None:
        avatar_map = {a.get('username'): a for a in avatars if a.get('username')}
        if not avatar_map:
            return

        for contact in result.get('contacts', []):
            avatar = avatar_map.get(contact.get('username'))
            if avatar:
                contact['avatar_data_url'] = avatar.get('avatar_data_url', '')
                contact['avatar_md5'] = avatar.get('md5', '')

        for session in result.get('sessions', []):
            avatar = avatar_map.get(session.get('username'))
            if avatar:
                session['avatar_data_url'] = avatar.get('avatar_data_url', '')
                session['avatar_md5'] = avatar.get('md5', '')

        for biz_session in result.get('biz_sessions', []):
            avatar = avatar_map.get(biz_session.get('username'))
            if avatar:
                biz_session['avatar_data_url'] = avatar.get('avatar_data_url', '')
                biz_session['avatar_md5'] = avatar.get('md5', '')

        for post in result.get('sns_posts', []):
            avatar = avatar_map.get(post.get('username'))
            if avatar:
                post['avatar_data_url'] = avatar.get('avatar_data_url', '')

        for message in result.get('sns_messages', []):
            avatar = avatar_map.get(message.get('from_username'))
            if avatar:
                message['avatar_data_url'] = avatar.get('avatar_data_url', '')

        for request in result.get('friend_requests', []):
            avatar = avatar_map.get(request.get('username'))
            if avatar:
                request['avatar_data_url'] = avatar.get('avatar_data_url', '')

    @staticmethod
    def _enrich_result_entities(result: Dict[str, Any]) -> None:
        contact_map = {c.get('username'): c for c in result.get('contacts', []) if c.get('username')}

        for session in result.get('sessions', []):
            contact = contact_map.get(session.get('username'))
            if contact:
                session['nick_name'] = contact.get('nick_name', session.get('nick_name', ''))
                session['remark'] = contact.get('remark', session.get('remark', ''))
                if contact.get('avatar_data_url'):
                    session['avatar_data_url'] = contact.get('avatar_data_url', '')
                if contact.get('avatar_md5'):
                    session['avatar_md5'] = contact.get('avatar_md5', '')
                if not session.get('avatar_data_url') and contact.get('small_head_url'):
                    session['small_head_url'] = contact.get('small_head_url', '')

        for biz_session in result.get('biz_sessions', []):
            contact = contact_map.get(biz_session.get('username'))
            if contact:
                biz_session['nick_name'] = contact.get('nick_name', biz_session.get('nick_name', ''))
                biz_session['remark'] = contact.get('remark', biz_session.get('remark', ''))
                if contact.get('avatar_data_url'):
                    biz_session['avatar_data_url'] = contact.get('avatar_data_url', '')
                if contact.get('avatar_md5'):
                    biz_session['avatar_md5'] = contact.get('avatar_md5', '')
                if not biz_session.get('avatar_data_url') and contact.get('small_head_url'):
                    biz_session['small_head_url'] = contact.get('small_head_url', '')
            if not biz_session.get('display_name'):
                biz_session['display_name'] = (
                    biz_session.get('nick_name')
                    or biz_session.get('remark')
                    or biz_session.get('username')
                    or '未知'
                )

        for post in result.get('sns_posts', []):
            contact = contact_map.get(post.get('username'))
            if contact:
                post['nick_name'] = contact.get('nick_name', '')
                post['remark'] = contact.get('remark', '')
                if contact.get('avatar_data_url'):
                    post['avatar_data_url'] = contact.get('avatar_data_url', '')
                if not post.get('avatar_data_url') and contact.get('small_head_url'):
                    post['small_head_url'] = contact.get('small_head_url', '')

        for message in result.get('sns_messages', []):
            contact = contact_map.get(message.get('from_username'))
            if contact:
                message['display_name'] = contact.get('nick_name') or contact.get('remark') or message.get('from_nickname', '') or message.get('from_username', '') or '未知'
                if contact.get('avatar_data_url'):
                    message['avatar_data_url'] = contact.get('avatar_data_url', '')
                if not message.get('avatar_data_url') and contact.get('small_head_url'):
                    message['small_head_url'] = contact.get('small_head_url', '')
            elif not message.get('display_name'):
                message['display_name'] = message.get('from_nickname', '') or message.get('from_username', '') or '未知'

        for request in result.get('friend_requests', []):
            contact = contact_map.get(request.get('username'))
            if contact:
                request['nick_name'] = contact.get('nick_name', request.get('nick_name', ''))
                request['remark'] = contact.get('remark', request.get('remark', ''))
                if contact.get('avatar_data_url'):
                    request['avatar_data_url'] = contact.get('avatar_data_url', '')
                if not request.get('avatar_data_url') and contact.get('small_head_url'):
                    request['small_head_url'] = contact.get('small_head_url', '')
            greeting = request.get('content') or ''
            if greeting.startswith('我是') and not request.get('request_name'):
                request['request_name'] = greeting[2:].strip()
            if not request.get('display_name'):
                request['display_name'] = (
                    request.get('request_name')
                    or request.get('nick_name')
                    or request.get('remark')
                    or request.get('username')
                    or '未知'
                )
            if not request.get('greeting'):
                request['greeting'] = greeting
            if not request.get('source_text'):
                scene = int(request.get('scene') or 0)
                scene_map = {
                    3: '来自微信号搜索',
                    14: '来自群聊',
                    17: '来自名片分享',
                    30: '来自扫一扫',
                }
                request['source_text'] = scene_map.get(scene, f'场景 {scene}' if scene else '来源未知')
            if not request.get('status_text'):
                request['status_text'] = '等待验证'
            if not request.get('display_name'):
                request['display_name'] = (
                    request.get('nick_name')
                    or request.get('remark')
                    or request.get('username')
                    or '未知'
                )

        result['biz_sessions'].sort(key=lambda item: int(item.get('last_timestamp') or 0), reverse=True)
        result['friend_requests'].sort(key=lambda item: int(item.get('timestamp') or 0), reverse=True)
        result['sns_posts'].sort(key=lambda item: int(item.get('create_time') or 0), reverse=True)
        result['sns_messages'].sort(key=lambda item: int(item.get('create_time') or 0), reverse=True)

    def merge_parsed_db_into_result(self, result: Dict[str, Any], parsed: Dict[str, Any]) -> Dict[str, Any]:
        tables = parsed.get('tables', {})
        result.setdefault('contacts', [])
        result.setdefault('sessions', [])
        result.setdefault('biz_sessions', [])
        result.setdefault('friend_requests', [])
        result.setdefault('sns_posts', [])
        result.setdefault('sns_messages', [])
        result.setdefault('messages_summary', {})

        if 'contact' in tables:
            self._merge_records_by_key(result['contacts'], tables['contact'], 'username')
        if 'SessionTable' in tables:
            self._merge_records_by_key(result['sessions'], tables['SessionTable'], 'username')
        if 'biz_sessions' in tables:
            self._merge_records_by_key(result['biz_sessions'], tables['biz_sessions'], 'username')
        if 'FMessageTable' in tables:
            self._merge_records_by_key(result['friend_requests'], tables['FMessageTable'], 'request_key')
        if 'SnsTimeLine' in tables:
            self._merge_records_by_key(result['sns_posts'], tables['SnsTimeLine'], 'tid')
        if 'SnsMessage_tmp3' in tables:
            self._merge_records_by_key(result['sns_messages'], tables['SnsMessage_tmp3'], 'local_id')
        if 'head_image' in tables:
            self._apply_avatar_entries(result, tables['head_image'])
            result['_cached_avatars'] = tables['head_image']

        for table_name, table_data in tables.items():
            if table_name.startswith('Msg_'):
                result['messages_summary'][table_name] = table_data

        if 'sns_partial_recovered_python' in parsed.get('warnings', []):
            result['sns_notice'] = '朋友圈库部分损坏，当前结果为 Python sqlite3 可读到的部分记录。'
        elif 'sns_malformed_unreadable' in parsed.get('warnings', []) and not result.get('sns_notice'):
            result['sns_notice'] = '朋友圈库部分损坏，当前未能读取到可显示记录。'

        self._enrich_result_entities(result)
        return result

    @staticmethod
    def _safe_sqlite_preview_value(value: Any) -> str:
        if value is None:
            return ''
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
        return str(value)

    @classmethod
    def _extract_message_preview_from_row(cls, row: Dict[str, Any]) -> str:
        for key in ['msgContent', 'message_content', 'content', 'summary', 'content_', 'remark_']:
            if key in row and row[key] not in (None, ''):
                return cls._safe_sqlite_preview_value(row[key])
        return ''

    def parse_decrypted_db(self, db_path: str, db_name: str) -> Dict:
        import sqlite3

        result = {'db_name': db_name, 'tables': {}, 'warnings': []}

        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            if 'contact' in db_name.lower():
                try:
                    cursor.execute("PRAGMA table_info(contact)")
                    contact_columns = {row[1] for row in cursor.fetchall()}
                    username_col = 'username' if 'username' in contact_columns else 'userName'
                    nick_col = 'nick_name' if 'nick_name' in contact_columns else 'nickName'
                    remark_col = 'remark' if 'remark' in contact_columns else 'dbContactRemark'
                    has_head_url = 'big_head_url' in contact_columns or 'small_head_url' in contact_columns

                    select_cols = [username_col, nick_col, remark_col, 'alias']
                    if 'big_head_url' in contact_columns:
                        select_cols.append('big_head_url')
                    else:
                        select_cols.append(None)
                    if 'small_head_url' in contact_columns:
                        select_cols.append('small_head_url')
                    else:
                        select_cols.append(None)
                    actual_cols = [c for c in select_cols if c]

                    cursor.execute(
                        f"SELECT {', '.join(actual_cols)} FROM contact"
                    )
                    contacts = []
                    for row in cursor.fetchall():
                        record = {
                            'username': row[0] or '',
                            'nick_name': row[1] or '',
                            'remark': row[2] or '',
                            'alias': row[3] or '',
                        }
                        col_idx = 4
                        if 'big_head_url' in actual_cols:
                            record['big_head_url'] = row[col_idx] or ''
                            col_idx += 1
                        if 'small_head_url' in actual_cols:
                            record['small_head_url'] = row[col_idx] or ''
                            col_idx += 1
                        contacts.append(record)
                    result['tables']['contact'] = contacts
                except Exception as e:
                    logger.debug(f"解析 contact 表失败: {e}")

            elif 'session' in db_name.lower():
                try:
                    cursor.execute("PRAGMA table_info(SessionTable)")
                    session_columns = {row[1] for row in cursor.fetchall()}
                    username_col = 'username' if 'username' in session_columns else 'userName'
                    summary_col = 'summary' if 'summary' in session_columns else 'content'
                    timestamp_col = 'last_timestamp' if 'last_timestamp' in session_columns else 'timestamp'

                    cursor.execute(
                        f"SELECT {username_col}, {summary_col}, {timestamp_col} FROM SessionTable"
                    )
                    sessions = []
                    for row in cursor.fetchall():
                        sessions.append({
                            'username': row[0] or '',
                            'summary': row[1] or '',
                            'last_timestamp': row[2] or 0,
                        })
                    result['tables']['SessionTable'] = sessions
                except Exception as e:
                    logger.debug(f"解析 SessionTable 失败: {e}")

            elif 'biz_message' in db_name.lower():
                try:
                    import hashlib

                    biz_sessions = []
                    if 'Name2Id' in tables:
                        cursor.execute("SELECT user_name, is_session FROM Name2Id")
                        name_rows = cursor.fetchall()
                    else:
                        name_rows = []

                    for row in name_rows:
                        username = row[0] or ''
                        is_session = row[1]
                        if not username or is_session == 0:
                            continue

                        table_name = f"Msg_{hashlib.md5(username.encode('utf-8')).hexdigest()}"
                        if table_name not in tables:
                            continue

                        message_count = 0
                        last_timestamp = 0
                        summary = ''
                        try:
                            cursor.execute(f"PRAGMA table_info([{table_name}])")
                            columns = [info[1] for info in cursor.fetchall()]
                            time_column = 'create_time' if 'create_time' in columns else ('CreateTime' if 'CreateTime' in columns else ('sort_seq' if 'sort_seq' in columns else None))
                            order_by = f"[{time_column}] DESC" if time_column else 'rowid DESC'

                            cursor.execute(f"SELECT COUNT(*) FROM [{table_name}]")
                            message_count = int(cursor.fetchone()[0] or 0)
                            cursor.execute(f"SELECT * FROM [{table_name}] ORDER BY {order_by} LIMIT 1")
                            latest = cursor.fetchone()
                            if latest:
                                latest_row = dict(zip(columns, latest))
                                summary = self._extract_message_preview_from_row(latest_row)
                                if time_column and latest_row.get(time_column):
                                    last_timestamp = int(latest_row.get(time_column) or 0)
                                    if last_timestamp > 1000000000000:
                                        last_timestamp = int(last_timestamp / 1000)
                        except Exception as e:
                            logger.debug(f"解析 biz_message 会话 {table_name} 失败: {e}")

                        if summary.startswith('<BLOB '):
                            summary = ''

                        biz_sessions.append({
                            'username': username,
                            'summary': summary or (f'共 {message_count} 条消息' if message_count else ''),
                            'last_timestamp': last_timestamp,
                            'message_count': message_count,
                            'table_name': table_name,
                        })

                    result['tables']['biz_sessions'] = biz_sessions
                except Exception as e:
                    logger.debug(f"解析 biz_message 数据库失败: {e}")

            elif 'message' in db_name.lower() or db_name.lower().startswith('msg_'):
                msg_tables = [t for t in tables if t.startswith('Msg_')]

                for table_name in msg_tables:
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM [{table_name}]")
                        count = cursor.fetchone()[0]
                        result['tables'][table_name] = {
                            'count': count,
                        }
                    except Exception as e:
                        logger.debug(f"统计 {table_name} 失败: {e}")

            elif 'general' in db_name.lower():
                try:
                    cursor.execute(
                        "SELECT user_name_, type_, timestamp_, content_, remark_ "
                        "FROM FMessageTable ORDER BY timestamp_ DESC LIMIT 200"
                    )
                    friend_requests = []
                    for row in cursor.fetchall():
                        username = row[0] or ''
                        timestamp = int(row[2] or 0)
                        content = row[3] or ''
                        remark = row[4] or ''
                        type_value = int(row[1] or 0)
                        friend_requests.append({
                            'request_key': f'{username}:{timestamp}:{content}',
                            'username': username,
                            'type': type_value,
                            'timestamp': timestamp,
                            'content': content,
                            'remark': remark,
                            'scene': int(row[5] or 0),
                        })
                    result['tables']['FMessageTable'] = friend_requests
                except Exception as e:
                    logger.debug(f"解析 FMessageTable 失败: {e}")

            elif 'head_image' in db_name.lower():
                try:
                    cursor.execute("SELECT username, md5, image_buffer, update_time FROM head_image")
                    avatars = []
                    for row in cursor.fetchall():
                        avatar_blob = row[2]
                        if not avatar_blob:
                            continue
                        avatars.append({
                            'username': row[0] or '',
                            'md5': row[1] or '',
                            'avatar_data_url': self._blob_to_data_url(avatar_blob),
                            'update_time': row[3] or 0,
                        })
                    result['tables']['head_image'] = avatars
                except Exception as e:
                    logger.debug(f"解析 head_image 表失败: {e}")

            elif 'sns' in db_name.lower():
                try:
                    cursor.execute("SELECT COUNT(*) FROM SnsTimeLine")
                    timeline_count = int(cursor.fetchone()[0] or 0)
                    sns_posts = self._parse_sns_timeline_with_offsets(conn, min(timeline_count, 100))
                    if sns_posts:
                        result['tables']['SnsTimeLine'] = sns_posts
                        if len(sns_posts) < timeline_count:
                            result['warnings'].append('sns_partial_recovered_python')
                    elif timeline_count > 0:
                        result['warnings'].append('sns_malformed_unreadable')
                except Exception as e:
                    logger.debug(f"解析 SnsTimeLine 表失败: {e}")
                    result['warnings'].append('sns_malformed_unreadable')

                try:
                    cursor.execute(
                        "SELECT local_id, create_time, type, feed_id, from_username, from_nickname, "
                        "to_username, to_nickname, content FROM SnsMessage_tmp3 "
                        "ORDER BY create_time DESC, local_id DESC LIMIT 100"
                    )
                    sns_messages = []
                    for row in cursor.fetchall():
                        parsed = self._parse_sns_message_row(row)
                        if parsed:
                            sns_messages.append(parsed)
                    result['tables']['SnsMessage_tmp3'] = sns_messages
                except Exception as e:
                    logger.debug(f"解析 SnsMessage_tmp3 表失败: {e}")

            conn.close()
        except Exception as e:
            logger.error(f"解析数据库失败 {db_name}: {e}")

        return result

    @staticmethod
    def _guess_image_mime(blob: bytes) -> str:
        if not blob:
            return 'application/octet-stream'
        if blob.startswith(b'\xff\xd8\xff'):
            return 'image/jpeg'
        if blob.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'image/png'
        if blob.startswith((b'GIF87a', b'GIF89a')):
            return 'image/gif'
        if blob.startswith(b'BM'):
            return 'image/bmp'
        if blob.startswith(b'RIFF') and blob[8:12] == b'WEBP':
            return 'image/webp'
        return 'application/octet-stream'

    @classmethod
    def _blob_to_data_url(cls, blob: bytes) -> str:
        if blob is None:
            return ''
        if isinstance(blob, memoryview):
            blob = blob.tobytes()
        elif isinstance(blob, bytearray):
            blob = bytes(blob)
        if not isinstance(blob, (bytes, bytearray)) or not blob:
            return ''
        mime_type = cls._guess_image_mime(blob)
        encoded = base64.b64encode(blob).decode('ascii')
        return f'data:{mime_type};base64,{encoded}'

    @staticmethod
    def _extract_xml_tag_value(text: str, tag_name: str) -> str:
        if not text:
            return ''
        pattern = rf'<{tag_name}(?:\s+[^>]*)?>(.*?)</{tag_name}>'
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if not match:
            return ''
        return html.unescape(match.group(1).strip())

    @classmethod
    def _parse_sns_timeline_row(cls, row) -> Dict[str, Any]:
        raw_content = row[2] or ''
        pack_info = row[3] or ''
        create_time = cls._extract_xml_tag_value(raw_content, 'createTime')
        content_desc = cls._extract_xml_tag_value(raw_content, 'contentDesc')
        nickname = cls._extract_xml_tag_value(raw_content, 'nickname')
        content_type = cls._extract_xml_tag_value(raw_content, 'type')
        thumb_url = cls._extract_xml_tag_value(raw_content, 'thumb')
        media_url = cls._extract_xml_tag_value(raw_content, 'url')
        media_count = cls._extract_xml_tag_value(pack_info, 'mediaCount')
        username = row[1] or ''
        try:
            create_time_value = int(create_time) if create_time else 0
        except Exception:
            create_time_value = 0

        preview = content_desc
        if not preview:
            if '<mediaList>' in raw_content:
                type_map = {
                    '1': '[文字朋友圈]',
                    '2': '[图片朋友圈]',
                    '3': '[语音朋友圈]',
                    '4': '[视频朋友圈]',
                    '7': '[媒体朋友圈]',
                }
                preview = type_map.get(content_type, '[媒体朋友圈]')
            else:
                collapsed = re.sub(r'<[^>]+>', ' ', raw_content)
                collapsed = re.sub(r'\s+', ' ', html.unescape(collapsed)).strip()
                preview = collapsed[:200]

        return {
            'tid': row[0],
            'username': username,
            'nickname': nickname or '',
            'content': preview or '',
            'create_time': create_time_value,
            'media_count': media_count or (str(raw_content.count('<media>')) if '<media>' in raw_content else ''),
            'thumb_url': thumb_url or '',
            'media_url': media_url or '',
            'content_type': content_type or '',
            'raw_content': raw_content[:2000] if raw_content else '',
        }

    @staticmethod
    def _parse_sns_message_row(row) -> Dict[str, Any]:
        message_type = int(row[2] or 0)
        if message_type == 1:
            type_text = '点赞'
        elif message_type == 2:
            type_text = '评论'
        else:
            type_text = f'类型 {message_type}'

        return {
            'local_id': row[0],
            'create_time': int(row[1] or 0),
            'type': message_type,
            'type_text': type_text,
            'feed_id': row[3],
            'from_username': row[4] or '',
            'from_nickname': row[5] or '',
            'to_username': row[6] or '',
            'to_nickname': row[7] or '',
            'content': row[8] or '',
        }

    @staticmethod
    def _parse_sns_timeline_with_offsets(conn, limit: int = 20) -> List[Dict[str, Any]]:
        posts: List[Dict[str, Any]] = []
        seen_tids = set()
        for offset in range(limit):
            try:
                cur = conn.cursor()
                cur.execute(
                    f"SELECT tid, user_name, content, pack_info_buf FROM SnsTimeLine LIMIT 1 OFFSET {offset}"
                )
                row = cur.fetchone()
            except Exception as e:
                logger.debug(f"Python sqlite3 读取 SnsTimeLine offset={offset} 失败: {e}")
                continue
            if not row:
                continue
            post = WeChatAnalyzer._parse_sns_timeline_row(row)
            tid = post.get('tid')
            if tid in seen_tids:
                continue
            seen_tids.add(tid)
            posts.append(post)
        return posts


    @staticmethod
    def _prepare_work_dirs(cache_dir: Path) -> Dict[str, Path]:
        work_dir = cache_dir / 'wechat_analysis'
        work_dir.mkdir(parents=True, exist_ok=True)
        decrypted_dir = work_dir / 'decrypted'
        decrypted_dir.mkdir(exist_ok=True)
        dump_dir = work_dir / 'dump'
        dump_dir.mkdir(exist_ok=True)
        extracted_dir = work_dir / 'extracted'
        extracted_dir.mkdir(exist_ok=True)
        return {
            'work_dir': work_dir,
            'decrypted_dir': decrypted_dir,
            'dump_dir': dump_dir,
            'extracted_dir': extracted_dir,
        }

    @staticmethod
    def _build_base_result(decrypted_dir: Path) -> Dict[str, Any]:
        return {
            'status': 'success',
            'analysis_stage': 'keys_only',
            'keys': [],
            'keys_count': 0,
            'dbs_decrypted': 0,
            'dbs_found': 0,
            'contacts': [],
            'sessions': [],
            'biz_sessions': [],
            'friend_requests': [],
            'messages_summary': {},
            'db_details': [],
            'db_candidates': [],
            'decrypted_dir': str(decrypted_dir),
        }

    @staticmethod
    def _populate_result_metadata(result: Dict[str, Any], wechat_dbs: List[Dict]) -> None:
        result['dbs_found'] = len(wechat_dbs or [])
        for d in wechat_dbs or []:
            fp = d.get('file_path', '')
            if 'wxid_' in fp and not result.get('wxid'):
                wxid_match = re.search(r'(wxid_[a-zA-Z0-9]+)', fp)
                if wxid_match:
                    result['wxid'] = wxid_match.group(1)
            idx = fp.lower().find('xwechat_files')
            if idx > 0 and not result.get('wechat_data_path'):
                result['wechat_data_path'] = fp[:idx + len('xwechat_files')]

    def analyze_keys(self, cache_dir: str, progress_cb: Callable = None, include_db_scan: bool = False) -> Dict:
        cache_dir = Path(cache_dir)
        dirs = self._prepare_work_dirs(cache_dir)
        result = self._build_base_result(dirs['decrypted_dir'])

        def _progress(pct, msg):
            if progress_cb:
                progress_cb(pct, msg)

        _progress(0, '正在查找微信进程...')
        wechat_procs = self.find_wechat_process(cache_dir)
        if not wechat_procs:
            result['status'] = 'no_process'
            result['message'] = '未在内存中找到微信进程（Weixin.exe / WeChat.exe）'
            return result

        result['pid'] = wechat_procs[0]['pid']
        result['processes'] = wechat_procs
        _progress(5, f'找到 {len(wechat_procs)} 个微信进程')

        pid = wechat_procs[0]['pid']
        _progress(5, f'正在 dump 进程 {pid} 的内存...')
        dump_path = self.dump_process_memory(pid, str(dirs['dump_dir']), _progress)
        if not dump_path:
            result['status'] = 'dump_failed'
            result['message'] = f'无法 dump 进程 {pid} 的内存'
            return result
        result['dump_path'] = dump_path
        _progress(40, '进程内存 dump 完成')

        _progress(40, '正在从内存中扫描加密密钥...')
        keys = self.scan_keys(dump_path, _progress)
        if not keys:
            result['status'] = 'no_keys'
            result['message'] = '未在进程内存中找到 SQLCipher 密钥'
            return result

        result['keys_count'] = len(keys)
        result['keys'] = [{
            'enc_key': k['enc_key'],
            'salt': k['salt'],
            'full_hex': k['full_hex'],
            'offset': k['offset'],
            'pragma_key': k['pragma_key'],
        } for k in keys]
        _progress(55, f'找到 {len(keys)} 组候选密钥')

        wechat_dbs = []
        if include_db_scan:
            _progress(55, '正在查找微信数据库文件...')
            wechat_dbs = self.find_wechat_dbs(cache_dir, _progress)
            if not wechat_dbs:
                result['status'] = 'no_dbs'
                result['message'] = '未在内存中找到微信数据库文件'
                return result

            result['db_candidates'] = copy.deepcopy(wechat_dbs)
            self._populate_result_metadata(result, wechat_dbs)
            _progress(65, f'找到 {len(wechat_dbs)} 个数据库文件')
        _progress(65, '密钥提取完成，等待用户选择是否解密数据库')
        return result

    def compare_from_keys(self, cache_dir: str, base_result: Dict[str, Any], progress_cb: Callable = None) -> Dict:
        cache_dir = Path(cache_dir)
        dirs = self._prepare_work_dirs(cache_dir)
        result = copy.deepcopy(base_result or {})
        result.setdefault('decrypted_dir', str(dirs['decrypted_dir']))
        result['analysis_stage'] = 'compared'
        result['db_details'] = []
        result['dbs_decrypted'] = 0

        def _progress(pct, msg):
            if progress_cb:
                progress_cb(pct, msg)

        keys = result.get('keys', [])
        if not keys:
            result['status'] = 'no_keys'
            result['message'] = '缓存中没有可用的微信密钥，请重新提取'
            return result

        _progress(55, '正在查找微信数据库文件...')
        wechat_dbs = self.find_wechat_dbs(cache_dir, _progress)
        if not wechat_dbs:
            result['status'] = 'no_dbs'
            result['message'] = '未在内存中找到微信数据库文件'
            return result

        result['db_candidates'] = copy.deepcopy(wechat_dbs)
        self._populate_result_metadata(result, wechat_dbs)
        _progress(65, f'找到 {len(wechat_dbs)} 个数据库文件')

        total_dbs = len(wechat_dbs)
        for i, db_info in enumerate(wechat_dbs):
            pct = 65 + int((i / max(total_dbs, 1)) * 20)
            _progress(pct, f'比对数据库 {i+1}/{total_dbs}: {db_info["file_name"]}')

            local_path = self.extract_db(db_info['offset'], str(dirs['extracted_dir']))
            if not local_path:
                db_info['status'] = 'EXTRACT_FAILED'
                continue

            db_info['local_path'] = local_path

        matched_dbs = self.validate_and_match(wechat_dbs, keys)
        result['db_candidates'] = copy.deepcopy(matched_dbs)
        result['db_details'] = [
            {
                'database': d.get('file_name', ''),
                'status': d.get('status', ''),
                'enc_key': d.get('enc_key', ''),
                'salt': d.get('salt', ''),
                'pragma_key': d.get('pragma_key', ''),
                'file_path': d.get('file_path', ''),
            }
            for d in matched_dbs
        ]
        result['dbs_matched'] = sum(1 for d in matched_dbs if d.get('status') == 'DECRYPTED')
        _progress(85, '数据库比对完成')
        return result

    def decrypt_from_keys(self, cache_dir: str, base_result: Dict[str, Any], progress_cb: Callable = None) -> Dict:
        cache_dir = Path(cache_dir)
        dirs = self._prepare_work_dirs(cache_dir)
        result = copy.deepcopy(base_result or {})
        result.setdefault('decrypted_dir', str(dirs['decrypted_dir']))
        result['contacts'] = []
        result['sessions'] = []
        result['biz_sessions'] = []
        result['friend_requests'] = []
        result['sns_posts'] = []
        result['sns_messages'] = []
        result['sns_notice'] = ''
        result['messages_summary'] = {}
        result['db_details'] = []
        result['dbs_decrypted'] = 0
        result['analysis_stage'] = 'decrypted'

        def _progress(pct, msg):
            if progress_cb:
                progress_cb(pct, msg)

        keys = result.get('keys', [])
        if not keys:
            result['status'] = 'no_keys'
            result['message'] = '缓存中没有可用的微信密钥，请重新提取'
            return result

        wechat_dbs = copy.deepcopy(result.get('db_candidates') or [])
        has_compared = any(d.get('status') for d in wechat_dbs)
        if not has_compared:
            result = self.compare_from_keys(cache_dir, result, progress_cb)
            if result.get('status') != 'success':
                return result
            wechat_dbs = copy.deepcopy(result.get('db_candidates') or [])

        if not wechat_dbs:
            result['status'] = 'no_dbs'
            result['message'] = '未在内存中找到微信数据库文件'
            return result

        _progress(85, '正在解密数据库...')
        matched_dbs = wechat_dbs

        decrypted_count = 0
        for db_info in matched_dbs:
            if db_info.get('status') != 'DECRYPTED':
                continue

            enc_key = db_info['enc_key']
            enc_key_32 = enc_key[:64]
            db_path = db_info['local_path']
            db_name = db_info['file_name']
            out_path = str(dirs['decrypted_dir'] / db_name)

            try:
                if self.decrypt_db(enc_key_32, db_path, out_path):
                    decrypted_count += 1
                    parsed = self.parse_decrypted_db(out_path, db_name)
                    self.merge_parsed_db_into_result(result, parsed)

                    db_info['decrypted_path'] = out_path
            except Exception as e:
                logger.error(f"解密数据库失败 {db_name}: {e}")
                db_info['status'] = 'DECRYPT_FAILED'

        result['dbs_decrypted'] = decrypted_count

        if result.get('_cached_avatars'):
            self._apply_avatar_entries(result, result.pop('_cached_avatars'))
            self._enrich_result_entities(result)
        result['db_details'] = [
            {
                'database': d.get('file_name', ''),
                'status': d.get('status', ''),
                'enc_key': d.get('enc_key', ''),
                'salt': d.get('salt', ''),
                'pragma_key': d.get('pragma_key', ''),
                'file_path': d.get('file_path', ''),
                'decrypted_path': d.get('decrypted_path', ''),
            }
            for d in matched_dbs
        ]

        _progress(95, '数据库解密完成')
        return result

    def analyze(self, cache_dir: str, progress_cb: Callable = None) -> Dict:
        keys_result = self.analyze_keys(cache_dir, progress_cb)
        if keys_result.get('status') != 'success':
            return keys_result
        return self.decrypt_from_keys(cache_dir, keys_result, progress_cb)
