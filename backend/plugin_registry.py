PLUGIN_MAP = {
    'pslist': 'windows.pslist.PsList',
    'pstree': 'windows.pstree.PsTree',
    'psscan': 'windows.psscan.PsScan',
    'dlllist': 'windows.dlllist.DllList',
    'handles': 'windows.handles.Handles',
    'netscan': 'windows.netscan.NetScan',
    'netstat': 'windows.netstat.NetStat',
    'cmdline': 'windows.cmdline.CmdLine',
    'filescan': 'windows.filescan.FileScan',
    'eventlog': 'windows.filescan.FileScan',
    'hivelist': 'windows.registry.hivelist.HiveList',
    'printkey': 'windows.registry.printkey.PrintKey',
    'certificates': 'windows.registry.certificates.Certificates',
    'malfind': 'windows.malware.malfind.Malfind',
    'getsids': 'windows.getsids.GetSIDs',
    'envars': 'windows.envars.Envars',
    'svcscan': 'windows.svcscan.SvcScan',
    'svcscan_reg': 'windows.registry.printkey.PrintKey',
    'hashdump': 'windows.hashdump.Hashdump',
    'lsadump': 'windows.lsadump.Lsadump',
    'cachedump': 'windows.cachedump.Cachedump',
    'pypykatz_internal': 'pypykatz_plugin.PypykatzPlugin',
    'pypykatz': 'pypykatz_plugin.PypykatzPlugin',  
    'cmdscan': 'windows.cmdscan.CmdScan',
    'consoles': 'windows.consoles.Consoles',
    'psxview': 'windows.malware.psxview.PsXView',
    'ldrmodules': 'windows.malware.ldrmodules.LdrModules',
    'hollowprocesses': 'windows.malware.hollowprocesses.HollowProcesses',
    'svcdiff': 'windows.malware.svcdiff.SvcDiff',
    'unhooked_system_calls': 'windows.malware.unhooked_system_calls.UnhookedSystemCalls',
    'processghosting': 'windows.malware.processghosting.ProcessGhosting',
    'malware_psxview': 'windows.malware.psxview.PsXView',
    'pebmasquerade': 'windows.malware.pebmasquerade.PebMasquerade',
    'callbacks': 'windows.callbacks.Callbacks',
    'timers': 'windows.timers.Timers',
    'verinfo': 'windows.verinfo.VerInfo',
    'skeleton_key_check': 'windows.malware.skeleton_key_check.Skeleton_Key_Check',
    'mutantscan': 'windows.mutantscan.MutantScan',
    'suspicious_threads': 'windows.malware.suspicious_threads.SuspiciousThreads',
    'imageinfo': 'windows.info.Info',
    'privileges': 'windows.privileges.Privs',
    'sessions': 'windows.sessions.Sessions',
    'threads': 'windows.threads.Threads',
    'vadinfo': 'windows.vadinfo.VadInfo',
    'userassist': 'windows.registry.userassist.UserAssist',
    'scheduled_tasks': 'windows.registry.scheduled_tasks.ScheduledTasks',
    'amcache': 'windows.registry.amcache.Amcache',
    'truecrypt': 'windows.truecrypt.Passphrase',
    'modscan': 'windows.modscan.ModScan',
    'ssdt': 'windows.ssdt.SSDT',
    'driverscan': 'windows.driverscan.DriverScan',
    'drivermodule': 'windows.malware.drivermodule.DriverModule',
    'driverirp': 'windows.driverirp.DriverIrp',
    'deskscan': 'windows.deskscan.DeskScan',
    'desktops': 'windows.desktops.Desktops',
    'devicetree': 'windows.devicetree.DeviceTree',
    'bigpools': 'windows.bigpools.BigPools',

    'linux_pslist': 'linux.pslist.PsList',
    'linux_pstree': 'linux.pstree.PsTree',
    'linux_psscan': 'linux.psscan.PsScan',
    'linux_psaux': 'linux.psaux.PsAux',
    'linux_netstat': 'linux.sockstat.Sockstat',  
    'linux_sockstat': 'linux.sockstat.Sockstat',  
    'linux_ip_addr': 'linux.ip.Addr',  
    'linux_ip_link': 'linux.ip.Link',  
    'linux_lsof': 'linux.lsof.Lsof',
    'linux_elfs': 'linux.elfs.Elfs',
    'linux_mountinfo': 'linux.mountinfo.MountInfo',
    'linux_pagecache_files': 'linux.pagecache.Files',  
    'linux_pagecache_inodepages': 'linux.pagecache.InodePages',  
    'linux_pagecache_recoverfs': 'linux.pagecache.RecoverFs',  
    'linux_bash': 'linux.bash.Bash',
    'linux_bash_history': 'linux.bash.Bash',  
    'linux_envars': 'linux.envars.Envars',
    'linux_passwd_hashes': 'linux.pagecache.Files',  
    'linux_malfind': 'linux.malfind.Malfind',
    'linux_vmayarascan': 'linux.vmayarascan.VmaYaraScan',
    'linux_lsmod': 'linux.lsmod.Lsmod',
    'linux_check_modules': 'linux.check_modules.Check_modules',
    'linux_capabilities': 'linux.capabilities.Capabilities',
    'linux_malware_malfind': 'linux.malware.malfind.Malfind',
    'linux_malware_check_afinfo': 'linux.malware.check_afinfo.Check_afinfo',
    'linux_malware_check_creds': 'linux.malware.check_creds.Check_creds',
    'linux_malware_check_idt': 'linux.malware.check_idt.Check_idt',
    'linux_malware_check_modules': 'linux.malware.check_modules.Check_modules',
    'linux_malware_check_syscall': 'linux.malware.check_syscall.Check_syscall',
    'linux_malware_hidden_modules': 'linux.malware.hidden_modules.Hidden_modules',
    'linux_malware_keyboard_notifiers': 'linux.malware.keyboard_notifiers.Keyboard_notifiers',
    'linux_malware_netfilter': 'linux.malware.netfilter.Netfilter',
    'linux_malware_tty_check': 'linux.malware.tty_check.Tty_Check',
    'linux_malware_modxview': 'linux.malware.modxview.Modxview',
    'linux_check_afinfo': 'linux.check_afinfo.Check_afinfo',
    'linux_check_creds': 'linux.check_creds.Check_creds',
    'linux_check_idt': 'linux.check_idt.Check_idt',
    'linux_check_syscall': 'linux.check_syscall.Check_syscall',
    'linux_keyboard_notifiers': 'linux.keyboard_notifiers.Keyboard_notifiers',
    'linux_tty_check': 'linux.tty_check.tty_check',
    'linux_iomem': 'linux.iomem.IOMem',
    'linux_kmsg': 'linux.kmsg.Kmsg',
    'linux_maps': 'linux.proc.Maps',

    'mac.pslist.PsList': 'mac.pslist.PsList',
    'mac_pslist': 'mac.pslist.PsList',
    'mac.pstree.PsTree': 'mac.pstree.PsTree',
    'mac_pstree': 'mac.pstree.PsTree',
    'mac.psaux.Psaux': 'mac.psaux.Psaux',
    'mac_psaux': 'mac.psaux.Psaux',
    'mac.netstat.Netstat': 'mac.netstat.Netstat',
    'mac_netstat': 'mac.netstat.Netstat',
    'mac.ifconfig.Ifconfig': 'mac.ifconfig.Ifconfig',
    'mac_ifconfig': 'mac.ifconfig.Ifconfig',
    'mac.socket_filters.Socket_filters': 'mac.socket_filters.Socket_filters',
    'mac_socket_filters': 'mac.socket_filters.Socket_filters',
    'mac.lsof.Lsof': 'mac.lsof.Lsof',
    'mac_lsof': 'mac.lsof.Lsof',
    'mac.list_files.List_Files': 'mac.list_files.List_Files',
    'mac_list_files': 'mac.list_files.List_Files',
    'mac.mount.Mount': 'mac.mount.Mount',
    'mac_mount': 'mac.mount.Mount',
    'mac.bash.Bash': 'mac.bash.Bash',
    'mac_bash': 'mac.bash.Bash',
    'mac.malfind.Malfind': 'mac.malfind.Malfind',
    'mac_malfind': 'mac.malfind.Malfind',
    'mac.lsmod.Lsmod': 'mac.lsmod.Lsmod',
    'mac_lsmod': 'mac.lsmod.Lsmod',
    'mac.check_syscall.Check_syscall': 'mac.check_syscall.Check_syscall',
    'mac_check_syscall': 'mac.check_syscall.Check_syscall',
    'mac.check_sysctl.Check_sysctl': 'mac.check_sysctl.Check_sysctl',
    'mac_check_sysctl': 'mac.check_sysctl.Check_sysctl',
    'mac.check_trap_table.Check_trap_table': 'mac.check_trap_table.Check_trap_table',
    'mac_check_trap_table': 'mac.check_trap_table.Check_trap_table',
    'mac.dmesg.Dmesg': 'mac.dmesg.Dmesg',
    'mac_dmesg': 'mac.dmesg.Dmesg',
    'mac.kevents.Kevents': 'mac.kevents.Kevents',
    'mac_kevents': 'mac.kevents.Kevents',
    'mac.timers.Timers': 'mac.timers.Timers',
    'mac_timers': 'mac.timers.Timers',
    'mac.kauth_listeners.Kauth_listeners': 'mac.kauth_listeners.Kauth_listeners',
    'mac_kauth_listeners': 'mac.kauth_listeners.Kauth_listeners',
    'mac.kauth_scopes.Kauth_scopes': 'mac.kauth_scopes.Kauth_scopes',
    'mac_kauth_scopes': 'mac.kauth_scopes.Kauth_scopes',
    'mac.trustedbsd.Trustedbsd': 'mac.trustedbsd.Trustedbsd',
    'mac_trustedbsd': 'mac.trustedbsd.Trustedbsd',
    'mac.proc_maps.Maps': 'mac.proc_maps.Maps',
    'mac_maps': 'mac.proc_maps.Maps',
    'mac.vfsevents.VFSevents': 'mac.vfsevents.VFSevents',
    'mac_vfsevents': 'mac.vfsevents.VFSevents',
}


def get_volatility_plugin_name(plugin_id: str) -> str:
    return PLUGIN_MAP.get(str(plugin_id or "").strip(), "")


def normalize_plugin_id(plugin_id: str) -> str:
    original = str(plugin_id or '').strip()
    lowered = original.lower()
    if not lowered:
        return original

    if lowered.startswith('windows.'):
        parts = lowered.split('.')
        if len(parts) < 2:
            return original
        namespace = parts[1]
        module = parts[2] if namespace in ('registry', 'malware') and len(parts) > 2 else namespace
        return {
            'info': 'imageinfo',
            'privs': 'privileges',
        }.get(module, module)

    if lowered.startswith('linux.'):
        parts = lowered.split('.')
        if len(parts) < 2:
            return original
        namespace = parts[1]
        module = parts[2] if namespace in ('malware', 'pagecache') and len(parts) > 2 else namespace
        if namespace == 'malware':
            return f'linux_malware_{module}'
        if namespace == 'proc':
            return 'linux_maps'
        if namespace == 'pagecache':
            return {
                'files': 'linux_pagecache_files',
                'inodepages': 'linux_pagecache_inodepages',
                'recoverfs': 'linux_pagecache_recoverfs',
            }.get(module, f'linux_{module}')
        return f'linux_{namespace}'

    if lowered.startswith('mac.'):
        parts = lowered.split('.')
        if len(parts) < 2:
            return original
        return 'mac_maps' if parts[1] == 'proc_maps' else f'mac_{parts[1]}'

    return original


def resolve_plugin(plugin_id: str):
    canonical_id = normalize_plugin_id(plugin_id)
    return canonical_id, get_volatility_plugin_name(canonical_id)
