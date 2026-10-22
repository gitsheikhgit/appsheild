/**
 * AppShield Parental Features Module
 * Handles: Active Applications, Child User Accounts & Path Jail,
 *          Rules & Curfew Schedules, Installed Apps, Audit Logs, and Family DNS Shield.
 */

window.AppShieldFeatures = {
  // --- Data State for Features ---
  processes: [],
  selectedUserFilter: 'ALL',
  processSearch: '',
  
  users: [],
  showCreateUserModal: false,
  newUser: { username: '', password: '' },

  rules: [],
  showRuleModal: false,
  newRule: {
    ruleType: 'AllowedWindow',
    targetProcess: '',
    targetPath: '',
    scheduleStart: '12:00',
    scheduleEnd: '20:00',
    isEnabled: true
  },
  scheduleSelectedApps: [],
  ruleCategoryFilter: 'all',
  ruleAppSearch: '',

  installedApps: [],
  installedAppFilter: '',
  isLoadingApps: false,

  logs: [],
  logFilter: 'ALL',

  dnsSettings: {
    preset: 'cloudflare_public',
    primary_dns: '1.1.1.1',
    secondary_dns: '1.0.0.1',
    primary_ipv6: '2606:4700:4700::1111',
    secondary_ipv6: '2606:4700:4700::1001',
    is_enabled: true,
    apply_to_all: false
  },
  dnsPresets: [
    {
      id: 'cloudflare_public',
      name: 'Cloudflare Public (Default)',
      tag: 'Default (Fastest)',
      description: 'Ultra-fast, privacy-first public DNS resolver by Cloudflare. Default global resolver.',
      primary: '1.1.1.1',
      secondary: '1.0.0.1',
      primary_ipv6: '2606:4700:4700::1111',
      secondary_ipv6: '2606:4700:4700::1001',
      website: 'https://1.1.1.1',
      icon: '⚡'
    },
    {
      id: 'cloudflare_family',
      name: 'Cloudflare (Family)',
      tag: 'Adult + Malware',
      description: '1.1.1.1 for Families automatically blocks adult domains, pornography, and malware threats.',
      primary: '1.1.1.3',
      secondary: '1.0.0.3',
      primary_ipv6: '2606:4700:4700::1113',
      secondary_ipv6: '2606:4700:4700::1003',
      website: 'https://1.1.1.1/family/',
      icon: '🛡️'
    },
    {
      id: 'adguard_family',
      name: 'AdGuard (Family Protection)',
      tag: 'Adult + Ads + SafeSearch',
      description: 'Blocks adult websites, enforces SafeSearch on Google/Bing/YouTube, and stops tracking.',
      primary: '94.140.14.15',
      secondary: '94.140.15.16',
      primary_ipv6: '2a10:50c0::bad1:ff',
      secondary_ipv6: '2a10:50c0::bad2:ff',
      website: 'https://adguard-dns.io',
      icon: '🚫'
    },
    {
      id: 'cleanbrowsing',
      name: 'CleanBrowsing (Family Filter)',
      tag: 'Strict Kid Safe',
      description: 'Strict family filtering blocking adult content, malicious domains, and mixed content.',
      primary: '185.228.168.168',
      secondary: '185.228.169.168',
      primary_ipv6: '2a0d:2a00:1::',
      secondary_ipv6: '2a0d:2a00:2::',
      website: 'https://cleanbrowsing.org',
      icon: '👶'
    },
    {
      id: 'quad9',
      name: 'Quad9 (Malware & Phishing)',
      tag: 'Cyber Defense',
      description: 'Enterprise-grade threat intelligence that blocks malicious domains and ransomware.',
      primary: '9.9.9.9',
      secondary: '149.112.112.112',
      primary_ipv6: '2620:fe::fe',
      secondary_ipv6: '2620:fe::9',
      website: 'https://quad9.net',
      icon: '🔒'
    },
    {
      id: 'custom',
      name: 'Custom DNS (Manual)',
      tag: 'Custom',
      description: 'Specify your own custom primary and secondary IPv4/IPv6 DNS resolver addresses.',
      primary: '',
      secondary: '',
      primary_ipv6: '',
      secondary_ipv6: '',
      website: '',
      icon: '⚙️'
    }
  ],

  // =================================================================
  // 1. ACTIVE PROCESSES & APPLICATION CONTROL
  // =================================================================
  async loadProcesses() {
    if (!this.currentNode) return;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/processes`);
      const json = await res.json();
      if (json.success) {
        this.processes = json.data || [];
      }
    } catch (e) {
      console.error('Error loading processes:', e);
    }
  },

  async forceCloseProcess(pid, processName) {
    if (!this.currentNode) return;
    if (!confirm(`Force quit ${processName} (PID ${pid}) on ${this.currentNode.name}?`)) return;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/kill_process`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
      });
      const json = await res.json();
      if (json.success) {
        this.showToast(`Terminated ${processName}`, 'success');
        this.processes = this.processes.filter(p => p.pid !== pid);
      }
    } catch (e) {
      this.showToast('Failed to kill process', 'error');
    }
  },

  openBlockModalForProcess(proc) {
    this.scheduleSelectedApps = [proc.processName];
    this.newRule.targetProcess = proc.processName;
    this.newRule.ruleType = 'AlwaysBlock';
    this.showRuleModal = true;
  },

  async grantOverride(procName, minutes = 60) {
    if (!this.currentNode) return;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/override`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ process_name: procName, minutes })
      });
      const json = await res.json();
      if (json.success) {
        this.showToast(`Granted ${minutes}m override for ${procName}`, 'success');
      }
    } catch (e) {
      this.showToast('Failed to grant override', 'error');
    }
  },

  async lockDevice() {
    if (!this.currentNode) return;
    if (!confirm(`Instantly lock screen on ${this.currentNode.name}?`)) return;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/lock`, { method: 'POST' });
      const json = await res.json();
      if (json.success) {
        this.showToast('Screen locked on target device', 'success');
      }
    } catch (e) {
      this.showToast('Failed to lock screen', 'error');
    }
  },

  // =================================================================
  // 2. CHILD USER ACCOUNTS & PATH JAIL
  // =================================================================
  async loadUsers() {
    if (!this.currentNode) return;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/users`);
      const json = await res.json();
      if (json.success) {
        this.users = json.data || [];
      }
    } catch (e) {
      console.error('Error loading users:', e);
    }
  },

  async toggleManageUser(user) {
    if (!this.currentNode) return;
    const newManaged = !user.isManaged;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/users/manage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sid: user.sid,
          username: user.username,
          isManaged: newManaged,
          blockUserWritableDirectories: user.blockUserWritableDirectories ?? true
        })
      });
      const json = await res.json();
      if (json.success) {
        user.isManaged = newManaged;
        this.showToast(`${user.username} is now ${newManaged ? 'Managed (Protected)' : 'Unmanaged'}`, 'success');
      }
    } catch (e) {
      this.showToast('Error updating child management policy', 'error');
    }
  },

  async toggleBlockDirs(user) {
    if (!this.currentNode) return;
    const newBlock = !user.blockUserWritableDirectories;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/users/manage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sid: user.sid,
          username: user.username,
          isManaged: user.isManaged,
          blockUserWritableDirectories: newBlock
        })
      });
      const json = await res.json();
      if (json.success) {
        user.blockUserWritableDirectories = newBlock;
        this.showToast(`Path Jail for ${user.username} set to ${newBlock ? 'Enforced' : 'Disabled'}`, 'success');
      }
    } catch (e) {
      this.showToast('Error updating Path Jail policy', 'error');
    }
  },

  async openWindowsAccountSettings() {
    if (!this.currentNode) return;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/system/open-account-settings`, { method: 'POST' });
      const json = await res.json();
      if (json.success) {
        this.showToast('Account Settings opened on target machine', 'info');
      }
    } catch (e) {
      this.showToast('Failed to open Account Settings', 'error');
    }
  },

  async createStandardChildAccount() {
    if (!this.currentNode) return;
    if (!this.newUser.username || !this.newUser.password) {
      this.showToast('Username and password are required', 'error');
      return;
    }
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/command`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'create_child_account',
          payload: { username: this.newUser.username, password: this.newUser.password }
        })
      });
      const json = await res.json();
      if (json.success) {
        this.showToast(`Standard child account ${this.newUser.username} created!`, 'success');
        this.showCreateUserModal = false;
        this.newUser = { username: '', password: '' };
        setTimeout(() => this.loadUsers(), 2000);
      }
    } catch (e) {
      this.showToast('Failed to create account', 'error');
    }
  },

  // =================================================================
  // 3. RULES & CURFEW SCHEDULES
  // =================================================================
  async loadRules() {
    if (!this.currentNode) return;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/rules`);
      const json = await res.json();
      if (json.success) {
        this.rules = json.data || [];
      }
    } catch (e) {
      console.error('Error loading rules:', e);
    }
  },

  async deleteRule(ruleId) {
    if (!this.currentNode) return;
    if (!confirm('Remove this schedule rule?')) return;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/rules/${ruleId}`, { method: 'DELETE' });
      const json = await res.json();
      if (json.success) {
        this.showToast('Rule removed', 'info');
        this.rules = this.rules.filter(r => r.id !== ruleId);
      }
    } catch (e) {
      this.showToast('Error deleting rule', 'error');
    }
  },

  setTimePreset(start, end) {
    this.newRule.scheduleStart = start;
    this.newRule.scheduleEnd = end;
  },

  toggleScheduleApp(app) {
    const idx = this.scheduleSelectedApps.indexOf(app);
    if (idx >= 0) {
      this.scheduleSelectedApps.splice(idx, 1);
    } else {
      this.scheduleSelectedApps.push(app);
    }
  },

  isScheduleAppSelected(app) {
    return this.scheduleSelectedApps.includes(app);
  },

  clearScheduleAppSelection() {
    this.scheduleSelectedApps = [];
  },

  selectAllCategory(cat) {
    const games = ['Roblox', 'RobloxPlayerBeta', 'steam', 'Minecraft', 'FortniteClient-Win64-Shipping', 'EpicGamesLauncher', 'LeagueClient'];
    const chat = ['Discord', 'Telegram', 'WhatsApp', 'Messenger', 'Skype'];
    const browsers = ['chrome', 'msedge', 'firefox', 'brave', 'Safari'];

    let targetList = [];
    if (cat === 'games') targetList = games;
    else if (cat === 'chat') targetList = chat;
    else if (cat === 'browsers') targetList = browsers;

    for (const a of targetList) {
      if (!this.scheduleSelectedApps.includes(a)) {
        this.scheduleSelectedApps.push(a);
      }
    }
  },

  selectAllVisibleApps() {
    const allProcs = this.processes.map(p => p.processName);
    const allInstalled = this.installedApps.map(a => a.name);
    const combined = Array.from(new Set([...allProcs, ...allInstalled])).filter(Boolean);
    for (const a of combined) {
      if (!this.scheduleSelectedApps.includes(a)) {
        this.scheduleSelectedApps.push(a);
      }
    }
  },

  async saveSchedule() {
    if (!this.currentNode) return;
    if (this.scheduleSelectedApps.length === 0 && !this.newRule.targetProcess) {
      this.showToast('Please select at least one application to schedule', 'error');
      return;
    }

    const appsToSave = this.scheduleSelectedApps.length > 0 
      ? this.scheduleSelectedApps 
      : [this.newRule.targetProcess.trim()];

    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/rules/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          apps: appsToSave,
          rule_type: this.newRule.ruleType,
          schedule_start: this.newRule.scheduleStart,
          schedule_end: this.newRule.scheduleEnd,
          is_enabled: true
        })
      });
      const json = await res.json();
      if (json.success) {
        this.showToast(`Applied schedule to ${json.created_count} application(s)!`, 'success');
        this.showRuleModal = false;
        this.scheduleSelectedApps = [];
        this.newRule.targetProcess = '';
        await this.loadRules();
      }
    } catch (e) {
      this.showToast('Error saving schedule rules', 'error');
    }
  },

  // =================================================================
  // 4. INSTALLED APPLICATIONS
  // =================================================================
  async loadInstalledApps() {
    if (!this.currentNode) return;
    this.isLoadingApps = true;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/installed_apps`);
      const json = await res.json();
      if (json.success) {
        this.installedApps = json.data || [];
      }
    } catch (e) {
      console.error('Error loading installed apps:', e);
    } finally {
      this.isLoadingApps = false;
    }
  },

  // =================================================================
  // 5. AUDIT & INTERCEPT LOGS
  // =================================================================
  async loadLogs() {
    if (!this.currentNode) return;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/logs`);
      const json = await res.json();
      if (json.success) {
        this.logs = json.data || [];
      }
    } catch (e) {
      console.error('Error loading logs:', e);
    }
  },

  // =================================================================
  // 6. FAMILY WEB & DNS SHIELD
  // =================================================================
  async loadDnsSettings() {
    if (!this.currentNode) return;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/dns`);
      const json = await res.json();
      if (json.success && json.data) {
        this.dnsSettings = {
          preset: json.data.preset || 'cloudflare_public',
          primary_dns: json.data.primary_dns || '1.1.1.1',
          secondary_dns: json.data.secondary_dns || '1.0.0.1',
          primary_ipv6: json.data.primary_ipv6 || '',
          secondary_ipv6: json.data.secondary_ipv6 || '',
          is_enabled: json.data.is_enabled === 1 || json.data.is_enabled === true,
          apply_to_all: json.data.apply_to_all === 1 || json.data.apply_to_all === true
        };
      }
    } catch (e) {
      console.error('Error loading DNS settings:', e);
    }
  },

  selectDnsPreset(presetId) {
    const p = this.dnsPresets.find(x => x.id === presetId);
    if (!p) return;
    this.dnsSettings.preset = p.id;
    if (p.id !== 'custom') {
      this.dnsSettings.primary_dns = p.primary;
      this.dnsSettings.secondary_dns = p.secondary;
      this.dnsSettings.primary_ipv6 = p.primary_ipv6 || '';
      this.dnsSettings.secondary_ipv6 = p.secondary_ipv6 || '';
    }
  },

  async saveDnsSettings() {
    if (!this.currentNode) return;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/dns`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(this.dnsSettings)
      });
      const json = await res.json();
      if (json.success) {
        this.showToast(json.message || 'DNS Shield settings saved & active!', 'success');
      }
    } catch (e) {
      this.showToast('Error applying DNS settings', 'error');
    }
  },

  async toggleFleetDns(val) {
    this.dnsSettings.apply_to_all = val;
    try {
      await fetch('/api/settings/fleet-dns-toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apply_to_all: val })
      });
    } catch (e) {
      console.error('Error toggling fleet DNS:', e);
    }
  }
};
