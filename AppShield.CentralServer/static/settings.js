/**
 * AppShield Settings & Infrastructure Module
 * Handles: Tailscale Mesh Network Setup, 1-Click Proxmox Server Deployment,
 *          Node Fleet Configuration, Master Admin Password, and Standalone Client Setup.
 */

window.AppShieldSettings = {
  // --- Settings State ---
  tailscale: {
    installed: false,
    running: false,
    ip: '',
    authUrl: '',
    statusText: 'Checking...',
    isChecking: false,
    isInstalling: false,
    isLoggingIn: false
  },

  serverSetup: {
    proxmoxCommand: 'curl -fsSL https://raw.githubusercontent.com/gitsheikhgit/appsheild/main/install-on-proxmox-lxc.sh | bash',
    copiedCommand: false
  },

  showPskInSettings: false,
  showPskInAdd: false,
  showAddModal: false,
  newNode: { name: '', lan_ip: '', tailscale_ip: '', psk: '' },
  discoveredServices: [],

  // =================================================================
  // 1. TAILSCALE REMOTE MESH MANAGEMENT
  // =================================================================
  async checkTailscaleStatus() {
    this.tailscale.isChecking = true;
    try {
      const res = await fetch('/api/tailscale/status');
      const json = await res.json();
      if (json.success && json.data) {
        this.tailscale.installed = json.data.installed;
        this.tailscale.running = json.data.running;
        this.tailscale.ip = json.data.ip || '';
        this.tailscale.authUrl = json.data.auth_url || '';
        this.tailscale.statusText = json.data.running 
          ? `🟢 Active: ${json.data.ip}` 
          : (json.data.installed ? '🟡 Installed, Not Logged In' : '⚪ Not Installed');
      }
    } catch (e) {
      this.tailscale.statusText = '🔴 Status check failed';
    } finally {
      this.tailscale.isChecking = false;
    }
  },

  async installTailscaleOnServer() {
    if (!confirm('Run automated 1-click installation of Tailscale on this Central Server?')) return;
    this.tailscale.isInstalling = true;
    try {
      const res = await fetch('/api/tailscale/install', { method: 'POST' });
      const json = await res.json();
      if (json.success) {
        this.showToast('Tailscale installed successfully!', 'success');
        await this.checkTailscaleStatus();
      } else {
        this.showToast(json.message || 'Installation failed', 'error');
      }
    } catch (e) {
      this.showToast('Error executing Tailscale install script', 'error');
    } finally {
      this.tailscale.isInstalling = false;
    }
  },

  async loginTailscaleOnServer() {
    this.tailscale.isLoggingIn = true;
    try {
      const res = await fetch('/api/tailscale/login', { method: 'POST' });
      const json = await res.json();
      if (json.success && json.auth_url) {
        this.tailscale.authUrl = json.auth_url;
        // Try opening in new tab
        const win = window.open(json.auth_url, '_blank');
        if (!win || win.closed || typeof win.closed === 'undefined') {
          this.showToast('Popup blocked by browser. Click the "Open Tailscale Login" button below!', 'warning');
        } else {
          this.showToast('Opened Tailscale login in new tab. Sign in to authorize!', 'info');
        }
        this.startTailscaleAuthPolling();
      } else if (json.running || (json.success && json.tailscale_ip)) {
        this.showToast(`Tailscale already running at ${json.tailscale_ip || json.ip}!`, 'success');
        await this.checkTailscaleStatus();
      } else {
        this.showToast(json.message || 'Could not initiate login', 'error');
      }
    } catch (e) {
      this.showToast('Error requesting Tailscale login URL', 'error');
    } finally {
      this.tailscale.isLoggingIn = false;
    }
  },

  startTailscaleAuthPolling() {
    if (this._tsPollInterval) clearInterval(this._tsPollInterval);
    let attempts = 0;
    this._tsPollInterval = setInterval(async () => {
      attempts++;
      if (attempts > 30) {
        clearInterval(this._tsPollInterval);
        return;
      }
      await this.checkTailscaleStatus();
      if (this.tailscale.running) {
        clearInterval(this._tsPollInterval);
        this.showToast('🎉 Tailscale Connected! Remote IP: ' + this.tailscale.ip, 'success');
      }
    }, 3000);
  },

  async autoDetectNodeTailscale() {
    if (!this.currentNode) return;
    try {
      const res = await fetch(`/api/nodes/${this.currentNode.id}/tailscale-probe`);
      const json = await res.json();
      if (json.success && json.tailscale_ip) {
        this.currentNode.tailscale_ip = json.tailscale_ip;
        this.showToast(`Found Tailscale IP: ${json.tailscale_ip}! Click "Save Settings" to persist.`, 'success');
      } else {
        this.showToast('No Tailscale IP detected on child node yet. Make sure Tailscale is connected on their device.', 'info');
      }
    } catch (e) {
      this.showToast('Failed to probe Tailscale IP', 'error');
    }
  },

  // =================================================================
  // 2. FLEET NODE CONFIGURATION & SETTINGS
  // =================================================================
  async saveCurrentNodeSettings() {
    if (!this.currentNode) return;
    try {
      const res = await fetch(`/api/fleet/${this.currentNode.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: this.currentNode.name,
          lan_ip: this.currentNode.lan_ip,
          tailscale_ip: this.currentNode.tailscale_ip,
          psk: this.currentNode.psk
        })
      });
      const json = await res.json();
      if (json.success) {
        this.showToast('Node configuration updated successfully!', 'success');
        await this.loadFleet();
      } else {
        this.showToast(json.message || 'Failed to update node', 'error');
      }
    } catch (e) {
      this.showToast('Error saving node settings', 'error');
    }
  },

  async deleteCurrentNode() {
    if (!this.currentNode) return;
    if (!confirm(`Are you sure you want to remove ${this.currentNode.name} from Central Management?`)) return;
    try {
      const res = await fetch(`/api/fleet/${this.currentNode.id}`, { method: 'DELETE' });
      const json = await res.json();
      if (json.success) {
        this.showToast('Device removed from fleet', 'info');
        await this.loadFleet();
        if (this.fleet.length > 0) {
          this.selectedNodeId = this.fleet[0].id;
          this.onNodeChange();
        } else {
          this.currentNode = null;
        }
      }
    } catch (e) {
      this.showToast('Error removing device', 'error');
    }
  },

  generateNewPsk() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = '';
    for (let i = 0; i < 32; i++) {
      key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    this.newNode.psk = key;
    this.showToast('Generated secure 32-character PSK!', 'info');
  },

  // =================================================================
  // 3. SERVER SETUP & 1-CLICK PROXMOX DEPLOYMENT
  // =================================================================
  copyServerCommand() {
    navigator.clipboard.writeText(this.serverSetup.proxmoxCommand);
    this.serverSetup.copiedCommand = true;
    this.showToast('Proxmox 1-click install command copied to clipboard!', 'success');
    setTimeout(() => {
      this.serverSetup.copiedCommand = false;
    }, 3000);
  },

  copyCommand(text) {
    if (!text) return;
    navigator.clipboard.writeText(text);
    this.showToast('Copied to clipboard!', 'info');
  },

  // =================================================================
  // 4. MASTER ADMIN PASSWORD MANAGEMENT
  // =================================================================
  async submitPasswordChange() {
    this.auth.changePasswordError = '';
    if (!this.auth.currentPassword) {
      this.auth.changePasswordError = 'Please enter your current password.';
      return;
    }
    if (!this.auth.newPassword || this.auth.newPassword.length < 6) {
      this.auth.changePasswordError = 'New password must be at least 6 characters.';
      return;
    }
    if (this.auth.newPassword === 'changeme') {
      this.auth.changePasswordError = 'New password cannot be the default "changeme".';
      return;
    }
    if (this.auth.newPassword !== this.auth.confirmPassword) {
      this.auth.changePasswordError = 'New passwords do not match.';
      return;
    }

    this.auth.changePasswordLoading = true;
    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          current_password: this.auth.currentPassword,
          new_password: this.auth.newPassword
        })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        this.auth.mustChangePassword = false;
        this.auth.isDefaultSetup = false;
        this.auth.currentPassword = '';
        this.auth.newPassword = '';
        this.auth.confirmPassword = '';
        this.showToast('Master password successfully updated!', 'success');
      } else {
        this.auth.changePasswordError = data.detail || data.message || 'Failed to change password.';
      }
    } catch (e) {
      this.auth.changePasswordError = 'Network error while changing password.';
    } finally {
      this.auth.changePasswordLoading = false;
    }
  }
};
