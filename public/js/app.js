/**
 * CloudDrop - Main Application
 */

import { WebRTCManager } from './webrtc.js';
import { cryptoManager } from './crypto.js';
import * as ui from './ui.js';

class CloudDrop {
  constructor() {
    this.peerId = null;
    this.peers = new Map();
    this.ws = null;
    this.webrtc = null;
    this.selectedPeer = null;

    // Try to get saved name from localStorage, otherwise generate new one
    const savedName = localStorage.getItem('clouddrop_device_name');
    this.deviceName = savedName || ui.generateDisplayName();
    if (!savedName) {
      localStorage.setItem('clouddrop_device_name', this.deviceName);
    }

    this.deviceType = ui.detectDeviceType();
    this.roomCode = null;
    this.browserInfo = ui.getDetailedDeviceInfo();
    this.messageHistory = new Map(); // peerId -> messages array
    this.currentChatPeer = null; // Currently viewing chat history
    this.unreadMessages = new Map(); // peerId -> unread count
    this.pendingFileRequest = null; // Current pending file request waiting for user decision
    this.currentTransfer = null; // Current active transfer { peerId, fileId, fileName, direction }

    // Trusted devices - auto-accept files from these devices
    this.trustedDevices = this.loadTrustedDevices();

    // Room password state
    this.roomPassword = null; // Room password (plaintext, only in memory)
    this.roomPasswordHash = null; // Password hash for server verification
    this.isSecureRoom = false; // Whether current room is password-protected
  }

  /**
   * Load trusted devices from localStorage
   * Stores device fingerprint (name + deviceType + browserInfo hash)
   */
  loadTrustedDevices() {
    try {
      const saved = localStorage.getItem('clouddrop_trusted_devices');
      return saved ? new Map(JSON.parse(saved)) : new Map();
    } catch (e) {
      console.warn('Failed to load trusted devices:', e);
      return new Map();
    }
  }

  /**
   * Save trusted devices to localStorage
   */
  saveTrustedDevices() {
    try {
      localStorage.setItem('clouddrop_trusted_devices',
        JSON.stringify(Array.from(this.trustedDevices.entries())));
    } catch (e) {
      console.warn('Failed to save trusted devices:', e);
    }
  }

  /**
   * Generate a fingerprint for a device (for trust identification)
   * Uses name + deviceType + browserInfo to create a stable identifier
   */
  getDeviceFingerprint(peer) {
    const str = `${peer.name}|${peer.deviceType}|${peer.browserInfo || ''}`;
    // Simple hash for fingerprint
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(16);
  }

  /**
   * Check if a device is trusted
   */
  isDeviceTrusted(peer) {
    const fingerprint = this.getDeviceFingerprint(peer);
    return this.trustedDevices.has(fingerprint);
  }

  /**
   * Trust a device (auto-accept files from it)
   */
  trustDevice(peer) {
    const fingerprint = this.getDeviceFingerprint(peer);
    this.trustedDevices.set(fingerprint, {
      name: peer.name,
      deviceType: peer.deviceType,
      browserInfo: peer.browserInfo,
      trustedAt: Date.now()
    });
    this.saveTrustedDevices();
    this.updateTrustedBadge(peer.id, true);
    ui.showToast(`已信任设备: ${peer.name}`, 'success');
  }

  /**
   * Untrust a device
   */
  untrustDevice(peer) {
    const fingerprint = this.getDeviceFingerprint(peer);
    this.trustedDevices.delete(fingerprint);
    this.saveTrustedDevices();
    this.updateTrustedBadge(peer.id, false);
  }

  /**
   * Update trusted badge on peer card
   */
  updateTrustedBadge(peerId, trusted) {
    const card = document.querySelector(`[data-peer-id="${peerId}"]`);
    if (!card) return;

    const existingBadge = card.querySelector('.peer-trusted-badge');

    if (trusted && !existingBadge) {
      const badge = document.createElement('div');
      badge.className = 'peer-trusted-badge';
      badge.title = '点击取消信任';
      badge.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>`;

      // Click to untrust
      badge.addEventListener('click', async (e) => {
        e.stopPropagation();
        const peer = this.peers.get(peerId);
        if (!peer) return;

        const confirmed = await ui.showConfirmDialog({
          title: '取消信任设备',
          message: `确定要取消信任「<strong>${ui.escapeHtml(peer.name)}</strong>」吗？<br><br><span style="color: var(--text-muted)">取消后，该设备发送文件时需要您手动确认。</span>`,
          confirmText: '取消信任',
          cancelText: '保留信任',
          type: 'warning'
        });

        if (confirmed) {
          this.untrustDevice(peer);
          ui.showToast(`已取消信任: ${peer.name}`, 'info');
        }
      });

      card.appendChild(badge);
    } else if (!trusted && existingBadge) {
      existingBadge.remove();
    }
  }

  /**
   * Get list of all trusted devices
   */
  getTrustedDevicesList() {
    return Array.from(this.trustedDevices.entries()).map(([fingerprint, info]) => ({
      fingerprint,
      ...info
    }));
  }

  /**
   * Remove a trusted device by fingerprint
   */
  removeTrustedDevice(fingerprint) {
    const info = this.trustedDevices.get(fingerprint);
    this.trustedDevices.delete(fingerprint);
    this.saveTrustedDevices();

    // Update any matching peer cards
    for (const [peerId, peer] of this.peers.entries()) {
      if (this.getDeviceFingerprint(peer) === fingerprint) {
        this.updateTrustedBadge(peerId, false);
      }
    }

    return info;
  }

  /**
   * Create a secure room with password
   * @param {string} roomCode - Room code
   * @param {string} password - Room password (min 6 characters)
   */
  async createSecureRoom(roomCode, password) {
    // Validate password
    if (!password || password.length < 6) {
      ui.showToast('密码至少需要6位字符', 'error');
      return false;
    }

    // Validate room code
    if (!roomCode || !/^[a-zA-Z0-9]{4,16}$/.test(roomCode)) {
      ui.showToast('房间号格式无效 (4-16位字母数字)', 'error');
      return false;
    }

    try {
      // Generate password hash for server
      const passwordHash = await cryptoManager.hashPasswordForServer(password, roomCode);

      // Set room password on server
      const response = await fetch(`/api/room/set-password?room=${roomCode}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passwordHash })
      });

      const result = await response.json();

      if (!result.success) {
        ui.showToast(`创建失败: ${result.error}`, 'error');
        return false;
      }

      // Set room password for client-side encryption
      await cryptoManager.setRoomPassword(password, roomCode);

      // Store password info locally
      this.roomPassword = password;
      this.roomPasswordHash = passwordHash;
      this.isSecureRoom = true;

      // Update security badge
      this.updateRoomSecurityBadge();

      console.log('[App] Secure room created:', roomCode);
      return true;
    } catch (error) {
      console.error('[App] Failed to create secure room:', error);
      ui.showToast('创建加密房间失败', 'error');
      return false;
    }
  }

  /**
   * Check if a room requires password
   * @param {string} roomCode - Room code
   * @returns {Promise<boolean>} - true if password required
   */
  async checkRoomPassword(roomCode) {
    try {
      const response = await fetch(`/api/room/check-password?room=${roomCode}`);
      const result = await response.json();
      return result.hasPassword || false;
    } catch (error) {
      console.error('[App] Failed to check room password:', error);
      return false;
    }
  }

  /**
   * Join a secure room with password
   * @param {string} roomCode - Room code
   * @param {string} password - Room password
   */
  async joinSecureRoom(roomCode, password) {
    if (!password) {
      ui.showToast('请输入房间密码', 'error');
      return false;
    }

    // Normalize roomCode to uppercase (must match creation)
    const normalizedRoomCode = roomCode.toUpperCase();

    try {
      // Generate password hash (using normalized room code)
      const passwordHash = await cryptoManager.hashPasswordForServer(password, normalizedRoomCode);

      // Set room password for client-side encryption
      await cryptoManager.setRoomPassword(password, normalizedRoomCode);

      // Store password info
      this.roomPassword = password;
      this.roomPasswordHash = passwordHash;
      this.isSecureRoom = true;

      // Update security badge
      this.updateRoomSecurityBadge();

      console.log('[App] Joining secure room:', normalizedRoomCode);
      return true;
    } catch (error) {
      console.error('[App] Failed to prepare for secure room:', error);
      ui.showToast('加入加密房间失败', 'error');
      return false;
    }
  }

  /**
   * Clear room password (when leaving secure room)
   */
  clearRoomPassword() {
    this.roomPassword = null;
    this.roomPasswordHash = null;
    this.isSecureRoom = false;
    cryptoManager.clearRoomPassword();
    this.updateRoomSecurityBadge();
    console.log('[App] Room password cleared');
  }

  async init() {
    await cryptoManager.generateKeyPair();
    // Check URL for room code - only use explicit room parameter
    // If no room param, let server assign room based on IP
    const params = new URLSearchParams(location.search);
    const roomParam = params.get('room');
    this.roomCode = roomParam ? roomParam.toUpperCase() : null; // Normalize to uppercase

    // If joining a specific room, check if it requires password
    if (this.roomCode) {
      const requiresPassword = await this.checkRoomPassword(this.roomCode);
      if (requiresPassword) {
        // Show password prompt before connecting
        ui.showJoinRoomModal(this.roomCode, true); // true = password required
        // Will connect after user enters password
        this.setupEventListeners(); // Setup listeners so modal works
        return;
      }
    }

    this.updateRoomDisplay();
    this.connectWebSocket();
    this.setupEventListeners();
    ui.setupModalCloseHandlers();
    ui.updateEmptyState();
    this.updateDeviceNameDisplay();
    this.setupKeyboardDetection();
    this.setupVisualViewport();
  }

  // Generate room code is only used for creating shareable room codes
  generateRoomCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
    return code;
  }

  updateRoomDisplay() {
    const el = document.getElementById('roomCode');
    if (el) {
      if (this.roomCode) {
        el.textContent = this.roomCode;
      } else {
        // Auto-assigned room, show placeholder until we get the room ID from server
        el.textContent = '自动分配中...';
      }
    }
  }

  /**
   * Switch to a different room without page refresh
   * Used after creating a secure room to avoid re-entering password
   * @param {string} newRoomCode - The room code to switch to
   */
  switchRoom(newRoomCode) {
    // Close existing WebSocket connection
    if (this.ws) {
      this.ws.onclose = null; // Prevent auto-reconnect
      this.ws.close();
    }

    // Clear peers
    this.peers.clear();
    ui.clearPeersGrid(document.getElementById('peersGrid'));
    this.webrtc?.closeAll();

    // Update room code
    this.roomCode = newRoomCode;
    this.updateRoomDisplay();
    this.updateRoomSecurityBadge();

    // Update URL without refresh
    const url = new URL(location.href);
    url.searchParams.set('room', newRoomCode);
    history.pushState({}, '', url.toString());

    // Reconnect to new room
    this.connectWebSocket();
  }

  connectWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    // If roomCode is set, use it; otherwise let server assign based on IP
    let wsUrl = this.roomCode
      ? `${protocol}//${location.host}/ws?room=${this.roomCode}`
      : `${protocol}//${location.host}/ws`;

    // For WebSocket connections, we can't use custom headers directly,
    // but we can pass auth info via subprotocol or upgrade request modifications
    // Cloudflare Workers can access request headers during upgrade
    // We'll use a custom header through fetch API upgrade mechanism

    // Create connection with password hash if available
    if (this.isSecureRoom && this.roomPasswordHash) {
      // Note: Browser WebSocket doesn't support custom headers directly
      // But Cloudflare Workers can intercept the upgrade request
      // We pass the password hash through a query parameter (over WSS it's encrypted)
      wsUrl += `${this.roomCode ? '&' : '?'}passwordHash=${encodeURIComponent(this.roomPasswordHash)}`;
    }

    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      ui.updateConnectionStatus('connected', '已连接');

      // Clear existing peers on reconnect to avoid duplicates
      this.peers.clear();
      ui.clearPeersGrid(document.getElementById('peersGrid'));
      this.webrtc?.closeAll(); // Also close stale WebRTC connections

      this.ws.send(JSON.stringify({
        type: 'join',
        data: {
          name: this.deviceName,
          deviceType: this.deviceType,
          browserInfo: this.browserInfo
        }
      }));
    };

    this.ws.onmessage = (e) => {
      const message = JSON.parse(e.data);

      // Handle password error messages
      if (message.type === 'error') {
        if (message.error === 'PASSWORD_REQUIRED' || message.error === 'PASSWORD_INCORRECT') {
          ui.showToast(message.message || '密码错误', 'error');
          this.clearRoomPassword();
          // WebSocket will be closed by server, onclose handler will show join modal
          return;
        }
      }

      this.handleSignaling(message);
    };

    this.ws.onclose = (event) => {
      // Handle password authentication errors (custom close codes)
      if (event.code === 4001 || event.code === 4002) {
        // Password error - don't auto-reconnect
        ui.updateConnectionStatus('disconnected', '密码错误');
        ui.showToast(event.code === 4001 ? '此房间需要密码' : '房间密码错误', 'error');
        this.clearRoomPassword();
        // Show join room modal again with password input
        if (this.roomCode) {
          ui.showJoinRoomModal(this.roomCode);
        }
        return;
      }

      ui.updateConnectionStatus('disconnected', '已断开');
      setTimeout(() => this.connectWebSocket(), 3000);
    };

    this.ws.onerror = (event) => {
      console.error('[WebSocket] Error:', event);
      ui.updateConnectionStatus('disconnected', '已断开');
    };

    this.webrtc = new WebRTCManager({
      send: (msg) => this.ws.readyState === WebSocket.OPEN && this.ws.send(JSON.stringify(msg))
    });

    this.webrtc.onProgress = (p) => {
      const isRelayMode = this.webrtc.relayMode.get(p.peerId) || false;

      // Update modal title to show actual transfer (in case it was "waiting for confirmation")
      const modalTitle = document.getElementById('modalTitle');
      if (modalTitle && modalTitle.textContent === '等待确认') {
        modalTitle.textContent = '正在发送';
      }

      ui.updateTransferProgress({
        fileName: p.fileName,
        fileSize: p.fileSize,
        percent: p.percent,
        speed: p.speed,
        mode: isRelayMode ? 'relay' : 'p2p'
      });
    };

    this.webrtc.onFileReceived = (peerId, name, blob) => {
      ui.hideModal('transferModal');

      // Show download modal instead of auto-download (better mobile support)
      this.showFileDownloadModal(name, blob);
      this.currentTransfer = null;
    };

    // Note: onFileRequest is now handled via signaling (file-request message)
    // This callback is kept for legacy P2P direct messages
    this.webrtc.onFileRequest = (peerId, info) => {
      // For P2P data channel messages (file-start), if we haven't confirmed yet
      // This is for backward compatibility - normally requests go through signaling
      const transfer = this.webrtc.incomingTransfers.get(peerId);
      if (transfer && transfer.confirmed) {
        // Already confirmed via signaling, just update progress modal
        const isRelayMode = this.webrtc.relayMode.get(peerId) || false;
        ui.showReceivingModal(info.name, info.size, isRelayMode ? 'relay' : 'p2p');
      }
    };

    this.webrtc.onTextReceived = (peerId, text) => {
      this.saveMessage(peerId, { type: 'received', text, timestamp: Date.now() });

      // If chat panel is open for this peer, update UI immediately
      if (this.currentChatPeer && this.currentChatPeer.id === peerId) {
        this.renderChatHistory(peerId);
        // Play a subtle sound? (Optional)
        return;
      }

      // Update unread count
      const currentUnread = this.unreadMessages.get(peerId) || 0;
      this.unreadMessages.set(peerId, currentUnread + 1);
      this.updateUnreadBadge(peerId);

      // Show toast notification
      const peer = this.peers.get(peerId);
      ui.showToast(`${peer?.name || '未知设备'}: ${text.substring(0, 30)}${text.length > 30 ? '...' : ''}`, 'info');
    };

    // Transfer start callback (for tracking fileId)
    this.webrtc.onTransferStart = ({ peerId, fileId, fileName, direction }) => {
      this.currentTransfer = { peerId, fileId, fileName, direction };
    };

    // Transfer cancelled callback
    this.webrtc.onTransferCancelled = (peerId, fileId, reason) => {
      const peer = this.peers.get(peerId);
      ui.hideModal('transferModal');

      if (reason === 'user') {
        ui.showToast(`${peer?.name || '对方'} 取消了传输`, 'warning');
      } else {
        ui.showToast('传输已取消', 'info');
      }

      this.currentTransfer = null;
    };

    // Connection state change handler
    this.webrtc.onConnectionStateChange = ({ peerId, status, message }) => {
      const toastId = `connection-${peerId}`;

      switch (status) {
        case 'connecting':
          // Only show toast if message is provided (user-initiated action)
          // Otherwise just update the badge silently
          if (message) {
            ui.showPersistentToast(toastId, message, 'loading');
          }
          ui.updatePeerConnectionMode(peerId, 'connecting');
          break;
        case 'slow':
          if (message) {
            ui.updatePersistentToast(toastId, message, 'warning');
          }
          break;
        case 'relay':
          ui.hidePersistentToast(toastId);
          if (message) {
            ui.showToast(message, 'info');
          }
          ui.updatePeerConnectionMode(peerId, 'relay');
          break;
        case 'connected':
          ui.hidePersistentToast(toastId);
          ui.updatePeerConnectionMode(peerId, 'p2p');
          break;
      }
    };
  }

  handleSignaling(msg) {
    console.log('[Signaling] Received:', msg.type, msg);
    switch (msg.type) {
      case 'joined':
        this.peerId = msg.peerId;
        console.log('[Signaling] My peer ID:', this.peerId);
        // Set peer ID for Perfect Negotiation pattern
        this.webrtc.setMyPeerId(this.peerId);
        // Update room code from server if auto-assigned
        if (msg.roomCode) {
          this.roomCode = msg.roomCode;
          this.updateRoomDisplay();
          console.log('[Signaling] Room code:', this.roomCode);
        }
        msg.peers?.forEach(p => this.addPeer(p));

        // Show room info hint if no peers (help users understand they need to share room code)
        if (!msg.peers || msg.peers.length === 0) {
          // Check if this is an auto-assigned room (no explicit room in URL)
          const params = new URLSearchParams(location.search);
          const hasExplicitRoom = params.has('room');

          if (!hasExplicitRoom) {
            // Auto-assigned room - show a hint about sharing
            ui.showToast(`已加入房间 ${this.roomCode}，请分享房间号给其他设备`, 'info', 5000);
          }
        }
        break;
      case 'peer-joined':
        this.addPeer(msg.data);
        ui.showToast(`${msg.data.name} 已加入`, 'info');
        break;
      case 'peer-left':
        this.removePeer(msg.data.id);
        break;
      case 'offer':
        this.webrtc.handleOffer(msg.from, msg.data);
        break;
      case 'answer':
        this.webrtc.handleAnswer(msg.from, msg.data);
        break;
      case 'ice-candidate':
        this.webrtc.handleIceCandidate(msg.from, msg.data);
        break;
      case 'relay-data':
        this.webrtc.handleRelayData(msg.from, msg.data);
        break;
      case 'key-exchange':
        this.webrtc.handleKeyExchange(msg.from, msg.data);
        break;
      case 'name-changed':
        this.handleNameChanged(msg.from, msg.data.name);
        break;
      case 'file-request':
        this.handleFileRequest(msg.from, msg.data);
        break;
      case 'file-response':
        this.webrtc.handleFileResponse(msg.from, msg.data);
        break;
      case 'file-cancel':
        this.webrtc.handleFileCancel(msg.from, msg.data);
        break;
    }
  }

  /**
   * Handle incoming file request - show confirmation dialog or auto-accept if trusted
   */
  handleFileRequest(peerId, data) {
    const peer = this.peers.get(peerId);
    const isRelayMode = data.transferMode === 'relay';

    // Store pending request info
    this.pendingFileRequest = { peerId, fileId: data.fileId, data };

    // Check if this device is trusted - auto-accept if so
    if (peer && this.isDeviceTrusted(peer)) {
      console.log(`[App] Auto-accepting file from trusted device: ${peer.name}`);
      ui.showToast(`自动接收来自 ${peer.name} 的文件: ${data.name}`, 'info');
      this.acceptFileRequest();
      return;
    }

    // Update the receive modal with detailed info
    ui.updateReceiveModal({
      senderName: peer?.name || '未知设备',
      senderDeviceType: peer?.deviceType || 'desktop',
      senderBrowserInfo: peer?.browserInfo,
      fileName: data.name,
      fileSize: data.size,
      mode: isRelayMode ? 'relay' : 'p2p'
    });

    // Trigger notification (vibration)
    ui.triggerNotification('file');

    // Show the confirmation modal
    ui.showModal('receiveModal');
  }

  /**
   * Accept the pending file request
   */
  acceptFileRequest() {
    if (!this.pendingFileRequest) return;

    const { peerId, fileId, data } = this.pendingFileRequest;

    // Send acceptance
    this.webrtc.respondToFileRequest(peerId, fileId, true);

    // Save current transfer state for cancellation
    this.currentTransfer = {
      peerId,
      fileId,
      fileName: data.name,
      direction: 'receive'
    };

    // Hide confirmation, show receiving progress
    ui.hideModal('receiveModal');
    const isRelayMode = data.transferMode === 'relay';
    ui.showReceivingModal(data.name, data.size, isRelayMode ? 'relay' : 'p2p');

    // Initialize transfer state for receiving
    this.webrtc.incomingTransfers.set(peerId, {
      fileId: fileId,
      name: data.name,
      size: data.size,
      totalChunks: data.totalChunks,
      chunks: [],
      received: 0,
      startTime: Date.now(),
      confirmed: true
    });

    this.pendingFileRequest = null;
  }

  /**
   * Decline the pending file request
   */
  declineFileRequest() {
    if (!this.pendingFileRequest) return;

    const { peerId, fileId } = this.pendingFileRequest;

    // Send decline
    this.webrtc.respondToFileRequest(peerId, fileId, false);

    ui.hideModal('receiveModal');
    ui.showToast('已拒绝文件接收', 'info');

    this.pendingFileRequest = null;
  }

  /**
   * Accept file and trust the sending device for future transfers
   */
  acceptAndTrustDevice() {
    if (!this.pendingFileRequest) return;

    const { peerId } = this.pendingFileRequest;
    const peer = this.peers.get(peerId);

    // Trust the device first
    if (peer) {
      this.trustDevice(peer);
    }

    // Then accept the file
    this.acceptFileRequest();
  }

  /**
   * Cancel the current active transfer
   */
  cancelCurrentTransfer() {
    if (!this.currentTransfer) {
      ui.hideModal('transferModal');
      return;
    }

    const { peerId, fileId, fileName, direction } = this.currentTransfer;

    // Cancel the transfer via WebRTC
    this.webrtc.cancelTransfer(fileId, peerId, 'user');

    // Hide modal and show feedback
    ui.hideModal('transferModal');

    if (direction === 'send') {
      ui.showToast(`已取消发送: ${fileName}`, 'info');
    } else {
      ui.showToast(`已取消接收: ${fileName}`, 'info');
    }

    this.currentTransfer = null;
  }

  addPeer(peer) {
    this.peers.set(peer.id, peer);
    ui.addPeerToGrid(peer, document.getElementById('peersGrid'), (p, e) => this.onPeerClick(p, e));

    // Check if this device is trusted and show badge
    if (this.isDeviceTrusted(peer)) {
      // Small delay to ensure DOM is ready
      setTimeout(() => this.updateTrustedBadge(peer.id, true), 50);
    }

    // Prewarm WebRTC connection for faster first transfer
    if (this.webrtc) {
      this.webrtc.prewarmConnection(peer.id);
    }
  }

  removePeer(peerId) {
    const peer = this.peers.get(peerId);
    if (peer) ui.showToast(`${peer.name} 已离开`, 'info');
    this.peers.delete(peerId);
    ui.removePeerFromGrid(peerId, document.getElementById('peersGrid'));
    this.webrtc.closeConnection(peerId);
  }

  updateDeviceNameDisplay() {
    document.getElementById('deviceName').textContent = this.deviceName;
  }

  updateDeviceName(newName) {
    this.deviceName = newName;
    localStorage.setItem('clouddrop_device_name', newName);
    this.updateDeviceNameDisplay();

    // Broadcast name change to all peers
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'name-changed',
        data: { name: newName }
      }));
    }

    ui.showToast('设备名称已更新', 'success');
  }

  handleNameChanged(peerId, newName) {
    const peer = this.peers.get(peerId);
    if (peer) {
      const oldName = peer.name;
      peer.name = newName;

      // Update the peer card
      const card = document.querySelector(`[data-peer-id="${peerId}"]`);
      if (card) {
        const nameEl = card.querySelector('.peer-name');
        if (nameEl) nameEl.textContent = newName;
      }

      ui.showToast(`${oldName} 改名为 ${newName}`, 'info');
    }
  }

  onPeerClick(peer, e) {
    // If message button was clicked, open chat panel
    if (e && e.target.closest('[data-action="message"]')) {
      if (e.stopPropagation) e.stopPropagation();
      this.openChatPanel(peer);
      return;
    }

    // Default: select file
    this.selectedPeer = peer;
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    input.onchange = () => this.sendFiles(peer.id, Array.from(input.files));
    input.click();
  }

  async sendFiles(peerId, files) {
    const peer = this.peers.get(peerId);
    for (const file of files) {
      // Show waiting for confirmation
      this.showWaitingForConfirmation(peer?.name || '对方', file.name);

      try {
        // sendFile now handles the request/confirm flow internally
        // It will throw if declined, timeout, or cancelled
        // onTransferStart callback will set this.currentTransfer
        await this.webrtc.sendFile(peerId, file);

        ui.hideModal('transferModal');
        ui.showToast(`已发送: ${file.name}`, 'success');
      } catch (e) {
        ui.hideModal('transferModal');
        if (e.message.includes('拒绝')) {
          ui.showToast(`${peer?.name || '对方'} 拒绝了接收文件`, 'warning');
        } else if (e.message.includes('超时')) {
          ui.showToast('文件请求超时，对方未响应', 'warning');
        } else if (e.message.includes('取消')) {
          ui.showToast('传输已取消', 'info');
        } else {
          ui.showToast(`发送失败: ${e.message}`, 'error');
        }
      } finally {
        this.currentTransfer = null;
      }
    }
  }

  /**
   * Show modal indicating waiting for recipient to accept
   */
  showWaitingForConfirmation(peerName, fileName) {
    document.getElementById('modalTitle').textContent = '等待确认';
    document.getElementById('transferFileName').textContent = fileName;
    document.getElementById('transferFileSize').textContent = `等待 ${peerName} 确认接收...`;
    document.getElementById('transferProgress').style.width = '0%';
    document.getElementById('transferPercent').textContent = '';
    document.getElementById('transferSpeed').textContent = '';

    // Add waiting state classes for special styling
    document.querySelector('.transfer-info')?.classList.add('waiting');
    document.querySelector('.progress-container')?.classList.add('waiting');
    document.querySelector('.transfer-stats')?.classList.add('waiting');

    // Update mode indicator to show waiting (with icon)
    ui.updateTransferModeIndicator('waiting');

    ui.showModal('transferModal');
  }

  /**
   * Show file download modal (for mobile-friendly download)
   */
  showFileDownloadModal(fileName, blob) {
    // Store blob URL for cleanup
    if (this._pendingDownloadUrl) {
      URL.revokeObjectURL(this._pendingDownloadUrl);
    }
    this._pendingDownloadUrl = URL.createObjectURL(blob);
    this._pendingDownloadName = fileName;

    // Update modal content
    document.getElementById('downloadFileName').textContent = fileName;
    document.getElementById('downloadFileSize').textContent = ui.formatFileSize(blob.size);

    // Set download link
    const downloadBtn = document.getElementById('downloadFileBtn');
    downloadBtn.href = this._pendingDownloadUrl;
    downloadBtn.download = fileName;

    // Show modal
    ui.showModal('fileDownloadModal');

    // Trigger notification
    ui.triggerNotification('file');
  }

  /**
   * Clean up download modal resources
   */
  cleanupDownloadModal() {
    if (this._pendingDownloadUrl) {
      URL.revokeObjectURL(this._pendingDownloadUrl);
      this._pendingDownloadUrl = null;
    }
    this._pendingDownloadName = null;
    ui.hideModal('fileDownloadModal');
  }

  joinRoom(code) {
    if (!code || !/^[a-zA-Z0-9]{4,16}$/.test(code)) {
      ui.showToast('房间号格式无效 (4-16位字母数字)', 'error');
      return;
    }
    // Navigate to new room
    const url = new URL(location.href);
    url.searchParams.set('room', code.toUpperCase());
    location.href = url.toString();
  }

  /**
   * Calculate password strength (0-3)
   * 0 = weak, 1 = fair, 2 = good, 3 = strong
   */
  calculatePasswordStrength(password) {
    let strength = 0;

    if (password.length >= 6) strength++;
    if (password.length >= 10) strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[^a-zA-Z0-9]/.test(password)) strength++;

    // Normalize to 0-3 scale
    return Math.min(Math.floor(strength / 1.5), 3);
  }

  /**
   * Update room lock icon display
   */
  updateRoomSecurityBadge() {
    const lockIcon = document.getElementById('roomLockIcon');
    if (lockIcon) {
      if (this.isSecureRoom) {
        lockIcon.classList.add('locked');
        lockIcon.title = '加密房间 - 已启用密码保护';
      } else {
        lockIcon.classList.remove('locked');
        lockIcon.title = '点击创建加密房间';
      }
    }
  }

  saveMessage(peerId, message) {
    if (!this.messageHistory.has(peerId)) {
      this.messageHistory.set(peerId, []);
    }
    this.messageHistory.get(peerId).push(message);
  }

  getMessageHistory(peerId) {
    return this.messageHistory.get(peerId) || [];
  }

  async sendTextMessage(peerId, text) {
    if (!text.trim()) return;

    try {
      await this.webrtc.sendText(peerId, text);
      this.saveMessage(peerId, { type: 'sent', text, timestamp: Date.now() });
      return true;
    } catch (e) {
      ui.showToast(`发送失败: ${e.message}`, 'error');
      return false;
    }
  }

  openChatPanel(peer) {
    this.currentChatPeer = peer;
    document.getElementById('chatTitle').textContent = `与 ${peer.name} 的消息`;
    this.renderChatHistory(peer.id);
    document.getElementById('chatPanel').classList.add('active');
    document.getElementById('chatInput').focus();

    // Clear unread messages
    this.unreadMessages.set(peer.id, 0);
    this.updateUnreadBadge(peer.id);
  }

  closeChatPanel() {
    document.getElementById('chatPanel').classList.remove('active');
    this.currentChatPeer = null;
  }

  renderChatHistory(peerId) {
    const messages = this.getMessageHistory(peerId);
    const container = document.getElementById('chatMessages');
    container.innerHTML = '';

    if (messages.length === 0) {
      // Empty state
      const emptyEl = document.createElement('div');
      emptyEl.className = 'chat-empty-state';
      emptyEl.innerHTML = `
        <div class="chat-empty-icon">💬</div>
        <p class="chat-empty-text">还没有消息</p>
        <p class="chat-empty-hint">在下方输入框发送第一条消息吧</p>
      `;
      container.appendChild(emptyEl);
      return;
    }

    messages.forEach((msg, index) => {
      const msgEl = document.createElement('div');
      let statusClass = msg.type;
      if (msg.sending) statusClass += ' sending';
      if (msg.failed) statusClass += ' failed';
      msgEl.className = `chat-message ${statusClass}`;

      let statusText = this.formatTime(msg.timestamp);
      if (msg.sending) statusText = '发送中...';
      if (msg.failed) statusText = '发送失败 · 点击重试';

      msgEl.innerHTML = `
        <div class="chat-bubble-wrapper">
          <div class="chat-bubble">${ui.escapeHtml(msg.text)}</div>
          <button class="chat-copy-btn" title="复制消息">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2"/>
              <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
            </svg>
          </button>
        </div>
        <div class="chat-time">${statusText}</div>
      `;

      // Add copy button functionality
      const copyBtn = msgEl.querySelector('.chat-copy-btn');
      copyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.copyMessageText(msg.text, copyBtn);
      });

      // Add click event for retry on failed messages
      if (msg.failed) {
        msgEl.style.cursor = 'pointer';
        msgEl.addEventListener('click', () => this.retryMessage(peerId, index));
      }

      container.appendChild(msgEl);
    });

    // Scroll to bottom
    container.scrollTop = container.scrollHeight;
  }

  formatTime(timestamp) {
    const now = Date.now();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);

    if (minutes < 1) return '刚刚';
    if (minutes < 60) return `${minutes}分钟前`;

    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}小时前`;

    const date = new Date(timestamp);
    return `${date.getMonth() + 1}/${date.getDate()} ${date.getHours()}:${String(date.getMinutes()).padStart(2, '0')}`;
  }

  async copyMessageText(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
      // Show success feedback
      btn.classList.add('copied');
      const originalTitle = btn.title;
      btn.title = '已复制';
      setTimeout(() => {
        btn.classList.remove('copied');
        btn.title = originalTitle;
      }, 1500);
    } catch (e) {
      ui.showToast('复制失败', 'error');
    }
  }

  async retryMessage(peerId, messageIndex) {
    const messages = this.getMessageHistory(peerId);
    const msg = messages[messageIndex];

    if (!msg || !msg.failed) return;

    // Reset status to sending
    msg.failed = false;
    msg.sending = true;
    msg.timestamp = Date.now();
    this.renderChatHistory(peerId);

    try {
      await this.webrtc.sendText(peerId, msg.text);
      // Mark as sent
      msg.sending = false;
      this.renderChatHistory(peerId);
    } catch (e) {
      // Mark as failed again
      msg.sending = false;
      msg.failed = true;
      this.renderChatHistory(peerId);
      ui.showToast(`重试失败: ${e.message}`, 'error');
    }
  }

  updateUnreadBadge(peerId) {
    const count = this.unreadMessages.get(peerId) || 0;
    const card = document.querySelector(`[data-peer-id="${peerId}"]`);
    if (!card) return;

    const button = card.querySelector('[data-action="message"]');
    if (!button) return;

    // Remove existing badge
    const existingBadge = button.querySelector('.unread-badge');
    if (existingBadge) existingBadge.remove();

    // Add new badge if count > 0
    if (count > 0) {
      const badge = document.createElement('span');
      badge.className = 'unread-badge';
      badge.textContent = count > 99 ? '99+' : count;
      button.appendChild(badge);
      button.classList.add('has-unread');
    } else {
      button.classList.remove('has-unread');
    }
  }

  setupEventListeners() {
    const app = document.getElementById('app');
    let dragCounter = 0;

    app.addEventListener('dragenter', (e) => {
      e.preventDefault();
      dragCounter++;
      if (this.peers.size > 0) ui.showDropZone();
    });

    app.addEventListener('dragleave', (e) => {
      e.preventDefault();
      dragCounter--;
      if (dragCounter === 0) ui.hideDropZone();
    });

    app.addEventListener('dragover', (e) => e.preventDefault());

    app.addEventListener('drop', (e) => {
      e.preventDefault();
      dragCounter = 0;
      ui.hideDropZone();
      const files = Array.from(e.dataTransfer.files);
      if (files.length && this.peers.size === 1) {
        const [peerId] = this.peers.keys();
        this.sendFiles(peerId, files);
      } else if (files.length && this.peers.size > 1) {
        ui.showToast('请点击目标设备发送文件', 'warning');
      }
    });

    // Desktop share popover
    this.setupDesktopSharePopover();

    // Mobile bottom navigation
    this.setupMobileNavigation();

    // Empty state actions
    this.setupEmptyStateActions();

    // Edit device name
    document.getElementById('editDeviceName')?.addEventListener('click', () => {
      document.getElementById('nameInput').value = this.deviceName;
      ui.showModal('editNameModal');
      document.getElementById('nameInput').focus();
    });

    document.getElementById('editNameConfirm')?.addEventListener('click', () => {
      const newName = document.getElementById('nameInput').value.trim();
      if (newName && newName !== this.deviceName) {
        this.updateDeviceName(newName);
      }
      ui.hideModal('editNameModal');
    });

    document.getElementById('editNameCancel')?.addEventListener('click', () => {
      ui.hideModal('editNameModal');
    });

    document.getElementById('editNameModalClose')?.addEventListener('click', () => {
      ui.hideModal('editNameModal');
    });

    // Refresh room button - generate new room code
    document.getElementById('refreshRoomBtn')?.addEventListener('click', async () => {
      // Generate new room code
      const newRoomCode = this.generateRoomCode();

      // Clear room password since it's a new room
      this.clearRoomPassword();

      // Switch to new room
      this.switchRoom(newRoomCode);
      this.triggerHaptic('medium');
      ui.showToast(`已切换到新房间: ${newRoomCode}`, 'success');
    });

    // Join room button
    document.getElementById('joinRoomBtn')?.addEventListener('click', () => {
      document.getElementById('roomInput').value = '';
      ui.showModal('joinRoomModal');
    });

    // Join room modal
    document.getElementById('joinRoomModalClose')?.addEventListener('click', () => ui.hideModal('joinRoomModal'));
    document.getElementById('joinRoomCancel')?.addEventListener('click', () => ui.hideModal('joinRoomModal'));
    document.getElementById('joinRoomConfirm')?.addEventListener('click', async () => {
      const code = document.getElementById('roomInput').value.trim();
      const password = document.getElementById('joinRoomPassword').value;

      if (!code) {
        ui.showToast('请输入房间号', 'error');
        return;
      }

      // If password is provided, join secure room
      if (password) {
        const success = await this.joinSecureRoom(code, password);
        if (success) {
          ui.hideModal('joinRoomModal');
          // Use switchRoom to avoid page refresh (preserves password in memory)
          this.switchRoom(code.toUpperCase());
        }
      } else {
        // Check if room requires password
        const requiresPassword = await this.checkRoomPassword(code);
        if (requiresPassword) {
          // Show password input
          ui.showJoinRoomPasswordSection();
          ui.showToast('此房间需要密码', 'warning');
        } else {
          // Regular room join (no password needed, can use page refresh)
          this.joinRoom(code);
        }
      }
    });
    document.getElementById('roomInput')?.addEventListener('keydown', async (e) => {
      if (e.key === 'Enter') {
        const code = document.getElementById('roomInput').value.trim();
        const password = document.getElementById('joinRoomPassword').value;

        if (password) {
          const success = await this.joinSecureRoom(code, password);
          if (success) {
            ui.hideModal('joinRoomModal');
            // Use switchRoom to avoid page refresh (preserves password in memory)
            this.switchRoom(code.toUpperCase());
          }
        } else {
          const requiresPassword = await this.checkRoomPassword(code);
          if (requiresPassword) {
            ui.showJoinRoomPasswordSection();
            ui.showToast('此房间需要密码', 'warning');
          } else {
            this.joinRoom(code);
          }
        }
      }
    });

    // Password toggle for join room modal
    document.getElementById('joinPasswordToggle')?.addEventListener('click', () => {
      const passwordInput = document.getElementById('joinRoomPassword');
      const isPassword = passwordInput.type === 'password';
      passwordInput.type = isPassword ? 'text' : 'password';
    });

    // Room lock icon click - create secure room or show info
    document.getElementById('roomLockIcon')?.addEventListener('click', () => {
      if (this.isSecureRoom) {
        // Already in a secure room, show info toast
        ui.showToast('当前已在加密房间中', 'info');
        return;
      }
      // Generate a random room code for new secure room
      const randomCode = this.generateRoomCode();
      document.getElementById('secureRoomCode').value = randomCode;
      document.getElementById('secureRoomPassword').value = '';
      ui.hidePasswordStrength(); // Reset password strength indicator
      ui.showModal('createSecureRoomModal');
      document.getElementById('secureRoomPassword').focus();
    });

    // Create secure room modal
    document.getElementById('createSecureRoomClose')?.addEventListener('click', () => ui.hideModal('createSecureRoomModal'));
    document.getElementById('createSecureRoomCancel')?.addEventListener('click', () => ui.hideModal('createSecureRoomModal'));
    document.getElementById('createSecureRoomConfirm')?.addEventListener('click', async () => {
      const roomCode = document.getElementById('secureRoomCode').value.trim().toUpperCase();
      const password = document.getElementById('secureRoomPassword').value;

      if (!roomCode) {
        ui.showToast('请输入房间号', 'error');
        return;
      }

      if (!password || password.length < 6) {
        ui.showToast('密码至少需要6位字符', 'error');
        return;
      }

      const success = await this.createSecureRoom(roomCode, password);
      if (success) {
        ui.hideModal('createSecureRoomModal');
        ui.showToast('加密房间创建成功', 'success');
        // Switch to the new secure room without page refresh
        // This preserves the password in memory so creator doesn't need to re-enter
        this.switchRoom(roomCode);
      }
    });

    // Password toggle for create secure room modal
    document.getElementById('createPasswordToggle')?.addEventListener('click', () => {
      const passwordInput = document.getElementById('secureRoomPassword');
      const isPassword = passwordInput.type === 'password';
      passwordInput.type = isPassword ? 'text' : 'password';
    });

    // Password strength indicator
    document.getElementById('secureRoomPassword')?.addEventListener('input', (e) => {
      const password = e.target.value;
      if (password.length > 0) {
        const strength = this.calculatePasswordStrength(password);
        ui.showPasswordStrength(strength);
      } else {
        ui.hidePasswordStrength();
      }
    });

    // Modal close buttons
    document.getElementById('modalClose')?.addEventListener('click', () => {
      // If there's an active transfer, ask for confirmation
      if (this.currentTransfer) {
        this.cancelCurrentTransfer();
      } else {
        ui.hideModal('transferModal');
      }
    });

    // Cancel transfer button
    document.getElementById('cancelTransfer')?.addEventListener('click', () => {
      this.triggerHaptic('medium');
      this.cancelCurrentTransfer();
    });
    document.getElementById('receiveModalClose')?.addEventListener('click', () => {
      this.declineFileRequest();
    });
    document.getElementById('receiveDecline')?.addEventListener('click', () => {
      this.triggerHaptic('light');
      this.declineFileRequest();
    });
    document.getElementById('receiveAccept')?.addEventListener('click', () => {
      this.triggerHaptic('medium');
      this.acceptFileRequest();
    });
    document.getElementById('receiveAlwaysAccept')?.addEventListener('click', () => {
      this.triggerHaptic('medium');
      this.acceptAndTrustDevice();
    });

    // Text modal
    document.getElementById('textModalClose')?.addEventListener('click', () => ui.hideModal('textModal'));
    document.getElementById('textCancel')?.addEventListener('click', () => ui.hideModal('textModal'));
    document.getElementById('textSend')?.addEventListener('click', async () => {
      const text = document.getElementById('textInput').value.trim();
      if (text && this.selectedPeer) {
        const success = await this.sendTextMessage(this.selectedPeer.id, text);
        if (success) {
          document.getElementById('textInput').value = '';
          ui.hideModal('textModal');
          ui.showToast('消息已发送', 'success');
        }
      }
    });

    // Received text modal
    document.getElementById('receivedTextModalClose')?.addEventListener('click', () => ui.hideModal('receivedTextModal'));
    document.getElementById('closeReceivedText')?.addEventListener('click', () => ui.hideModal('receivedTextModal'));
    document.getElementById('copyText')?.addEventListener('click', () => {
      const text = document.getElementById('receivedText').textContent;
      navigator.clipboard.writeText(text);
      ui.showToast('已复制到剪贴板', 'success');
    });

    // File download modal
    document.getElementById('fileDownloadModalClose')?.addEventListener('click', () => this.cleanupDownloadModal());
    document.getElementById('downloadFileClose')?.addEventListener('click', () => this.cleanupDownloadModal());
    document.getElementById('downloadFileBtn')?.addEventListener('click', () => {
      // Show success toast after user clicks download
      ui.showToast(`已保存: ${this._pendingDownloadName}`, 'success');
      // Delay cleanup to allow download to start
      setTimeout(() => this.cleanupDownloadModal(), 500);
    });

    // Chat panel events
    document.getElementById('closeChatPanel')?.addEventListener('click', () => this.closeChatPanel());

    document.getElementById('sendChatMessage')?.addEventListener('click', async () => {
      if (!this.currentChatPeer) return;
      const input = document.getElementById('chatInput');
      const btn = document.getElementById('sendChatMessage');
      const text = input.value.trim();
      if (!text) return;

      // Optimistic UI: show message immediately with sending state
      const tempMessage = { type: 'sent', text, timestamp: Date.now(), sending: true };
      this.saveMessage(this.currentChatPeer.id, tempMessage);
      this.renderChatHistory(this.currentChatPeer.id);

      // Disable input and show loading state
      input.value = '';
      input.disabled = true;
      btn.disabled = true;
      btn.classList.add('sending');

      try {
        await this.webrtc.sendText(this.currentChatPeer.id, text);
        // Mark message as sent
        tempMessage.sending = false;
        this.renderChatHistory(this.currentChatPeer.id);
      } catch (e) {
        // Mark message as failed
        tempMessage.failed = true;
        tempMessage.sending = false;
        this.renderChatHistory(this.currentChatPeer.id);
        ui.showToast(`发送失败: ${e.message}`, 'error');
      } finally {
        // Re-enable input
        input.disabled = false;
        btn.disabled = false;
        btn.classList.remove('sending');
        input.focus();
      }
    });

    document.getElementById('chatInput')?.addEventListener('keydown', async (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        const btn = document.getElementById('sendChatMessage');
        if (btn) btn.click();
      }
    });
  }

  // Desktop share popover setup
  setupDesktopSharePopover() {
    const shareBtn = document.getElementById('shareRoomBtn');
    const roomCodeEl = document.getElementById('roomCode');
    const popover = document.getElementById('sharePopover');
    const closeBtn = document.getElementById('sharePopoverClose');
    const copyCodeBtn = document.getElementById('sharePopoverCopyCode');
    const copyLinkBtn = document.getElementById('sharePopoverCopyLink');

    if (!shareBtn || !popover) return;

    // Create overlay for click-outside-to-close
    let overlay = document.querySelector('.share-popover-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.className = 'share-popover-overlay';
      document.body.appendChild(overlay);
    }

    const showPopover = () => {
      // Update room code display
      document.getElementById('sharePopoverRoomCode').textContent = this.roomCode || '-';

      // Generate QR code
      const canvas = document.getElementById('shareQRCode');
      if (canvas && this.roomCode) {
        const url = new URL(location.href);
        url.searchParams.set('room', this.roomCode);
        ui.generateQRCode(canvas, url.toString(), { size: 160 });
      }

      popover.classList.add('active');
      overlay.classList.add('active');
    };

    const hidePopover = () => {
      popover.classList.remove('active');
      overlay.classList.remove('active');
    };

    // Toggle popover on share button click
    shareBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (popover.classList.contains('active')) {
        hidePopover();
      } else {
        showPopover();
      }
    });

    // Click room code to copy
    roomCodeEl?.addEventListener('click', (e) => {
      e.stopPropagation();
      if (this.roomCode) {
        navigator.clipboard.writeText(this.roomCode);
        ui.showToast('房间号已复制', 'success');
        this.triggerHaptic('light');
      }
    });

    // Close button
    closeBtn?.addEventListener('click', hidePopover);

    // Click outside to close
    overlay.addEventListener('click', hidePopover);

    // Copy room code
    copyCodeBtn?.addEventListener('click', () => {
      navigator.clipboard.writeText(this.roomCode);
      ui.showToast('房间号已复制', 'success');

      // Visual feedback
      copyCodeBtn.classList.add('copied');
      setTimeout(() => copyCodeBtn.classList.remove('copied'), 1000);
    });

    // Copy link
    copyLinkBtn?.addEventListener('click', () => {
      const url = new URL(location.href);
      url.searchParams.set('room', this.roomCode);
      navigator.clipboard.writeText(url.toString());
      ui.showToast('链接已复制', 'success');

      // Visual feedback
      copyLinkBtn.classList.add('copied');
      setTimeout(() => copyLinkBtn.classList.remove('copied'), 1000);
    });

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && popover.classList.contains('active')) {
        hidePopover();
      }
    });
  }

  // Mobile navigation setup
  setupMobileNavigation() {
    // Bottom nav buttons
    document.getElementById('navDevices')?.addEventListener('click', () => {
      this.triggerHaptic('light');
      // Scroll to peers grid
      document.getElementById('peersGrid')?.scrollIntoView({ behavior: 'smooth' });
    });

    document.getElementById('navRoom')?.addEventListener('click', () => {
      this.triggerHaptic('light');
      this.showMobileShareModal();
    });

    document.getElementById('navSend')?.addEventListener('click', () => {
      this.triggerHaptic('medium');
      this.showQuickActions();
    });

    document.getElementById('navShare')?.addEventListener('click', () => {
      this.triggerHaptic('light');
      this.showMobileShareModal();
    });

    document.getElementById('navSettings')?.addEventListener('click', () => {
      this.triggerHaptic('light');
      this.showMobileSettings();
    });

    // Quick actions panel
    document.getElementById('quickActionClose')?.addEventListener('click', () => {
      this.hideQuickActions();
    });

    document.getElementById('quickSendFile')?.addEventListener('click', () => {
      this.triggerHaptic('light');
      this.hideQuickActions();
      this.selectFileToSend();
    });

    document.getElementById('quickSendText')?.addEventListener('click', () => {
      this.triggerHaptic('light');
      this.hideQuickActions();
      this.showTextInputForSend();
    });

    // Mobile settings panel
    document.getElementById('mobileSettingsClose')?.addEventListener('click', () => {
      ui.hideModal('mobileSettingsModal');
    });

    document.getElementById('settingsEditName')?.addEventListener('click', () => {
      ui.hideModal('mobileSettingsModal');
      document.getElementById('nameInput').value = this.deviceName;
      ui.showModal('editNameModal');
    });

    document.getElementById('settingsCopyRoom')?.addEventListener('click', () => {
      navigator.clipboard.writeText(this.roomCode);
      this.triggerHaptic('light');
      ui.showToast('房间号已复制', 'success');
    });

    // Mobile share panel
    document.getElementById('mobileShareClose')?.addEventListener('click', () => {
      ui.hideModal('mobileShareModal');
    });

    document.getElementById('shareCopyLink')?.addEventListener('click', () => {
      const url = new URL(location.href);
      url.searchParams.set('room', this.roomCode);
      navigator.clipboard.writeText(url.toString());
      this.triggerHaptic('light');
      ui.showToast('链接已复制', 'success');
    });

    document.getElementById('shareNative')?.addEventListener('click', async () => {
      if (navigator.share) {
        try {
          const url = new URL(location.href);
          url.searchParams.set('room', this.roomCode);
          await navigator.share({
            title: 'CloudDrop - 加入房间',
            text: `加入房间 ${this.roomCode} 来互传文件`,
            url: url.toString()
          });
          this.triggerHaptic('medium');
        } catch (e) {
          if (e.name !== 'AbortError') {
            ui.showToast('分享失败', 'error');
          }
        }
      } else {
        ui.showToast('您的浏览器不支持分享功能', 'warning');
      }
    });

    // Close quick actions when clicking outside
    document.getElementById('mobileQuickActions')?.addEventListener('click', (e) => {
      if (e.target.id === 'mobileQuickActions') {
        this.hideQuickActions();
      }
    });
  }

  // Empty state actions setup
  setupEmptyStateActions() {
    document.getElementById('emptyShareRoom')?.addEventListener('click', () => {
      this.triggerHaptic('light');
      this.showMobileShareModal();
    });

    document.getElementById('emptyJoinRoom')?.addEventListener('click', () => {
      this.triggerHaptic('light');
      document.getElementById('roomInput').value = '';
      ui.showModal('joinRoomModal');
    });
  }

  // Show quick actions panel
  showQuickActions() {
    if (this.peers.size === 0) {
      ui.showToast('没有可用的设备', 'warning');
      return;
    }

    const panel = document.getElementById('mobileQuickActions');
    if (panel) {
      panel.classList.add('active');
    }
  }

  // Hide quick actions panel
  hideQuickActions() {
    const panel = document.getElementById('mobileQuickActions');
    if (panel) {
      panel.classList.remove('active');
    }
  }

  // Show mobile settings
  showMobileSettings() {
    document.getElementById('settingsDeviceName').textContent = this.deviceName;
    document.getElementById('settingsRoomCode').textContent = this.roomCode;

    const statusEl = document.getElementById('settingsStatus');
    const statusTextEl = document.getElementById('settingsStatusText');
    const mainStatusEl = document.getElementById('connectionStatus');

    if (statusEl && mainStatusEl) {
      statusEl.className = 'settings-value';
      const dotEl = statusEl.querySelector('.status-dot');
      if (dotEl) {
        dotEl.style.background = mainStatusEl.classList.contains('connected')
          ? 'var(--status-success)'
          : mainStatusEl.classList.contains('disconnected')
            ? 'var(--status-error)'
            : 'var(--status-warning)';
      }
    }

    if (statusTextEl) {
      statusTextEl.textContent = mainStatusEl?.classList.contains('connected')
        ? '已连接'
        : mainStatusEl?.classList.contains('disconnected')
          ? '已断开'
          : '连接中...';
    }

    // Render trusted devices list
    this.renderTrustedDevicesList();

    ui.showModal('mobileSettingsModal');
  }

  /**
   * Render trusted devices list in settings
   */
  renderTrustedDevicesList() {
    const container = document.getElementById('trustedDevicesList');
    if (!container) return;

    const devices = this.getTrustedDevicesList();

    if (devices.length === 0) {
      container.innerHTML = '<p class="trusted-empty">暂无信任的设备</p>';
      return;
    }

    const deviceTypeIcons = {
      desktop: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
      mobile: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="2" width="14" height="20" rx="2"/><path d="M12 18h.01"/></svg>',
      tablet: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="2" width="16" height="20" rx="2"/><path d="M12 18h.01"/></svg>'
    };

    container.innerHTML = devices.map(device => `
      <div class="trusted-device-item" data-fingerprint="${device.fingerprint}">
        <div class="trusted-device-info">
          <div class="trusted-device-icon">
            ${deviceTypeIcons[device.deviceType] || deviceTypeIcons.desktop}
          </div>
          <div class="trusted-device-details">
            <div class="trusted-device-name">${ui.escapeHtml(device.name)}</div>
            <div class="trusted-device-meta">${device.browserInfo || '未知浏览器'}</div>
          </div>
        </div>
        <button class="btn-untrust" title="取消信任" data-fingerprint="${device.fingerprint}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M18 6L6 18M6 6l12 12"/>
          </svg>
        </button>
      </div>
    `).join('');

    // Add click handlers for untrust buttons
    container.querySelectorAll('.btn-untrust').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const fingerprint = e.currentTarget.dataset.fingerprint;
        const deviceInfo = this.trustedDevices.get(fingerprint);

        if (!deviceInfo) return;

        const confirmed = await ui.showConfirmDialog({
          title: '取消信任设备',
          message: `确定要取消信任「<strong>${ui.escapeHtml(deviceInfo.name)}</strong>」吗？<br><br><span style="color: var(--text-muted)">取消后，该设备发送文件时需要您手动确认。</span>`,
          confirmText: '取消信任',
          cancelText: '保留信任',
          type: 'warning'
        });

        if (confirmed) {
          const info = this.removeTrustedDevice(fingerprint);
          if (info) {
            ui.showToast(`已取消信任: ${info.name}`, 'info');
          }
          this.renderTrustedDevicesList();
        }
      });
    });
  }

  // Show mobile share modal
  showMobileShareModal() {
    document.getElementById('shareRoomCode').textContent = this.roomCode;
    ui.showModal('mobileShareModal');
  }

  // Select file to send (for mobile)
  selectFileToSend() {
    if (this.peers.size === 0) {
      ui.showToast('没有可用的设备', 'warning');
      return;
    }

    if (this.peers.size === 1) {
      // Single peer, directly select file
      const [peerId] = this.peers.keys();
      const input = document.createElement('input');
      input.type = 'file';
      input.multiple = true;
      input.onchange = () => this.sendFiles(peerId, Array.from(input.files));
      input.click();
    } else {
      // Multiple peers, show selection first
      ui.showToast('请点击目标设备来发送文件', 'info');
    }
  }

  // Show text input for sending
  showTextInputForSend() {
    if (this.peers.size === 0) {
      ui.showToast('没有可用的设备', 'warning');
      return;
    }

    if (this.peers.size === 1) {
      const [peerId, peer] = [...this.peers.entries()][0];
      this.selectedPeer = peer;
      document.getElementById('textInput').value = '';
      ui.showModal('textModal');
    } else {
      ui.showToast('请点击目标设备上的消息按钮来发送文字', 'info');
    }
  }

  // Haptic feedback
  triggerHaptic(intensity = 'light') {
    if ('vibrate' in navigator) {
      switch (intensity) {
        case 'light':
          navigator.vibrate(10);
          break;
        case 'medium':
          navigator.vibrate(25);
          break;
        case 'heavy':
          navigator.vibrate([30, 10, 30]);
          break;
      }
    }
  }

  // Setup keyboard detection for mobile
  setupKeyboardDetection() {
    // Use focus/blur events to detect keyboard
    const inputs = document.querySelectorAll('input, textarea');

    inputs.forEach(input => {
      input.addEventListener('focus', () => {
        // Small delay to let keyboard animate
        setTimeout(() => {
          document.documentElement.classList.add('keyboard-visible');
        }, 100);
      });

      input.addEventListener('blur', () => {
        setTimeout(() => {
          document.documentElement.classList.remove('keyboard-visible');
        }, 100);
      });
    });
  }

  // Setup visual viewport handling for iOS
  setupVisualViewport() {
    if (window.visualViewport) {
      const viewport = window.visualViewport;

      const handleViewportChange = () => {
        // Calculate keyboard height
        const keyboardHeight = window.innerHeight - viewport.height;

        if (keyboardHeight > 100) {
          // Keyboard is visible
          document.documentElement.style.setProperty('--keyboard-height', `${keyboardHeight}px`);
          document.documentElement.classList.add('keyboard-visible');

          // Scroll active element into view
          const activeElement = document.activeElement;
          if (activeElement && (activeElement.tagName === 'INPUT' || activeElement.tagName === 'TEXTAREA')) {
            setTimeout(() => {
              activeElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }, 100);
          }
        } else {
          // Keyboard is hidden
          document.documentElement.style.setProperty('--keyboard-height', '0px');
          document.documentElement.classList.remove('keyboard-visible');
        }
      };

      viewport.addEventListener('resize', handleViewportChange);
      viewport.addEventListener('scroll', handleViewportChange);
    }
  }
}

// Initialize app
const app = new CloudDrop();
app.init().catch(console.error);

