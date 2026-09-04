(() => {
  'use strict';

  const STORAGE_KEY = 'baiyunkeys.github.config.v1';
  const SERVICES = [
    '0734594a-a8e7-4b1a-a6b1-cd5243059a57',
    '14839ac4-7d7e-415c-9a42-167340cf2339',
  ];
  const fields = {
    name: document.querySelector('#door-name'),
    mac: document.querySelector('#mac'),
    bluetoothName: document.querySelector('#bluetooth-name'),
    key: document.querySelector('#door-key'),
  };
  const statusCard = document.querySelector('#status-card');
  const statusDoor = document.querySelector('#status-door');
  const statusText = document.querySelector('#status-text');
  const statusIcon = document.querySelector('#status-icon');
  const savedBadge = document.querySelector('#saved-badge');
  const unlockButton = document.querySelector('#unlock');
  const logList = document.querySelector('#log-list');
  let logs = [];

  function sanitizeMac(value) { return value.toUpperCase().replace(/[^0-9A-F:]/g, '').slice(0, 17); }
  function sanitizeKey(value) { return value.toUpperCase().replace(/[^0-9A-F]/g, '').slice(0, 32); }
  function validMac(value) { return /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(value); }
  function validKey(value) { return value.length >= 16 && value.length <= 32 && value.length % 2 === 0; }
  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < hex.length; index += 2) bytes[index / 2] = parseInt(hex.slice(index, index + 2), 16);
    return bytes;
  }
  function bytesToHex(bytes) { return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase(); }
  function viewToBytes(view) { return new Uint8Array(view.buffer, view.byteOffset, view.byteLength).slice(); }
  function currentConfig() {
    return { name: fields.name.value.trim(), mac: fields.mac.value, bluetoothName: fields.bluetoothName.value.trim(), key: fields.key.value };
  }
  function setStatus(kind, message) {
    statusCard.classList.remove('success', 'error');
    if (kind !== 'idle' && kind !== 'busy') statusCard.classList.add(kind);
    statusIcon.textContent = kind === 'success' ? '✓' : kind === 'error' ? '!' : kind === 'busy' ? '◌' : '⌾';
    statusText.textContent = message;
  }
  function addLog(message) {
    logs.push(message);
    logList.innerHTML = '';
    logs.forEach((text) => { const item = document.createElement('li'); item.textContent = text; logList.appendChild(item); });
  }
  function validate(showErrors = true) {
    const config = currentConfig();
    const checks = { name: Boolean(config.name), mac: validMac(config.mac), key: validKey(config.key) };
    if (showErrors) {
      fields.name.classList.toggle('invalid', !checks.name);
      fields.mac.classList.toggle('invalid', !checks.mac);
      fields.key.classList.toggle('invalid', !checks.key);
    }
    return Object.values(checks).every(Boolean);
  }
  function saveConfig() {
    if (!validate()) { setStatus('error', '请先检查门禁名称、MAC 和 Key'); return false; }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(currentConfig()));
    savedBadge.classList.remove('hidden');
    statusDoor.textContent = fields.name.value.trim();
    setStatus('idle', '已安全保存到当前浏览器本机');
    return true;
  }
  function desEncrypt(keyHex, payloadHex) {
    const result = CryptoJS.DES.encrypt(CryptoJS.enc.Hex.parse(payloadHex), CryptoJS.enc.Hex.parse(keyHex.slice(0, 16)), { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding });
    return result.ciphertext.toString(CryptoJS.enc.Hex).toUpperCase();
  }
  function desDecrypt(keyHex, payloadHex) {
    const params = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Hex.parse(payloadHex) });
    return CryptoJS.DES.decrypt(params, CryptoJS.enc.Hex.parse(keyHex.slice(0, 16)), { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }).toString(CryptoJS.enc.Hex).toUpperCase();
  }
  function buildCommand(seed, mac, key) {
    if (seed.length < 4) throw new Error('门锁返回的随机数不足 4 字节');
    const seed4 = seed.slice(0, 4);
    const keyBytes = hexToBytes(key);
    const sum = [...seed4, ...keyBytes].reduce((total, byte) => total + byte, 0);
    const plain = new Uint8Array([sum & 255, (sum >> 8) & 255, ...seed4, 0, 0]);
    const encrypted = hexToBytes(desEncrypt(key, bytesToHex(plain)));
    const macBytes = hexToBytes(mac.replaceAll(':', ''));
    const frame = [0xa5, 0x14, 0x05, ...macBytes.slice(2), 0, 1, 7, ...encrypted, 0, 0x5a];
    const checksum = frame.reduce((total, byte) => total + byte, 0);
    frame[frame.length - 2] = (~(checksum & 255) + 256) & 255;
    return new Uint8Array(frame);
  }
  function parseReply(bytes, key) {
    const hex = bytesToHex(bytes);
    if (!hex.startsWith('A5')) return null;
    const command = hex.slice(4, 6);
    const type = hex.slice(18, 20);
    if (command === '04') {
      if (hex.length > 24) return { success: true, message: '握手成功，门锁已收到开锁指令' };
      const field = hex.slice(14, 18);
      const code = field.slice(2, 4) + field.slice(0, 2);
      return { success: false, message: `握手失败（0x${code || 'FFFF'}），请检查门禁信息` };
    }
    if (command === '08') return { success: false, message: '通讯密钥协商失败，请检查门禁信息' };
    if (type === '87' && hex.endsWith('5A') && hex.length >= 36) {
      const code = desDecrypt(key, hex.slice(20, 36)).slice(4, 6);
      if (code === '00') return { success: true, message: '开门成功' };
      if (code === '02') return { success: true, message: '门已经打开' };
      return { success: false, message: '开门失败，请检查 Key 是否有效' };
    }
    return null;
  }
  async function findService(server) {
    for (const uuid of SERVICES) { try { return await server.getPrimaryService(uuid); } catch (_) {} }
    throw new Error('未找到白云门禁蓝牙服务，请靠近门锁后重试');
  }
  async function writeValue(characteristic, bytes) {
    if (characteristic.properties.write && characteristic.writeValueWithResponse) return characteristic.writeValueWithResponse(bytes);
    if (characteristic.properties.writeWithoutResponse && characteristic.writeValueWithoutResponse) return characteristic.writeValueWithoutResponse(bytes);
    if (characteristic.writeValue) return characteristic.writeValue(bytes);
    throw new Error('门锁写入特征不可用');
  }
  async function selectDevice(config) {
    const expectedName = config.bluetoothName.trim();
    if (expectedName && typeof navigator.bluetooth.getDevices === 'function') {
      try {
        const permittedDevices = await navigator.bluetooth.getDevices();
        const target = permittedDevices.find((device) =>
          (device.name || '').trim().toLocaleLowerCase() === expectedName.toLocaleLowerCase()
        );
        if (target) {
          setStatus('busy', `正在自动连接 ${target.name}…`);
          addLog(`已找到授权设备 ${target.name}，无需再次选择`);
          return target;
        }
      } catch (_) {
        addLog('无法读取已授权设备，将打开设备选择列表');
      }
    }

    const prompt = expectedName
      ? `首次使用请在列表中选择 ${expectedName}`
      : '请在系统列表中选择你的门锁';
    setStatus('busy', prompt);
    addLog(prompt);
    const options = expectedName
      ? { filters: [{ name: expectedName }], optionalServices: SERVICES }
      : { acceptAllDevices: true, optionalServices: SERVICES };
    return navigator.bluetooth.requestDevice(options);
  }
  async function unlock() {
    if (!saveConfig()) return;
    if (!navigator.bluetooth) throw new Error('当前浏览器不支持网页蓝牙，请用 Bluefy 打开');
    const config = currentConfig();
    let server;
    const listeners = [];
    try {
      logs = []; logList.innerHTML = '<li class="empty-log">正在开始连接…</li>';
      unlockButton.disabled = true; unlockButton.textContent = '正在连接门锁…';
      const device = await selectDevice(config);
      setStatus('busy', `正在连接 ${device.name || config.bluetoothName || '门锁'}…`); addLog('正在连接门锁');
      server = await device.gatt.connect();
      const service = await findService(server);
      const characteristics = await service.getCharacteristics();
      const readable = characteristics.find((item) => item.properties.read);
      const writable = characteristics.find((item) => item.properties.write || item.properties.writeWithoutResponse);
      const notifiable = characteristics.filter((item) => item.properties.notify || item.properties.indicate);
      if (!readable || !writable || !notifiable.length) throw new Error('门锁未提供完整的蓝牙通道');
      let armed = false;
      let resolveReply;
      const replyPromise = new Promise((resolve) => { resolveReply = resolve; });
      for (const characteristic of notifiable) {
        const listener = (event) => {
          if (!armed || !event.currentTarget.value) return;
          const result = parseReply(viewToBytes(event.currentTarget.value), config.key);
          if (result) resolveReply(result);
        };
        characteristic.addEventListener('characteristicvaluechanged', listener);
        listeners.push([characteristic, listener]);
        await characteristic.startNotifications();
      }
      await new Promise((resolve) => setTimeout(resolve, 120));
      setStatus('busy', '正在读取门锁随机数…'); addLog('正在读取门锁随机数');
      const seed = viewToBytes(await readable.readValue());
      armed = true;
      setStatus('busy', '正在发送加密开锁指令…'); addLog('正在发送加密开锁指令');
      await writeValue(writable, buildCommand(seed, config.mac, config.key));
      setStatus('busy', '指令已发送，等待门锁响应…'); addLog('等待门锁响应');
      const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('等待门锁响应超时，请靠近门锁后重试')), 20000));
      const result = await Promise.race([replyPromise, timeout]);
      if (!result.success) throw new Error(result.message);
      setStatus('success', result.message); addLog(result.message);
    } finally {
      for (const [characteristic, listener] of listeners) {
        characteristic.removeEventListener('characteristicvaluechanged', listener);
        if (characteristic.stopNotifications) await characteristic.stopNotifications().catch(() => {});
      }
      if (server && server.connected) server.disconnect();
      unlockButton.disabled = false; unlockButton.textContent = '⌁　连接并开锁';
    }
  }

  fields.mac.addEventListener('input', () => { fields.mac.value = sanitizeMac(fields.mac.value); savedBadge.classList.add('hidden'); });
  fields.key.addEventListener('input', () => { fields.key.value = sanitizeKey(fields.key.value); savedBadge.classList.add('hidden'); });
  fields.name.addEventListener('input', () => { statusDoor.textContent = fields.name.value || '我的门禁'; savedBadge.classList.add('hidden'); });
  fields.bluetoothName.addEventListener('input', () => savedBadge.classList.add('hidden'));
  document.querySelector('#toggle-key').addEventListener('click', (event) => {
    const showing = fields.key.type === 'text'; fields.key.type = showing ? 'password' : 'text'; event.currentTarget.textContent = showing ? '显示' : '隐藏';
  });
  document.querySelector('#save').addEventListener('click', saveConfig);
  document.querySelector('#clear').addEventListener('click', () => {
    if (!confirm('清除本机保存的门禁信息？')) return;
    localStorage.removeItem(STORAGE_KEY); Object.values(fields).forEach((field) => { field.value = ''; });
    fields.name.value = '我的门禁'; statusDoor.textContent = '我的门禁'; savedBadge.classList.add('hidden'); logs = []; logList.innerHTML = '<li class="empty-log">还没有连接记录</li>'; setStatus('idle', '本机门禁信息已清除');
  });
  unlockButton.addEventListener('click', () => unlock().catch((error) => { setStatus('error', error.name === 'NotFoundError' ? '你取消了设备选择' : error.message || '操作失败'); addLog('操作失败，请查看上方提示'); }));

  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
    if (saved) {
      Object.keys(fields).forEach((key) => { fields[key].value = saved[key] || ''; });
      statusDoor.textContent = saved.name || '我的门禁'; savedBadge.classList.remove('hidden'); setStatus('idle', '门禁信息已从本机载入，可以直接开锁');
    } else fields.name.value = '我的门禁';
  } catch (_) { fields.name.value = '我的门禁'; }
  if (!navigator.bluetooth) document.querySelector('#browser-warning').classList.remove('hidden');
})();
