// Preload: exposes a tiny bridge for the injected team_mh desktop panel and the
// commands dialog (v0.3.0: direct local execution in real Chrome).
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('tmhDesktop', {
  version: () => ipcRenderer.invoke('tmh-version'),
  signin: (which) => ipcRenderer.send('tmh-google-signin', which),
  getState: () => ipcRenderer.invoke('tmh-google-state'),
  openCommands: () => ipcRenderer.send('tmh-open-commands'),
  runLocal: (payload) => ipcRenderer.invoke('tmh-run-local', payload),
  stopRun: () => ipcRenderer.invoke('tmh-stop-run'),
  copyLog: () => ipcRenderer.invoke('tmh-copy-log'),
  saveLog: () => ipcRenderer.invoke('tmh-save-log'),
  getSettings: () => ipcRenderer.invoke('tmh-get-settings'),
  setSpacing: (sec) => ipcRenderer.invoke('tmh-set-spacing', sec),
  history: () => ipcRenderer.invoke('tmh-history'),
  sheetStatus: (group) => ipcRenderer.invoke('tmh-sheet-status', group),
  onState: (cb) => {
    ipcRenderer.on('tmh-google-state', (_e, state) => cb(state));
  },
  onProgress: (cb) => {
    ipcRenderer.on('tmh-run-progress', (_e, info) => cb(info));
  }
});
