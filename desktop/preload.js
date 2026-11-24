// Preload: exposes a tiny bridge for the injected team_mh desktop panel and the
// commands dialog (v0.3.0: direct local execution in real Chrome).
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('tmhDesktop', {
  signin: (which) => ipcRenderer.send('tmh-google-signin', which),
  getState: () => ipcRenderer.invoke('tmh-google-state'),
  openCommands: () => ipcRenderer.send('tmh-open-commands'),
  runLocal: (payload) => ipcRenderer.invoke('tmh-run-local', payload),
  onState: (cb) => {
    ipcRenderer.on('tmh-google-state', (_e, state) => cb(state));
  },
  onProgress: (cb) => {
    ipcRenderer.on('tmh-run-progress', (_e, info) => cb(info));
  }
});
