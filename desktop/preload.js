// Preload: exposes a tiny bridge for the injected team_mh desktop panel.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('tmhDesktop', {
  signin: (which) => ipcRenderer.send('tmh-google-signin', which),
  getState: () => ipcRenderer.invoke('tmh-google-state'),
  openCommands: () => ipcRenderer.send('tmh-open-commands'),
  enqueue: (payload) => ipcRenderer.invoke('tmh-enqueue', payload),
  onState: (cb) => {
    ipcRenderer.on('tmh-google-state', (_e, state) => cb(state));
  }
});
