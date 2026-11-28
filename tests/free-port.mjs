// An unused local port chosen by the OS. Test servers must use this instead of a fixed number: test files run in
// parallel, and a fixed port can already be taken on a developer PC (Entity 360 on 3600/3601 ...).
// On Windows two processes can bind the same 127.0.0.1 port, so a clash shows up as wrong answers or a hang, not an error.
import { createServer } from 'node:net';

export const freePort = () => new Promise((resolve, reject) => {
  const s = createServer();
  s.unref();
  s.on('error', reject);
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});
