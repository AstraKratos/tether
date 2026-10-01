// Copy the web app (../app) into www/, which Capacitor bundles into the native apps. The app is
// the same one the relay serves in a browser; inside the apps it runs from the device and talks
// to the relay picked in Settings, so there is no web login page to open first.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const src = path.join(HERE, '..', '..', 'app');
const out = path.join(HERE, '..', 'www');
fs.rmSync(out, { recursive: true, force: true });
fs.cpSync(src, out, { recursive: true });
console.log(`copied ${src} -> ${out}`);
