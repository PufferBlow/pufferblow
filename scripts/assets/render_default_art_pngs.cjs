// Renders the default avatars (512x512) and banners (1500x500) from SVG to PNG with Electron's
// Chromium, for clients that cannot draw SVG. Transparent backgrounds are kept.
//
//   cd client-new && npx electron ../pufferblow/scripts/assets/render_default_art_pngs.cjs
//
// (unset ELECTRON_RUN_AS_NODE if your shell sets it)
const { app, BrowserWindow } = require("electron");
const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");

const ART = path.resolve(__dirname, "../../pufferblow/assets/default-art");
const JOBS = [
  { dir: "avatars", width: 512, height: 512 },
  { dir: "banners", width: 1500, height: 500 },
];

app.disableHardwareAcceleration();

app.whenReady().then(async () => {
  let written = 0;
  const win = new BrowserWindow({ width: 512, height: 512, show: false, transparent: true, frame: false, useContentSize: true, webPreferences: { offscreen: true } });
  for (const { dir, width, height } of JOBS) {
    win.setContentSize(width, height);
    for (const file of fs.readdirSync(path.join(ART, dir)).filter((f) => f.endsWith(".svg"))) {
      const svg = fs.readFileSync(path.join(ART, dir, file), "utf8");
      const html = `<!doctype html><html><body style="margin:0;background:transparent;overflow:hidden"><img style="display:block;width:${width}px;height:${height}px" src="data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}"></body></html>`;
      await win.loadURL("data:text/html;charset=utf-8," + encodeURIComponent(html));
      await new Promise((r) => setTimeout(r, 120));
      const image = await win.webContents.capturePage();
      const size = image.getSize();
      if (size.width !== width || size.height !== height) throw new Error(`${file}: captured ${size.width}x${size.height}, wanted ${width}x${height}`);
      fs.writeFileSync(path.join(ART, dir, file.replace(/\.svg$/, ".png")), image.toPNG());
      written += 1;
    }
  }
  win.destroy();
  console.log(`wrote ${written} PNGs under ${ART}`);
  app.quit();
});
