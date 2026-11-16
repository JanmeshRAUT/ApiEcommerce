const fs = require('fs');
const path = require('path');

if (process.platform === 'win32') {
  const binDir = path.join(__dirname, '..', 'node_modules', '.bin');
  if (fs.existsSync(binDir)) {
    for (const file of fs.readdirSync(binDir)) {
      if (file.endsWith('.cmd')) {
        const filePath = path.join(binDir, file);
        const content = fs.readFileSync(filePath, 'utf8');
        if (content.includes('SET dp0=%~dp0')) {
          fs.writeFileSync(filePath, content.replaceAll('SET dp0=%~dp0', 'SET "dp0=%~dp0"'), 'utf8');
        }
      }
    }
  }
}

