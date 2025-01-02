const fs = require('fs-extra');
const path = require('path');

if (process.env.INIT_CWD !== process.cwd()) {
  const sourceDir = path.join(__dirname, '..', 'auth');
  const targetDir = path.join(process.env.INIT_CWD, 'auth');

  fs.copySync(sourceDir, targetDir, {
    filter: (src) => {
      return src.endsWith('.hbs') || src.endsWith('.css') || src.endsWith('.js') || src.endsWith('.ico') || src.endsWith('.svg') || !path.extname(src);
    }
  });
}
