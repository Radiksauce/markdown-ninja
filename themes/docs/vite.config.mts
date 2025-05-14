
import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'


// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  },
  server: {
    proxy: {
      '/__markdown_ninja': {
        target: 'http://localhost:4080',
        // changeOrigin: true,
        secure: false
      },
      '/assets': {
        target: 'http://localhost:4080',
        secure: false
      }
    }
  },
  build:{
    assetsDir: 'theme',
    rollupOptions: {
      output: {
        // we use longer hashes to reduces the risk of collision with assets cached for long time
        assetFileNames(chunkInfo) {
          return `theme/[name]-[hash:20][extname]`;
        },
        chunkFileNames(chunkInfo) {
          return `theme/[name]-[hash:20].js`;
        },
        entryFileNames(chunkInfo) {
          return `theme/[name]-[hash:20].js`;
        },
        manualChunks: (id: string) => {
          // id = id.toLowerCase();
          // if (id.includes('pages/account')) {
          //   return 'account';
          // } else if (id.includes('pages')) {
          //   return '';
          // }

          return 'index';
        },
        // manualChunks: {
        //   'account': [
        //     // './src/ui/pages/account/account.vue',
        //     // './src/ui/pages/account/products/product.vue',
        //   ],
        // },
      },
    },
    terserOptions: {
      parse: {
        html5_comments: false,
      }
    },
  },
  esbuild: {
    legalComments: 'none',
  },
})
