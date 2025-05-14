import './theme.css';
import './nprogress.css';

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from '@/app.vue';
import { createConfig } from '@/app/config';
import { newRouter } from '@/app/router';
import NProgress from '@/libs/nprogress';
import { createLinkify } from './libs/linkify';
import { initData } from './app/mdninja';

async function main() {
  const config = createConfig();
  if (config.env !== 'production') {
    console.log(config);
  }

  const app = createApp(App);

  const pinia = createPinia();
  app.use(pinia);

  await initData(config.env);

  const router = newRouter();
  app.use(router);

  NProgress.configure({ easing: 'ease', speed: 500 });

  await router.isReady();

  createLinkify(router);

  app.mount('#markdown-ninja-website');
}

main();
