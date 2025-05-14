import { createRouter, createWebHistory, type Router } from 'vue-router';
import { useStore } from './store';

const Any = () =>  import('@/ui/pages/any.vue');
const Tags = () =>  import('@/ui/pages/tags.vue');
const Tag = () =>  import('@/ui/pages/tag.vue');


export function newRouter(): Router {
  const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes: [
      { path: '/tags', component: Tags },
      { path: '/tags/:tag', component: Tag },

      { path: '/:path(.*)*', component: Any, name: 'any' },
    ],
    scrollBehavior(to, from, savedPosition) {
      // if (savedPosition) {
      //   return savedPosition;
      // }

      if (to.hash) {
        return new Promise(resolve => {
          setTimeout(() => {
            resolve({ el: to.hash });
          }, 500);
        });
      }
      // else, always scroll to top
      return { top: 0 }
    },
  });

  router.beforeEach((to, from) => {
    const $store = useStore();
    $store.setLoading(true);
  });

  return router;
}
