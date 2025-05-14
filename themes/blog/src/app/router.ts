import { createRouter, createWebHistory, type Router } from 'vue-router';
import { useStore } from './store';

const Any = () =>  import('@/ui/pages/any.vue');
const Blog = () =>  import('@/ui/pages/blog.vue');
const Tags = () =>  import('@/ui/pages/tags.vue');
const Tag = () =>  import('@/ui/pages/tag.vue');
const Subscribe = () =>  import('@/ui/pages/subscribe.vue');
const Unsubscribe = () =>  import('@/ui/pages/unsubscribe.vue');
const Checkout = () =>  import('@/ui/pages/checkout/checkout.vue');
const CompleteCheckout = () =>  import('@/ui/pages/checkout/complete.vue');
const CancelCheckout = () =>  import('@/ui/pages/checkout/cancel.vue');
const Login = () => import('@/ui/pages/login.vue');

const Account = () => import('@/ui/pages/account/account.vue');
const Product = () => import('@/ui/pages/account/products/product.vue');


export function newRouter(): Router {
  const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes: [
      { path: '/subscribe', component: Subscribe },
      { path: '/unsubscribe', component: Unsubscribe },
      { path: '/blog', component: Blog },
      { path: '/tags', component: Tags },
      { path: '/tags/:tag', component: Tag },
      { path: '/checkout', component: Checkout },
      { path: '/checkout/:order_id/complete', component: CompleteCheckout },
      { path: '/checkout/:order_id/cancel', component: CancelCheckout },
      { path: '/login', component: Login },
      { path: '/account/login', redirect: '/login' },

      { path: '/account', component: Account },
      { path: '/account/products/:product_id', component: Product },


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

    if (!(to.path.startsWith('/account') || to.path === '/subscribe' ||  to.path === '/unsubscribe')) {
      $store.setLoading(true);
    }

    if (($store.contact) && (to.path === '/account/login' || to.path === '/subscribe' || to.path === '/unsubscribe')) {
      return '/account';
    } else if (!$store.contact) {
      if (to.path.startsWith('/account') && to.path !== '/account/login') {
        // window.location.href = '/account/login';
        // return '';
        return '/account/login';
      }
      // else if (to.path === '/subscribe' && history.state?.back) {
      //   history.pushState({}, '', '/subscribe');
      //   window.location.href = '/subscribe';
      //   return '';
      // }
    }
  });

  return router;
}
