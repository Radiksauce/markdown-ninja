// the linkify function opens external links in new tab
// and transform internal link to be handled by vue router while maintaining the behavior of a normal link
// See https://kerkour.com/vuejs-3-router-links-dynamic-vhtml
// https://dennisreimann.de/articles/delegating-html-links-to-vue-router.html
// https://stackoverflow.com/questions/50329382/vue-router-with-links-in-a-template-string
// https://levelup.gitconnected.com/vue-js-replace-a-with-router-link-in-dynamic-html-c423beea0d17
// https://stackoverflow.com/questions/47530417/dynamic-router-link
// https://stackoverflow.com/questions/57888239/vue-router-working-but-not-transform-router-link-to-anchor-tag
// https://stackoverflow.com/questions/50712483/vuejs-render-raw-html-links-to-router-link

import type { Router } from "vue-router";

let linkify: Linkify | null = null;

export function createLinkify(router: Router): Linkify {
  linkify = new Linkify(router);
  return linkify;
}

export function useLinkify(): Linkify {
  if (!linkify) {
    throw new Error('linkify should be created before using it');
  }
  return linkify!;
}

export class Linkify {
  private router: Router;

  constructor(router: Router) {
    this.router = router;
  }

  linkify(element: HTMLElement) {
    const links = element.getElementsByTagName('a');
    Array.from(links).forEach((link: HTMLAnchorElement) => {
    // for(let i = 0; i < links.length; i++) {
      // const link = links[i];
      if (link.hostname != '' && !link.href.startsWith('mailto:')) {
        if (link.hostname != window.location.hostname) {
          // open external links in new tab
          link.setAttribute('target', '_blank');
          link.setAttribute('rel', 'noopener');
        } else {
          // ignore if onclick is already set
          // e.g. RouterLink
          if (link.onclick) {
            return;
          }

          link.onclick = (event: MouseEvent) => {
            const { altKey, ctrlKey, metaKey, shiftKey, button, defaultPrevented } = event;
            // ignore with control keys
            if (metaKey || altKey || ctrlKey || shiftKey) {
              return;
            }

            // ignore when preventDefault called
            // e.g. if it's a router-link
            if (defaultPrevented) {
              return;
            }

            // ignore right clicks
            if (button !== undefined && button !== 0) {
              return;
            }

            // ignore if `target="_blank"`
            const linkTarget = link.getAttribute('target');
            if (linkTarget && /\b_blank\b/i.test(linkTarget)) {
              return;
            }

            let url: URL | null = null;
            try {
              url = new URL(link.href);
            } catch (err) {
              return;
            }

            // ignore same page links with anchors
            if (url.hash && window.location.pathname === url.pathname) {
              return;
            }

            event.preventDefault();
            this.router.push(`${url.pathname}${url.search}${url.hash}`);

            // if (window.location.pathname !== to && e.preventDefault) {
            //   e.preventDefault();
            //   $router.push(link.pathname)
            // }
          }
        }
      }
    });
  }
}
