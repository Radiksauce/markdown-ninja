<template>
  <div ref="component" v-html="html" />
</template>

<script lang="ts" setup>
import { useLinkify } from '../libs/linkify';
import { onMounted, ref, type PropType, type Ref, watch, nextTick } from 'vue';

// props
const props = defineProps({
  html: {
    type: String as PropType<string>,
    required: true,
  }
});

// events

// composables
const $linkify = useLinkify()

// lifecycle
onMounted(() => {
  $linkify.linkify(component.value!);
  redirectMarkdownNinjaSubscribe(component.value!);
});

// variables
const component: Ref<HTMLElement | null> = ref(null);

// computed

// watch
watch(() => props.html, () => {
  nextTick(() => {
    $linkify.linkify(component.value!);
    redirectMarkdownNinjaSubscribe(component.value!);
  });
});

// functions
// TODO: remove
// this was a quick workarround to enable the subscribe_form snippet to work with the new Markdown Ninja
function redirectMarkdownNinjaSubscribe(element: HTMLElement) {
  var elements = element.getElementsByClassName('markdown-ninja-subscribe');
  for (let i = 0; i < elements.length; i++) {
    elements[i].addEventListener('click', (event) => {
      event.preventDefault();
      // @ts-ignore
      // history.pushState(null, null, '/subscribe');
      // history.go();
      window.location.assign('/subscribe');
      // history.pushState
      // this.router.push('/portal/subscribe');
      // window.location.hash = '#/portal/subscribe';
    }, false);
  }
}
// function onClick(event: MouseEvent) {
//   let target: HTMLElement | null = event.target as HTMLElement;
//   while (target && target.tagName !== 'A') {
//     target = target.parentNode as HTMLElement | null;
//     if (!target || target.matches(".markdown-ninja-html")) {
//       return;
//     }
//   }
//   let link = target as HTMLAnchorElement;

//   if (link.hostname != window.location.hostname) {
//         // open external links in new tab
//         link.setAttribute('target', '_blank');
//         link.setAttribute('rel', 'noopener');
//   };

//   if (link.onclick) {
//     return;
//   }

//   if (link.matches("a:not([href*='://'])") && link.href) {
//       // some sanity checks taken from vue-router
//       const { altKey, ctrlKey, metaKey, shiftKey, button, defaultPrevented } = event;
//       // don't handle with control keys
//       if (metaKey || altKey || ctrlKey || shiftKey) {
//         return
//       }
//       // don't handle when preventDefault called
//       if (defaultPrevented) {
//         return;
//       }
//       // don't handle right clicks
//       if (button !== undefined && button !== 0) {
//         return;
//       }
//       // don't handle if `target="_blank"`
//       if (link.getAttribute) {
//         const linkTarget = link.getAttribute('target')
//         if (linkTarget && /\b_blank\b/i.test(linkTarget)) {
//           return
//         }
//       }
//       // don't handle same page links/anchors
//       const url = new URL(link.href)
//       const to = url.pathname
//       if (window.location.pathname !== to && event.preventDefault) {
//         event.preventDefault()
//         $router.push(to)
//       }

//   }

// }
</script>
