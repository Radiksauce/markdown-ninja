<template>
  <div class="border border-red-600 rounded-md bg-red-50 p-4 my-5 mx-5" v-if="error">
    <div class="flex">
      <div class="ml-3">
        <p class="text-sm text-red-700">
          {{ error }}
        </p>
      </div>
    </div>
  </div>

  <header class="sticky top-0 w-full z-10 left-0">
    <AnnouncementBar v-if="$store.website?.announcement" />
    <Navbar :website="website" subscribe-button />
  </header>

  <main v-if="!error" class="mt-5">
    <div class="m-auto max-w-3xl px-5 pb-3 leading-7">
      <RouterView />
      <div v-if="website.ad && showAd && !$store.loading" v-html="website.ad" />
    </div>
  </main>

  <footer class="flex text-center w-full my-4" v-if="!$store.loading && website.powered_by && showPoweredBy">
    <p class="inline w-full text-gray-400 font-light">
      Powered by&nbsp;
      <a href="https://markdown.ninja" target="_blank" rel="noopener" class="text-gray-500 underline font-normal">
        Markdown Ninja
      </a>
    </p>
  </footer>

  <Searchbar />
</template>

<script lang="ts" setup>
import { computed, onBeforeMount, ref, watch } from 'vue';
import { useStore } from './app/store';
import Navbar from '@/ui/components/navbar.vue';
import NProgress from '@/libs/nprogress';
import AnnouncementBar from '@/ui/components/announcement_bar.vue';
import Searchbar from '@/ui/components/searchbar.vue';
import { useRoute } from 'vue-router';

// props

// events

// composables
const $store = useStore();
const $route = useRoute();

// lifecycle
onBeforeMount(() => {
  if (window.__markdown_ninja_error) {
    error.value = window.__markdown_ninja_error;
    return;
  }

  // this should happen only in development
  if (!$store.website) {
    error.value = 'Site not found.';
  }

  window.addEventListener("keydown", handleShortcut);
});

// variables
const website = $store.website!;
let error = ref('');

// computed
const showAd = computed(() => {
  if (['/checkout'].includes($route.path)
    || $route.path.startsWith('/account')) {
    return false;
  }
  return true;
})

const showPoweredBy = computed(() => {
  if (['/checkout'].includes($route.path)) {
    return false;
  }
  return true;
})

// watch
watch(() => $store.loading, (newValue, oldValue) => {
  if (!oldValue && newValue) {
    NProgress.start();
  } else if (!newValue && oldValue) {
    NProgress.done();
  }
})

// functions
function handleShortcut(event: any) {
  // ctrl / cmd + K
  if (event.keyCode === 75 && event.metaKey) {
    $store.setShowSearchbar(!$store.showSearchbar);
    event.preventDefault();
    return;
  }
}
</script>
