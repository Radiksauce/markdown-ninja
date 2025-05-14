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

  <header v-if="!error" class="sticky top-0 w-full z-50 left-0">
    <AnnouncementBar v-if="$store.announcement" />
    <Navbar :website="website" has-sidebar />
  </header>
  <div v-if="!error">
    <SidebarWrapper>
      <Sidebar />
    </SidebarWrapper>
  </div>
  <main v-if="!error" class="md:ml-64 max-w-5xl px-5 pb-3 leading-7">
    <RouterView />
  </main>

  <Searchbar />
</template>

<script lang="ts" setup>
import { onBeforeMount, ref, watch } from 'vue';
import { useStore } from './app/store';
import Navbar from '@/ui/components/navbar.vue';
import NProgress from '@/libs/nprogress';
import SidebarWrapper from './ui/components/sidebar_wrapper.vue';
import Sidebar from './ui/components/sidebar.vue';
import AnnouncementBar from './ui/components/announcement_bar.vue';
import Searchbar from '@/ui/components/searchbar.vue';

// props

// events

// composables
const $store = useStore();

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
})

// variables
const website = $store.website!;
let error = ref('');

// computed

// watch
watch(() => $store.loading, (newValue, oldValue) => {
  if (!oldValue && newValue) {
    NProgress.start();
  } else if (!newValue && oldValue) {
    NProgress.done();
  }
});

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
