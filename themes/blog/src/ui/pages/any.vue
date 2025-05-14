<template>
  <div class="rounded-md bg-red-50 p-4 mb-3 mt-5" v-if="error">
    <div class="flex">
      <div class="ml-3">
        <p class="text-sm text-red-700">
          {{ error }}
        </p>
      </div>
    </div>
  </div>

  <div v-if="page">
    <PPage v-if="isPage" :page="page" />
    <Post v-else-if="isPost" :page="page" />
  </div>
  <PageNotFound v-else-if="!page && !$store.loading" />
</template>

<script lang="ts" setup>
import { PageType, type GetPageInput, type Page } from '@/app/model';
import PageNotFound from '@/ui/components/page_not_found.vue';
import PPage from '@/ui/components/page.vue';
import Post from '@/ui/components/post.vue';
import { computed, onBeforeMount, ref, watch, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import { useStore } from '@/app/store';
import { getPage } from '@/app/mdninja';

// props

// events

// composables
const $route = useRoute();
const $store = useStore();

// variables
const website = $store.website!;
let error = ref('');

let page: Ref<Page | null> = ref(null);


// lifecycle
onBeforeMount(() => {
  page.value = $store.initialPage;
  if (page.value) {
    $store.setLoading(false);
    $store.setInitialPage(null);
  } else {
    fetchPage();
  }
});

// computed
const isPage = computed((): boolean => page.value?.type === PageType.Page);
const isPost = computed((): boolean => page.value?.type === PageType.Post);

// watch
watch($route, (to) => {
  if (to.name === 'any') {
    fetchPage();
  }
}, { deep: true });

// functions


async function fetchPage() {
  $store.setInitialPage(null);
  $store.setLoading(true);
  error.value = '';
  page.value = null;
  let slug = location.pathname.trim();
  if (slug !== '/') {
    // some browsers may send an URL such as /mypage/ instead of /mypage so the trailing slash needs
    // to be removed
    slug.replace(/\/$/, '');
  }
  const input: GetPageInput = {
    slug: slug,
  };

  try {
    page.value = await getPage(input);
    if (page.value) {
      document.title = page.value!.title;
    } else {
      document.title = `${website.name} - Not Found`;
    }
  } catch (err: any) {
    error.value = err.message;
  } finally {
    $store.setLoading(false);
  }
}
</script>
