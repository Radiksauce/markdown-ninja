<template>
  <div class="rounded-md bg-red-50 p-2 mb-3 mt-10" v-if="error">
    <div class="flex">
      <div class="ml-3">
        <p class="text-sm text-red-700">
          {{ error }}
        </p>
      </div>
    </div>
  </div>

  <h1>All pages for: {{ tag }}</h1>

  <PostsList :posts="pages" />
</template>

<script lang="ts" setup>
import type { ListPagesInput, PageMetadata } from '@/app/model';
import { onBeforeMount, ref, type Ref, watch } from 'vue';
import PostsList from '@/ui/components/posts_list.vue';
import { useRoute } from 'vue-router';
import { useStore } from '@/app/store';
import { listPages, trackPage } from '@/app/mdninja';

// props

// events

// composables
const $route = useRoute();
const $store = useStore();

// lifecycle
onBeforeMount(() => {
  document.title = `${website.name} - Pages for: ${tag.value}`;
  trackPage();
  fetchPages();
});

// variables
const website = $store.website!;
let pages: Ref<PageMetadata[]> = ref([]);

let error = ref('');
let tag = ref($route.params.tag as string);


// computed

// watch
watch($route, (to) => {
  fetchPages();
  tag.value = to.params.tag as string;
}, { deep: true });

// functions
async function fetchPages() {
  // loading.value = true;
  error.value = '';
  const input: ListPagesInput = {
    tag: tag.value,
  };

  try {
    const apiRes = await listPages(input);
    pages.value = apiRes.data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    $store.setLoading(false);
  }
}
</script>
