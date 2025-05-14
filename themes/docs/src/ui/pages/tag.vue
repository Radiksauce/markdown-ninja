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

  <hr />

  <PagesList :pages="pages" />
</template>

<script lang="ts" setup>
import type { ListPagesInput, PageMetadata } from '@/app/model';
import { onBeforeMount, ref, type Ref } from 'vue';
import PagesList from '@/ui/components/pages_list.vue';
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
  document.title = `${website.name} - Pages for: ${tag}`;
  trackPage();
  fetchPages();
});

// variables
const website = $store.website!;
const tag = $route.params.tag as string;
let pages: Ref<PageMetadata[]> = ref([]);

let error = ref('');


// computed

// watch

// functions
async function fetchPages() {
  // loading.value = true;
  error.value = '';
  const input: ListPagesInput = {
    tag: tag,
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
