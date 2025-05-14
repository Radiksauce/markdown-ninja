<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-4">
      <h1 class="text-3xl font-extrabold text-gray-900">Pages</h1>
    </div>

    <div class="rounded-md bg-red-50 p-4" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex flex-row space-x-2">
      <sl-input :value="searchQuery" @input="searchQuery = $event.target.value" type="text"
        placeholder="Search"
      />

      <RouterLink :to="newPageUrl">
        <sl-button variant="primary">
          <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
          New Page
        </sl-button>
      </RouterLink>
    </div>

    <PagesList :pages="filteredPages" type="page" />
  </div>
</template>

<script lang="ts" setup>
import type { ListPagesInput, PageMetadata } from '@/api/model';
import PagesList from '@/ui/components/websites/pages_list.vue';
import { computed, onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import { PlusIcon } from '@heroicons/vue/24/outline';
import { useMdninja } from '@/api/mdninja';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';

// props

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const websiteId = $route.params.website_id as string;
const newPageUrl = './pages/new';

let loading = ref(false);
let error = ref('');
let pages: Ref<PageMetadata[]> = ref([]);
let searchQuery = ref('');

// computed
const filteredPages = computed((): PageMetadata[] => {
  return pages.value.filter((page) => {
    return page.title.toLowerCase().includes(searchQuery.value.toLowerCase()) || page.path.includes(searchQuery.value);
  });
});

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';
  const input: ListPagesInput = {
    website_id: websiteId,
  };

  try {
    const res = await $mdninja.listPages(input);
    pages.value = res.data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
