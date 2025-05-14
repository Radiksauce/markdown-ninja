<template>
  <div class="flex-1 space-y-5">
    <div class="px-4 sm:px-6 md:px-0">
      <h1 class="text-3xl font-extrabold text-gray-900">Websites</h1>
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

    <div class="flex min-w-full flex-col">
      <sl-input :value="searchQuery" @input="searchQuery = $event.target.value" type="text" @keyup.enter="fetchData()"
        placeholder="Search websites" />

      <WebsitesList :websites="websites" />
    </div>

  </div>
</template>

<script lang="ts" setup>
import type { ListWebsitesInput, Website } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import { useStore } from '@/app/store';
import { onBeforeMount, ref } from 'vue';
import { useRouter } from 'vue-router';
import WebsitesList from '@/ui/components/admin/websites_list.vue';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';

// props

// events

// composables
const $store = useStore();
const $mdninja = useMdninja();
const $router = useRouter();

// lifecycle
onBeforeMount(() => {
  if ($store.isAdmin !== true) {
    $router.push('/');
  }
  fetchData();
});

// variables
let loading = ref(false);
let error = ref('');
let websites = ref([] as Website[]);
let searchQuery = ref('');

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';
  const query = searchQuery.value.trim();
  const input: ListWebsitesInput = {
    query: query === "" ? undefined : query,
  };

  try {
    const res = await $mdninja.listAllWebsites(input);
    websites.value = res.data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
