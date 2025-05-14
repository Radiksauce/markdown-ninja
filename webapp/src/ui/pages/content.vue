<template>
  <div class="flex my-5 mx-3 place-content-center items-center h-full">

    <div class="flex ml-3 rounded-md bg-red-50 p-4" v-if="error">
      <p class="text-sm text-red-700">
        {{ error }}
      </p>
    </div>

    <div v-if="loading" class="w-full h-full items-center flex min-h-[calc(90vh-100px)]">
      <sl-spinner class="flex m-auto" style="font-size: 40px; --track-width: 4px; --indicator-color: var(--primary-color)"/>
    </div>

    <HtmlContent v-else-if="page" :html="page.body" class="content max-w-2xl text-left min-h-[calc(90vh-100px)]" />
  </div>
</template>

<script lang="ts" setup>
import { useMarkdownNinja, type Page } from '@/sdk/markdown_ninja_sdk';
import { onBeforeMount, ref, watch, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import HtmlContent from '../components/mdninja/html_content.vue';
import SlSpinner from '@shoelace-style/shoelace/dist/components/spinner/spinner.js';

// props

// events

// composables
const $markdownNinja = useMarkdownNinja();
const $route = useRoute();

// lifecycle
onBeforeMount(() => fetchData());

// variables
let loading = ref(false);
let error = ref('');
let page: Ref<Page | null> = ref(null);


// computed

// watch
watch($route, () => {
  page.value = null;
  fetchData()
}, { deep: true });


// functions
async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    page.value = await $markdownNinja.getPage($route.path);
    document.title = page.value.title;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
