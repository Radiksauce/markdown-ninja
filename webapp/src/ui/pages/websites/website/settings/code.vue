<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0">
      <h1 class="text-3xl font-extrabold text-gray-900">Code</h1>
      <p>Inject code in the header or footer of your website.</p>
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

    <div v-if="website" class="flex flex-col space-y-5 mt-5">
      <div class="flex w-full">
        <sl-textarea label="Header" :value="header" @input="header = $event.target.value"
          placeholder="Write your HTML code here" :disabled="loading" rows="10" />
      </div>

      <div class="flex w-full">
        <sl-textarea label="Footer" :value="footer" @input="footer = $event.target.value"
          placeholder="Write your HTML code here" :disabled="loading" rows="10" />
      </div>

      <div class="flex">
        <sl-button variant="primary" @click="updateWebsite()" :loading="loading">
          Save
        </sl-button>
      </div>
    </div>

  </div>
</template>

<script lang="ts" setup>
import type { GetWebsiteInput, UpdateWebsiteInput, Website } from '@/api/model';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlTextarea from '@shoelace-style/shoelace/dist/components/textarea/textarea.js';

// props

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const websiteId = $route.params.website_id as string;

let loading = ref(false);
let error = ref('');
let website: Ref<Website | null> = ref(null);
let header = ref('');
let footer = ref('');

// computed

// watch

// functions
function resetValues() {
  header.value = website.value!.header;
  footer.value = website.value!.footer;
}

async function fetchData() {
  loading.value = true;
  error.value = '';
  const input: GetWebsiteInput = {
    id: websiteId,
  };

  try {
    website.value = await $mdninja.getWebsite(input);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function updateWebsite() {
  loading.value = true;
  error.value = '';
  const input: UpdateWebsiteInput = {
    id: websiteId,
    header: header.value,
    footer: footer.value,
  };

  try {
    website.value = await $mdninja.updateWebsite(input);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
