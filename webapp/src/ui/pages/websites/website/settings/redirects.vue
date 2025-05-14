<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-5">
      <h1 class="text-3xl font-extrabold text-gray-900">Redirects</h1>
      <p>Create redirects for when your content has moved from an URL to another.</p>
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

    <div v-if="website" class="flex flex-col space-y-3">
      <div class="flex flex-row">
        <div class="flex">
          <sl-button variant="primary" :loading="loading" @click="saveRedirects()">
            Save
          </sl-button>
        </div>
        <div class="flex ml-3">
          <sl-button variant="primary" :loading="loading" @click="addRedirect">
            <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
            New Redirect
          </sl-button>
        </div>
      </div>


      <div class="flex">
        <RedirectsList :redirects="redirects" @delete="removeRedirect" />
      </div>

    </div>

  </div>
</template>

<script lang="ts" setup>
import type { GetWebsiteInput, Redirect, RedirectInput, SaveRedirectsInput, Website } from '@/api/model';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import RedirectsList from '@/ui/components/websites/redirects_list.vue';
import { PlusIcon } from '@heroicons/vue/24/outline';
import uuidv4 from 'mdninja-js/src/libs/uuidv4';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';

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
let redirects: Ref<Redirect[]> = ref([]);

// computed

// watch

// functions
function resetValues() {
  redirects.value = website.value!.redirects!;
}

async function fetchData() {
  loading.value = true;
  error.value = '';
  const input: GetWebsiteInput = {
    id: websiteId,
    redirects: true,
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

async function saveRedirects() {
  loading.value = true;
  error.value = '';
  const redirectsInput: RedirectInput[] = redirects.value.map((redirect) => {
    return {
      pattern: redirect.pattern,
      to: redirect.to,
      // status: redirect.status,
    };
  });
  const input: SaveRedirectsInput = {
    website_id: websiteId,
    redirects: redirectsInput,
  };

  try {
    redirects.value = await $mdninja.saveRedirects(input);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function addRedirect() {
  redirects.value.push({
    id: uuidv4(),
    created_at: '',
    updated_at: '',
    domain: '',
    pattern: '/',
    path_pattern: '',
    to: '',
    status: 301,
  });
}

function removeRedirect(redirectToRemove: Redirect) {
  redirects.value = redirects.value.filter((r: Redirect) => r.id !== redirectToRemove.id);
}
</script>
