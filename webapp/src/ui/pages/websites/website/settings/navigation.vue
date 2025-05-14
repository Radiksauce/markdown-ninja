<template>
  <div class="flex flex-col">

    <div class="px-4 sm:px-6 md:px-0">
      <h1 class="text-3xl font-extrabold text-gray-900">Navigation</h1>
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

    <div class="rounded-md bg-green-50 p-4 mt-5" v-if="success">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-green-700">
            Success
          </p>
        </div>
      </div>
    </div>

    <div class="flex mt-5 space-x-3">
      <sl-button outline @click="cancel()">
        Cancel
      </sl-button>

      <sl-button variant="primary" @click="saveNavigation()" :loading="loading">
        Save
      </sl-button>
    </div>


    <div class="px-4 sm:px-6 md:px-0 mt-8">
      <h3 class="text-xl font-medium text-gray-900">Primary</h3>
    </div>


    <div class="flex mt-2">
      <sl-button variant="primary" @click="addPrimary">
        <PlusIcon class="h-5 w-5 mr-2 -ml-1 inline" aria-hidden="true" />
        New Nav item
      </sl-button>
    </div>


    <div class="overflow-x-auto min-w-full">
      <div class="py-2 align-middle inline-block min-w-full">
        <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
          <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
              <tr class="max-w-0">
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Label
                </th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Url
                </th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="min-w-full bg-white divide-y divide-gray-200">
              <tr v-for="(nav, index) in navigation.primary" :key="index">
                <td class="px-6 py-4 whitespace-nowrap">
                  <sl-input :value="nav.label" @input="nav.label = $event.target.value"
                    label="Label"
                  />
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <sl-input :value="nav.url" @input="nav.url = $event.target.value"
                    label="Url"
                  />
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <sl-button variant="neutral" circle @click="removePrimary(index)">
                    <TrashIcon class="h-5 w-5" aria-hidden="true" />
                  </sl-button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>



    <div class="px-4 sm:px-6 md:px-0 mt-8">
      <h3 class="text-xl font-medium text-gray-900">Secondary</h3>
    </div>

    <div class="flex mt-2">
      <sl-button variant="primary" @click="addSecondary">
        <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
        New Nav item
      </sl-button>
    </div>



    <div class="overflow-x-auto min-w-full">
      <div class="py-2 align-middle inline-block min-w-full">
        <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
          <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
              <tr class="max-w-0">
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Label
                </th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Url
                </th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="min-w-full bg-white divide-y divide-gray-200">
              <tr v-for="(nav, index) in navigation.secondary" :key="index">
                <td class="px-6 py-4 whitespace-nowrap">
                  <sl-input :value="nav.label" @input="nav.label = $event.target.value"
                    label="Label"
                  />
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <sl-input :value="nav.url" @input="nav.url = $event.target.value"
                    label="Url"
                  />
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <sl-button variant="neutral" circle @click="removeSecondary(index)">
                    <TrashIcon class="h-5 w-5" aria-hidden="true" />
                  </sl-button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

  </div>
</template>

<script lang="ts" setup>
import { onBeforeMount, ref, type Ref } from 'vue'
import type { GetWebsiteInput, UpdateWebsiteInput, Website, WebsiteNavigation } from '@/api/model';
import { PlusIcon, TrashIcon } from '@heroicons/vue/24/outline';
import { useRoute } from 'vue-router';
import deepClone from 'mdninja-js/src/libs/deepclone';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';


// props

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const siteId = $route.params.website_id as string;
let site: Ref<Website | null> = ref(null);
let loading = ref(false);
let error = ref('');
let success = ref(false);
let navigation: Ref<WebsiteNavigation> = ref({
  primary: [],
  secondary: [],
});

// computed

// watch

// functions
function cancel() {
  navigation.value = deepClone(site.value?.navigation ?? navigation.value);
}

function removePrimary(index: number) {
  navigation.value.primary = navigation.value.primary.filter((_nav: any, i: number) => index !== i);
}
function removeSecondary(index: number) {
  navigation.value.secondary = navigation.value.secondary.filter((_nav: any, i: number) => index !== i);
}

function addPrimary() {
  navigation.value.primary.push({
    url: '',
    label: '',
  });
}

function addSecondary() {
  navigation.value.secondary.push({
    url: '',
    label: '',
  });
}

async function fetchData() {
  loading.value = true;
  error.value = '';
  const input: GetWebsiteInput = {
    id: siteId,
  };

  try {
    site.value = await $mdninja.getWebsite(input);
    navigation.value = deepClone(site.value.navigation);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function saveNavigation() {
  loading.value = true;
  error.value = '';

  const input: UpdateWebsiteInput = {
    id: siteId,
    navigation: navigation.value,
  };

  try {
    site.value = await $mdninja.updateWebsite(input);
    navigation.value = deepClone(site.value.navigation);
    success.value = true;
    setTimeout(() => {
      success.value = false;
    }, 4200);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
