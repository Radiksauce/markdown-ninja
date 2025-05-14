<template>
  <div class="flex flex-col justify-center max-w-2xl mx-auto space-y-2.5">

    <div class="flex rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex mt-2.5">
      <RouterLink  :to="newWebsiteUrl">
        <sl-button variant="primary">
          <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
          New Website
        </sl-button>
      </RouterLink>
    </div>


    <div v-if="websites.length !== 0" class="flex w-full justify-center">
      <WebsitesList :websites="websites" class="w-full"/>
    </div>

  </div>

</template>

<script lang="ts" setup>
import type { Website } from '@/api/model';
import WebsitesList from '@/ui/components/websites/websites_list.vue';
import { onBeforeMount, ref } from 'vue';
import { PlusIcon } from '@heroicons/vue/24/outline';
import { useRoute } from 'vue-router';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';

// props

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();

// lifecycle
onBeforeMount(() => {
  fetchData();
});

// variables
const organizationId = $route.params.organization_id as string;
const newWebsiteUrl = './websites/new';
let loading = ref(false);
let error = ref('');
let websites = ref([] as Website[]);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    websites.value = await $mdninja.listWebsites({ organization_id: organizationId });
    // if (websites.value.length === 0) {
    //   $router.push(newWebsiteUrl);
    // }
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
