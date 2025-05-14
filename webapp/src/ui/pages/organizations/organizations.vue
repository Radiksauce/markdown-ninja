<template>
  <div class="flex flex-col justify-center max-w-2xl mx-auto">

    <div class="rounded-md bg-red-50 p-4" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex flex-col mt-2.5 space-y-2.5">
      <div class="flex">
        <RouterLink :to="newOrganizationUrl">
          <sl-button variant="primary">
            <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
            New Organization
          </sl-button>
        </RouterLink>
      </div>
      <div v-if="organizations.length !== 0" class="flex w-full justify-center">
        <OrganizationsList :organizations="organizations" class="w-full"/>
      </div>
    </div>

  </div>

</template>

<script lang="ts" setup>
import type { Organization } from '@/api/model';
import OrganizationsList from '@/ui/components/kernel/organizations_list.vue';
import { onBeforeMount, ref } from 'vue';
import { PlusIcon } from '@heroicons/vue/24/outline';
import { useMdninja } from '@/api/mdninja';
import { useStore } from '@/app/store';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';

// props

// events

// composables
const $mdninja = useMdninja();
const $store = useStore();

// lifecycle
onBeforeMount(() => {
  fetchData();
});

// variables
const newOrganizationUrl = './organizations/new';

let loading = ref(false);
let error = ref('');
let organizations = ref([] as Organization[]);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    organizations.value = await $mdninja.fetchOrganizationsForUser();
    $store.setOrganizations(organizations.value);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
