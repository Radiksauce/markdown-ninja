<template>
  <div class="flex-1">

    <div v-if="website" class="flex flex-row justify-between">
      <div class="flex">
        <h2 class="text-2xl font-bold text-gray-900">
          {{ website.name }}
          <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800" v-if="website.blocked_at">
            Blocked
          </span>
        </h2>
      </div>
      <Menu as="div" class="flex relative inline-block text-left">
        <div>
          <MenuButton class="inline-flex w-full justify-center gap-x-1.5 rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-xs ring-1 ring-inset ring-gray-300 hover:bg-gray-50">
            <!-- Options -->
            <EllipsisVerticalIcon class="h-5 w-5 text-gray-700" aria-hidden="true" />
          </MenuButton>
        </div>

        <transition enter-active-class="transition ease-out duration-100" enter-from-class="transform opacity-0 scale-95" enter-to-class="transform opacity-100 scale-100" leave-active-class="transition ease-in duration-75" leave-from-class="transform opacity-100 scale-100" leave-to-class="transform opacity-0 scale-95">
          <MenuItems class="absolute right-0 z-10 mt-2 w-56 origin-top-right rounded-md bg-white shadow-lg ring-1 ring-gray-300 focus:outline-none">
            <div class="py-1">
              <MenuItem v-slot="{ active }" as="div" @click="blockUnblockWebsite()">
                <span
                  :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                  {{ blockUnblockButtonLabel }}
                </span>
              </MenuItem>
            </div>
          </MenuItems>
        </transition>
      </Menu>
    </div>

    <div class="rounded-md bg-red-50 p-4 my-4" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div v-if="website" class="flex flex-col space-y-5 mt-5">

      <div class="flex">
        <h3 class="font-bold">ID:</h3> &nbsp; <span>{{ website.id }}</span>
      </div>

      <div class="flex">
        <h3 class="font-bold">Created At:</h3> &nbsp; <span>{{ website.created_at }}</span>
      </div>

      <div class="flex">
        <h3 class="font-bold">Name:</h3> &nbsp; <span>{{ website.name }}</span>
      </div>


      <div class="flex">
        <h3 class="font-bold">Primary Domain:</h3> &nbsp;
        <a :href="websiteUrl" target="_blank" rel="noopener" class="hover:underline text-(--primary-color)">
          {{ website.primary_domain }}
        </a>
      </div>

      <div class="flex">
        <h3 class="font-bold">Slug:</h3> &nbsp; <span>{{ website.slug }}</span>
      </div>

      <div class="flex">
        <h3 class="font-bold">Organization:</h3> &nbsp; <span>
          <RouterLink :to="organizationUrl(website.organization_id)" class="text-(--primary-color) hover:underline">
            {{ website.organization_id }}
          </RouterLink>
        </span>
      </div>

      <div class="flex">
        <RouterLink :to="contactsUrl()">
          <sl-button variant="primary">
            Contacts
          </sl-button>
        </RouterLink>
      </div>


    </div>

  </div>
</template>

<script lang="ts" setup>
import { useMdninja } from '@/api/mdninja';
import type { GetWebsiteInput, UpdateWebsiteInput, Website } from '@/api/model';
import { computed, onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import { Menu, MenuButton, MenuItem, MenuItems } from '@headlessui/vue'
import { EllipsisVerticalIcon } from '@heroicons/vue/24/outline'
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


// computed
const blockUnblockButtonLabel = computed(() => website.value?.blocked_at ? 'Unblock website' : 'Block website');
const websiteUrl = computed((): string => {
  if (website.value) {
    return $mdninja.generateWebsiteUrl(website.value);
  }
  return '';
});


// watch

// functions
function organizationUrl(organizationId: string): string {
  return `/admin/organizations/${organizationId}`;
}

function contactsUrl(): string {
  return `/admin/websites/${websiteId}/contacts`;
}

async function fetchData() {
  loading.value = true;
  error.value = '';
  const input: GetWebsiteInput = {
    id: websiteId,
  };

  try {
    website.value = await $mdninja.getWebsite(input);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function blockUnblockWebsite() {
  loading.value = true;
  error.value = '';
  const blocked = website.value?.blocked_at ? false : true;
  const input: UpdateWebsiteInput = {
    id: websiteId,
    blocked,
  };

  try {
    website.value = await $mdninja.updateWebsite(input);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
