<template>
  <div class="min-h-full flex flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-md">
      <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
        New Website
      </h2>
    </div>

    <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
      <div class="bg-white py-8 px-4 sm:rounded-lg sm:px-10 space-y-6">

        <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
          <div class="flex">
            <div class="ml-3">
              <p class="text-sm text-red-700">
                {{ error }}
              </p>
            </div>
          </div>
        </div>

        <div>
          <sl-input :value="name" @input="name = $event.target.value.trim(); onNameChanged()"
            label="Name" placeholder="My Website" :disabled="loading"
          />
        </div>

        <div>
          <SlugInput v-model="slug" @keyup="onSlugKeyup" />
        </div>

        <div class="mt-5 flex justify-between space-x-3">
          <RouterLink to="..">
            <sl-button outline>
              Cancel
            </sl-button>
          </RouterLink>
          <sl-button variant="primary" :loading="loading" @click="createWebsite">
            Create Website
          </sl-button>
        </div>

      </div>
    </div>

  </div>
</template>

<script lang="ts" setup>
import type { CreateWebsiteInput } from '@/api/model';
import { ref } from 'vue'
import { useRouter } from 'vue-router';
import SlugInput from '@/ui/components/websites/slug_input.vue';
import { useMdninja } from '@/api/mdninja';
import { slugify } from '@/libs/slugify';
import { useRoute } from 'vue-router';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';

// props

// events

// composables
const $mdninja = useMdninja();
const $router = useRouter();
const $route = useRoute();

// lifecycle

// variables
const organization_id = $route.params.organization_id as string;

let name = ref('');
let slug = ref(slugify(name.value));
let error = ref('');
let loading = ref(false);
let slugManuallyUpdated = false;

// computed

// watch

// functions
async function createWebsite() {
  loading.value = true;
  error.value = '';
  const input: CreateWebsiteInput = {
    name: name.value.trim(),
    slug: slug.value.trim(),
    organization_id: organization_id,
  };

  try {
    const newWebsite = await $mdninja.createWebsite(input);
    $router.push(`/websites/${newWebsite.id}`);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function onNameChanged() {
  if (!slugManuallyUpdated) {
    slug.value = slugify(name.value);
  }
}

function onSlugKeyup() {
  slugManuallyUpdated = true;
}
</script>
