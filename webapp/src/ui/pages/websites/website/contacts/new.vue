<template>
  <div class="flex-1">

    <div class="rounded-md bg-red-50 p-4" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="mt-5" >
      <PContact :website-id="websiteId" :loading="loading"
        @create="createContact"
      />
    </div>

  </div>
</template>

<script lang="ts" setup>
import type { CreateContactInput } from '@/api/model';
import { ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import PContact from '@/ui/components/contacts/contact.vue';
import { useMdninja } from '@/api/mdninja';

// props

// events

// composables
const $route = useRoute();
const $router = useRouter();
const $mdninja = useMdninja();

// lifecycle

// variables
const websiteId = $route.params.website_id as string;

let error = ref('');
let loading = ref(false);

// computed

// watch

// functions
async function createContact(apiInput: CreateContactInput) {
  loading.value = true;
  error.value = '';

  try {
    const newContact = await $mdninja.createContact(apiInput);
    $router.push(`/websites/${websiteId}/contacts/${newContact.id}`);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
