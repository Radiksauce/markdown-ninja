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

    <div class="mt-5" v-if="contact">
      <PContact :contact="contact" :website-id="websiteId"
        @updated="onContactUpdated"
      />
    </div>

  </div>



</template>

<script lang="ts" setup>
import type { Contact } from '@/api/model';
import { onBeforeMount, ref, type Ref } from 'vue';
import PContact from '@/ui/components/contacts/contact.vue';
import { useRoute } from 'vue-router';
import { useMdninja } from '@/api/mdninja';

// props

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const contactId = $route.params.contact_id as string;
const websiteId = $route.params.website_id as string;

let error = ref('');
let loading = ref(false);
let contact: Ref<Contact | null> = ref(null);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    contact.value = await $mdninja.fetchContact(contactId);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function onContactUpdated(upadtedContact: Contact) {
  contact.value = upadtedContact;
}
</script>
