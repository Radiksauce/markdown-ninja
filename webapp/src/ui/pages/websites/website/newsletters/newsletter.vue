<template>
  <div class="w-full">
    <div class="rounded-md bg-red-50 p-4" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div v-if="newsletter" class="w-full flex flex-col">
      <NewsletterEditor v-model="newsletter" />
    </div>

  </div>
</template>

<script lang="ts" setup>
import type { Newsletter } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import NewsletterEditor from '@/ui/components/emails/newsletter_editor.vue';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';

// props

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();

// lifecycle
onBeforeMount(() => fetchData());

// variables
// const websiteId = $route.params.website_id as string;
const newsletterId = $route.params.newsletter_id as string;

let loading = ref(false);
let error = ref('');
let newsletter: Ref<Newsletter | null> = ref(null);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    newsletter.value = await $mdninja.fetchNewsletter(newsletterId);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
