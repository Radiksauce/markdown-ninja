<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-4">
      <h1 class="text-3xl font-extrabold text-gray-900">Refunds</h1>
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

    <div class="flex mt-5">
      <RefundsList :refunds="refunds" />
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { Refund } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import RefundsList from '@/ui/components/products/refunds_list.vue';

// props

// events

// composables
const $route = useRoute();
const $mdninja = useMdninja();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const websiteId = $route.params.website_id as string;

let loading = ref(false);
let error = ref('');
let refunds: Ref<Refund[]> = ref([]);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    const apiRes = await $mdninja.listRefunds(websiteId);
    refunds.value = apiRes.data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
