<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-4">
      <h1 class="text-3xl font-extrabold text-gray-900">Orders</h1>
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

    <div class="mt-5 rounded-md border border-gray-900/10">
      <dl class="mx-auto grid max-w-7xl grid-cols-1 sm:grid-cols-3 lg:px-2 xl:px-0">
        <div v-for="(stat, statIdx) in stats" :key="stat.name" :class="[statIdx % 2 === 1 ? 'sm:border-l' : statIdx === 2 ? 'lg:border-l' : '', 'flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-t border-gray-900/5 px-4 py-5 sm:px-6 lg:border-t-0 xl:px-8']">
          <dt class="text-md font-medium text-gray-500">{{ stat.name }}</dt>
          <dd class="w-full flex-none text-3xl font-medium tracking-tight text-gray-900">{{ stat.value }}</dd>
        </div>
      </dl>
    </div>

    <sl-input :value="searchQuery" @input="searchQuery = $event.target.value.trim()"
      placeholder="Search orders" @keyup.enter="fetchData()"
      class="mt-5"
    />

    <div class="flex mt-2">
      <OrdersList :orders="orders" />
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { ListOrdersInput, OrderMetadata, Website } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import OrdersList from '@/ui/components/products/orders_list.vue';
import { computed, onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';

type Stat = {
  name: string;
  value: string;
}

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
let website: Ref<Website | null> = ref(null);
let orders: Ref<OrderMetadata[]> = ref([]);
let searchQuery = ref('');

// computed
const stats = computed((): Stat[] => {
  return [
    {
      name: 'Revenue',
      value: (website.value?.revenue ?? 0).toLocaleString('en-US') + ' ' + (website.value?.currency ?? ''),
    },
    {
      name: 'Completed orders',
      value: 'TBD',
    },
    {
      name: 'Canceled orders',
      value: 'TBD',
    },
  ]
})

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';
  const query = searchQuery.value.trim();
  const input: ListOrdersInput = {
    website_id: websiteId,
    query: query === '' ? undefined : query,
  };

  try {
    const [websiteRes, ordersRes] = await Promise.all([
      $mdninja.getWebsite({ id: websiteId }),
      $mdninja.listOrders(input)
    ]);
    website.value = websiteRes;
    orders.value = ordersRes.data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
