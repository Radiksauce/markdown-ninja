<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-4">
      <h1 class="text-3xl font-extrabold text-gray-900">Coupons</h1>
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

    <div class="mt-5 flex flex-col">
      <div class="flex">
        <RouterLink :to="newCouponUrl">
          <sl-button variant="primary">
            <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
            New Coupon
          </sl-button>
        </RouterLink>
      </div>

      <div class="flex mt-5">
        <CouponsList :coupons="coupons" />
      </div>

    </div>
  </div>
</template>

<script lang="ts" setup>
import type { Coupon } from '@/api/model';
import CouponsList from '@/ui/components/products/coupons_list.vue';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import { PlusIcon } from '@heroicons/vue/24/outline';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import { useMdninja } from '@/api/mdninja';

// props

// events

// composables
const $route = useRoute();
const $mdninja = useMdninja();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const websiteId = $route.params.website_id as string;
const newCouponUrl = './coupons/new';

let loading = ref(false);
let error = ref('');
let coupons: Ref<Coupon[]> = ref([]);

// computed

// watch

// functions

async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    const apiRes = await $mdninja.listCoupons(websiteId);
    coupons.value = apiRes.data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

</script>
