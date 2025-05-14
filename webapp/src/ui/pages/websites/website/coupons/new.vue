<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-4">
      <h1 class="text-3xl font-extrabold text-gray-900">New Coupon</h1>
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
      <CouponEditor :products="products" :website-id="websiteId"
        @created="onCouponCreated"
      />
    </div>

  </div>
</template>

<script lang="ts" setup>
import type { Coupon, Product } from '@/api/model';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import CouponEditor from '@/ui/components/products/coupon_editor.vue';
import { useMdninja } from '@/api/mdninja';

// props

// events

// composables
const $route = useRoute();
const $mdninja = useMdninja();
const $router = useRouter();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const websiteId = $route.params.website_id as string;

let loading = ref(false);
let error = ref('');
let products: Ref<Product[]> = ref([]);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    const apiRes = await $mdninja.listProducts(websiteId);
    products.value = apiRes.data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function onCouponCreated(coupon: Coupon) {
  $router.push(`/websites/${websiteId}/coupons/${coupon.id}`);
}
</script>
