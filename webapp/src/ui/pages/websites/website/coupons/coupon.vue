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

    <div class="flex mt-5" v-if="coupon">
      <CouponEditor :products="products" :website-id="websiteId" :coupon="coupon" />
    </div>

  </div>
</template>

<script lang="ts" setup>
import type { Coupon, Product } from '@/api/model';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import CouponEditor from '@/ui/components/products/coupon_editor.vue';
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
const couponId = $route.params.coupon_id as string;

let loading = ref(false);
let error = ref('');
let products: Ref<Product[]> = ref([]);
let coupon: Ref<Coupon | null> = ref(null);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    const [productsApiRes, couponApi] = await Promise.all([
      $mdninja.listProducts(websiteId),
      $mdninja.getCoupon(couponId),
    ]);
    products.value = productsApiRes.data;
    coupon.value = couponApi;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
