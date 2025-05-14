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

    <div v-if="website && product" class="w-full flex flex-col">
      <ProductEditor :website="website" :product="product" @updated="onProductUpdated" />
    </div>

  </div>
</template>

<script lang="ts" setup>
import type { GetWebsiteInput, Product, Website } from '@/api/model';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import ProductEditor from '@/ui/components/products/product_editor.vue';
import { useMdninja } from '@/api/mdninja';

// props

// events

// composables
const $route = useRoute();
const $mdninja = useMdninja();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const productId = $route.params.product_id as string;
const websiteId = $route.params.website_id as string;

let loading = ref(false);
let error = ref('');
let product: Ref<Product | null> = ref(null);
let website: Ref<Website | null> = ref(null);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';
  const getWebsiteInput: GetWebsiteInput = {
    id: websiteId,
  };

  try {
    const [websiteRes, productRes] = await Promise.all([
      $mdninja.getWebsite(getWebsiteInput),
      $mdninja.getProduct(productId),
    ]);
    website.value = websiteRes;
    product.value = productRes;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function onProductUpdated(updatedProduct: Product) {
  product.value = updatedProduct;
}
</script>
