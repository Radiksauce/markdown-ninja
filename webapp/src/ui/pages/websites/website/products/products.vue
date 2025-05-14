<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-4">
      <h1 class="text-3xl font-extrabold text-gray-900">Products</h1>
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

    <div v-if="website" class="mt-5 flex flex-col">
      <div class="flex">
        <sl-button variant="primary" @click="openNewProductDialog()">
          <PlusIcon class="-ml-1 mr-2 h-5 w-5 inline" aria-hidden="true" />
          New Product
        </sl-button>
      </div>

      <div class="flex mt-5">
        <ProductsList :products="products" :currency="website.currency" />
      </div>

    </div>
  </div>

  <NewProductDialog v-model="showNewProductDialog" :website-id="websiteId" @created="onProductCreated" />
</template>

<script lang="ts" setup>
import { PlusIcon } from '@heroicons/vue/24/outline';
import { onBeforeMount, ref, type Ref } from 'vue';
import NewProductDialog from '@/ui/components/products/new_product_dialog.vue';
import { useRoute } from 'vue-router';
import type { Product, Website } from '@/api/model';
import { useRouter } from 'vue-router';
import ProductsList from '@/ui/components/products/products_list.vue';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';

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
let showNewProductDialog = ref(false);
let website: Ref<Website | null> = ref(null);

// computed

// watch

// functions
function openNewProductDialog() {
  showNewProductDialog.value = true;
}

async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    const res = await Promise.all([
      $mdninja.getWebsite({ id: websiteId }),
      $mdninja.listProducts(websiteId),
    ]);

    website.value = res[0];
    products.value = res[1].data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function onProductCreated(newProduct: Product) {
  $router.push(`/websites/${websiteId}/products/${newProduct.id}`);
}
</script>
