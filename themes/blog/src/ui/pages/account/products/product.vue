<template>
  <div v-if="product">

    <div class="flex items-center h-full text-center align-middle space-x-2">
      <RouterLink to="/account" class="h-full text-md font-medium text-gray-500 hover:text-gray-700">
        Account
      </RouterLink>
      <ChevronRightIcon class="h-5 w-5 flex-shrink-0 text-gray-400" aria-hidden="true" />
      <span class="text-md font-medium text-gray-500">
        {{ product.name }}
      </span>
    </div>

    <div class="flex">

      <!-- Sidebar with pages list -->
      <div v-if="pages.length > 1" class="flex w-32 flex-col">
        <nav class="flex flex-1 flex-col" aria-label="Sidebar">
          <ul role="list" class="px-0 space-y-1 list-none">
            <li v-for="(page, $index) in pages" :key="page.id" @click="setCurrentPage($index)">
              <span class="cursor-pointer text-[var(--mdninja-text)] hover:text-[var(--mdninja-accent)]
                hover:bg-gray-100 group flex gap-x-3 rounded-md p-2 pl-3 text-sm leading-6 font-semibold">
                {{ page.title }}
              </span>
            </li>
          </ul>
        </nav>
      </div>

      <div :class="[pages.length > 1 ? 'ml-4' : '']">
        <div>
          <h1> {{ currentPageTitle }}</h1>
        </div>

        <div v-html="currentPageBodyHtml" />

      </div>
    </div>


  </div>
</template>

<script lang="ts" setup>
import { useStore } from '@/app/store';
import type { GetProductInput, Product, ProductPage } from '@/app/model';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import { ChevronRightIcon } from '@heroicons/vue/24/solid'
import { getProduct, trackPage } from '@/app/mdninja';

// props

// events

// composables
const $store = useStore();
const $route = useRoute();

// lifecycle
onBeforeMount(() => {
  trackPage();
  fetchData();
});


// variables
const productId = $route.params.product_id as string;
const website = $store.website!;

let error = ref('');
let loading = ref(false);
let product: Ref<Product | null> = ref(null);
let pages: Ref<ProductPage[]> = ref([]);
let currentPageTitle = ref('');
let currentPageBodyHtml = ref('');

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';
  const getProductInput: GetProductInput = {
    id: productId,
  };

  try {
    product.value = await getProduct(getProductInput);
    document.title = `${website.name} - ${product.value.name}`;
    pages.value = product.value.content!;
    if (pages.value.length > 0) {
      setCurrentPage(0);
    }
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
    $store.setLoading(false);
  }
}

function setCurrentPage(index: number) {
  if (index > (pages.value.length - 1)) {
    error.value = 'Page not found';
    return;
  }

  currentPageTitle.value = pages.value[index].title;
  currentPageBodyHtml.value = pages.value[index].body;
}
</script>
