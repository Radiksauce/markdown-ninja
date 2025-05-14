<template>
  <div class="-my-2 overflow-x-auto min-w-full">
    <div class="min-w-full mt-1">
      <sl-input type="search" v-model="searchQuery" placeholder="Search" />
    </div>
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="table min-w-full divide-y divide-gray-200">
          <thead class="table-header-group bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Name
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Price
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <RouterLink :to="productUrl(product.id)" v-for="product in filteredProducts" :key="product.id"
              class="table-row cursor-pointer min-w-full">
              <div class="table-cell px-6 py-4 whitespace-nowrap max-w-0 w-full">
                <div class="text-gray-900 font-medium truncate">
                  {{ product.name }} <span class="text-gray-500 font-normal">({{ capitalize(product.type) }})</span>
                </div>
                <!-- <div class="mt-1 text-gray-500">
                  {{ capitalize(product.type) }}
                </div> -->
              </div>
              <div class="table-cell mx-3 px-6 py-4 whitespace-nowrap">
                <span>{{ product.price + ' ' + currency }}</span>
              </div>
              <div class="table-cell px-6 py-4 whitespace-nowrap">
                <span v-if="product.status === ProductStatus.Draft" class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-neutral-200">
                  Draft
                </span>
                <span v-else class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                  Published
                </span>
              </div>
            </RouterLink>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, type PropType, computed } from 'vue';
import { useRoute } from 'vue-router';
import { ProductStatus, type Product } from '@/api/model';
import capitalize from '@/filters/capitalize';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';

// props
const props = defineProps({
  products: {
    type: Array as PropType<Product[]>,
    required: true,
  },
  currency: {
    type: String as PropType<string>,
    required: true,
  },
})

// events

// composables
const $route = useRoute();

// lifecycle

// variables
const websiteId = $route.params.website_id;
let searchQuery = ref('');

// computed
const filteredProducts = computed((): Product[] => {
  return props.products.filter((product) => {
    return product.name.toLowerCase().includes(searchQuery.value.toLowerCase());
  });
})

// watch

// functions
function productUrl(id: string): string {
  return `/websites/${websiteId}/products/${id}`;
}
</script>
