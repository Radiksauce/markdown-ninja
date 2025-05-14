<template>
  <div class="-my-2 overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="table min-w-full divide-y divide-gray-200">
          <thead class="table-header-group bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Title
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <RouterLink :to="pageUrl(page.id)" v-for="page in pages" :key="page.id"
              class="table-row cursor-pointer min-w-full">
              <div class="table-cell px-6 py-4 whitespace-nowrap max-w-0 w-full">
                <div class="text-gray-900 font-medium truncate">
                  {{ page.title }}
                </div>
              </div>
            </RouterLink>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { type PropType } from 'vue';
import { useRoute } from 'vue-router';
import type { ProductPage } from '@/api/model';

// props
defineProps({
  pages: {
    type: Array as PropType<ProductPage[]>,
    required: true,
  },
})

// events

// composables
const $route = useRoute();

// lifecycle

// variables
const websiteId = $route.params.website_id;
const productId = $route.params.product_id;

// computed

// watch

// functions
function pageUrl(id: string): string {
  return `/websites/${websiteId}/products/${productId}/pages/${id}`;
}
</script>
