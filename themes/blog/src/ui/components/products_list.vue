<template>
  <div class="overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden rounded-md">
        <table class="min-w-full divide-y divide-gray-200">
          <thead>
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">
                Product
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full divide-y divide-gray-200">
            <RouterLink :to="productUrl(product)" v-for="product in products" :key="product.id"
              class="table-row cursor-pointer min-w-full text-[var(--mdninja-text)] hover:text-[var(--mdninja-accent)]">
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-2/5">
                <div class="text-md font-medium truncate">
                  {{ product.name }}
                </div>
              </td>
            </RouterLink>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { Product } from '@/app/model'
import { type PropType } from 'vue'

// props
defineProps({
  products: {
    type: Array as PropType<Product[]>,
    required: true,
  },
});

// events

// composables

// lifecycle

// variables

// computed

// watch

// functions
function productUrl(product: Product): string {
  return `/account/products/${product.id}`;
}
</script>
