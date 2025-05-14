<template>
  <div class="overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Product
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Unit Price
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Quantity
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <tr v-for="lineItem in lineItems" :key="lineItem.product_id" class="min-w-full">
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-2/5">
                <div class="text-md font-medium text-gray-900 truncate">
                  <RouterLink :to="productUrl(lineItem.product_id)">{{ lineItem.product_name }}</RouterLink>
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-1/5">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ lineItem.original_product_price }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-1/5">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ lineItem.quantity }}
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { OrderLineItem } from '@/api/model';
import type { PropType } from 'vue';


// props
const props = defineProps({
  lineItems: {
    type: Array as PropType<OrderLineItem[]>,
    required: true,
  },
  websiteId: {
    type: String as PropType<string>,
    required: true,
  }
});


// events

// composables

// lifecycle

// variables

// computed

// watch

// functions
function productUrl(productId: string) {
  return `/websites/${props.websiteId}/products/${productId}`;
}
</script>
