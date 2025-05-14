<template>
  <div class="overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden rounded-md">
        <table class="min-w-full divide-y divide-gray-200">
          <thead>
            <tr class="max-w-0 text-left text-xs font-medium uppercase">
              <th scope="col" class="px-6 py-3 tracking-wider">
                Order ID
              </th>
              <th scope="col" class="px-6 py-3 tracking-wider">
                Date
              </th>
              <th scope="col" class="px-6 py-3 tracking-wider">
                Total
              </th>
              <th scope="col" class="px-6 py-3 tracking-wider">
                Invoice
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full divide-y divide-gray-200">
            <tr v-for="order in orders" :key="order.id">
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-2/5">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ order.id }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-1/5">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ date(order.created_at) }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-1/5">
                {{ order.total_amount }} {{ order.currency }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-1/5">
                <a v-if="order.invoice_url" target="_blank" :href="order.invoice_url" class="cursor-pointer">
                  Invoice
                </a>
                <span v-else>-</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { Order } from '@/app/model'
import { type PropType } from 'vue'
import date from '@/libs/date';

// props
defineProps({
  orders: {
    type: Array as PropType<Order[]>,
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
</script>
