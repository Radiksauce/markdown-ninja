<template>
  <div class="overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Domain
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Type
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Value
              </th>

            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <tr v-for="record in records" :key="`${record.host}|${record.type}|${record.value}`">
              <td class="px-6 py-4 whitespace-nowrap text-md font-medium text-gray-900 truncate">
                {{ record.host }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-md font-medium text-gray-900 truncate">
                {{ record.type }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-md font-medium text-gray-900 truncate">
                {{ record.value }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { EmailDnsRecord } from '@/api/model';
import { type PropType } from 'vue';

// props
defineProps({
  records: {
    type: Array as PropType<EmailDnsRecord[]>,
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
