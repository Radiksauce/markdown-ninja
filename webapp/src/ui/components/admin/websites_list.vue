<template>
  <div class="overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Name
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Domain
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <RouterLink :to="websiteUrl(website)" v-for="website in websites" :key="website.id"
              class="table-row cursor-pointer min-w-full">
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ website.name }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ website.primary_domain }}
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
import type { Website } from '@/api/model';
import type { PropType } from 'vue';

// props
defineProps({
  websites: {
    type: Array as PropType<Website[]>,
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
function websiteUrl(website: Website): string {
  return `/admin/websites/${website.id}`;
}
</script>
