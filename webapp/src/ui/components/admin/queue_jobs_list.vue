<template>
  <div class="overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                ID
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Type
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <tr v-for="job in jobs" :key="job.id" class="table-row min-w-full cursor-pointer" @dblclick="open(job)">
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ job.id }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ job.type }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ job.status }}
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
import type { BackgroundJob } from '@/api/model';
import type { PropType } from 'vue';

// props
defineProps({
  jobs: {
    type: Array as PropType<BackgroundJob[]>,
    required: true,
  },
});

// events
const $emit = defineEmits(['open']);

// composables

// lifecycle

// variables

// computed

// watch

// functions
function open(job: BackgroundJob) {
  $emit('open', job)
}
</script>
