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
                Email
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <tr  v-for="staff in staffs" :key="staff.user_id" class="table-row min-w-full">
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ staff.name }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ staff.email }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                <span @click="$emit('remove', staff)"
                  class="text-(--primary-color) hover:text-(--primary-color-hover) cursor-pointer">
                  <span v-if="$store.userId === staff.user_id">
                    Quit
                  </span>
                  <span v-else>Remove</span>
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { Staff } from '@/api/model';
import { useStore } from '@/app/store';
import type { PropType } from 'vue';

// props
defineProps({
  staffs: {
    type: Array as PropType<Staff[]>,
    required: true,
  },
});

// events
const $emit = defineEmits(['remove']);

// composables
const $store = useStore();

// lifecycle

// variables

// computed

// watch

// functions
</script>
