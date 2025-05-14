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
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <tr v-for="tag in tags" :key="tag.id">
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-2/5">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ tag.name }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-1/5">
                <div class="flex flex-row space-x-3">
                  <sl-button variant="neutral" circle @click="onEditClicked(tag)">
                    <PencilIcon class="h-5 w-5" aria-hidden="true" />
                  </sl-button>

                  <sl-button variant="neutral" circle @click="onDeleteTagClicked(tag)">
                    <TrashIcon class="h-5 w-5" aria-hidden="true" />
                  </sl-button>
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
import type { Tag } from '@/api/model'
import { type PropType } from 'vue'
import { TrashIcon, PencilIcon } from '@heroicons/vue/24/outline'
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';

// props
defineProps({
  tags: {
    type: Array as PropType<Tag[]>,
    required: true,
  },
});

// events
const $emit = defineEmits(['delete', 'update']);

// composables

// lifecycle

// variables

// computed

// watch

// functions
function onEditClicked(tag: Tag) {
  $emit('update', tag)
}

function onDeleteTagClicked(tag: Tag) {
  $emit('delete', tag);
}
</script>
