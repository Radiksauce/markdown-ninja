<template>
  <div class="overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Snippet
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Render In Emails
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <tr  v-for="snippet in snippets" :key="snippet.id"
              class="table-row min-w-full">
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-2/4">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ snippet.name }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-1/4">
                <div class="text-md font-medium text-gray-900 truncate">
                  <input disabled type="checkbox" v-model="snippet.render_in_emails"
                    class="focus:ring-(--primary-color) h-4 w-4 text-(--primary-color) border-gray-300 rounded"
                  />
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-1/4">
                <div class="flex flex-row space-x-3">
                  <sl-button variant="neutral" @click="onEditClicked(snippet)" circle>
                    <PencilIcon class="h-5 w-5" aria-hidden="true" />
                  </sl-button>

                  <sl-button variant="neutral" @click="onDeleteClicked(snippet)" circle>
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
import type { Snippet } from '@/api/model'
import type { PropType } from 'vue';
import { TrashIcon, PencilIcon } from '@heroicons/vue/24/outline'
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';

// props
defineProps({
  snippets: {
    type: Array as PropType<Snippet[]>,
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
function onDeleteClicked(snippet: Snippet) {
  $emit('delete', snippet)
}

function onEditClicked(snippet: Snippet) {
  $emit('update', snippet)
}
</script>
